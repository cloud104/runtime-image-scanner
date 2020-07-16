import base64
import glob
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

from kubernetes import client, config
from prometheus_client import Gauge, generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST

QUEUE = queue.Queue()
VUL_LIST = dict()
VUL_POINTS = bytes()
DEBUG = os.getenv("DEBUG", "n").replace(" ", "").lower()
SEC_REPORT_DIR = os.getenv("SEC_REPORT_DIR", "/tmp/secreport")
TRIVY_REPORT_DIR = os.getenv("SEC_REPORT_DIR", "/tmp/trivyreport")
SCAN_INTERVAL = os.getenv("SCAN_INTERVAL", "120")
HTTP_SERVER_PORT = os.getenv("HTTP_PORT", "8080")
TRIVY_BIN_PATH = os.getenv("TRIVY_BIN_PATH", "./trivy")

log = logging.getLogger(__name__)
log_format = '%(asctime)s - [%(levelname)s] [%(threadName)s] - %(message)s'

if DEBUG.startswith("y"):
    logging.basicConfig(level=logging.DEBUG,
                        format=log_format)
else:
    logging.basicConfig(level=logging.INFO,
                        format=log_format)


class DockerConfigNotFound(Exception):
    pass


def list_all_pods():
    v1 = client.CoreV1Api()
    v1.list_endpoints_for_all_namespaces()
    return v1.list_pod_for_all_namespaces().items


def read_secret(namespace, secret):
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret, namespace)
    try:
        decoded_password = base64.b64decode(secret.data['.dockerconfigjson']).decode()
    except KeyError:
        raise DockerConfigNotFound("Not found .dockerconfigjson key")
    load_auth_config = json.loads(decoded_password)
    registry_addr = list(load_auth_config['auths'].keys())[0]
    return {"username": load_auth_config['auths'][registry_addr]['username'],
            "password": load_auth_config['auths'][registry_addr]['password']
            }


def parse_pods():
    parsed_pod = list()
    pods = list_all_pods()
    for pod in pods:
        a = {
            pod.metadata.name: {
                "namespace": pod.metadata.namespace,
                "containers": [],
                "init_containers": [],
                "docker_password": []
            }
        }

        for container in pod.spec.containers:
            a[pod.metadata.name]['containers'].append(container.image)
        parsed_pod.append(a)
        if pod.spec.init_containers is not None:
            for init_container in pod.spec.init_containers:
                a[pod.metadata.name]['init_containers'].append(init_container.image)

        if pod.spec.image_pull_secrets is not None:
            for secret in pod.spec.image_pull_secrets:
                try:
                    a[pod.metadata.name]['docker_password'] \
                        .append(read_secret(pod.metadata.namespace, secret.name))
                except DockerConfigNotFound:
                    log.info("The Secret {} don't have .dockerconfigjson key.".format(secret.name))
                except KeyError:
                    log.info("Invalid docker auth on secret {}".format(secret.name))

    return parsed_pod


def unique_images():
    pods = parse_pods()

    images = dict()
    for pod in pods:
        for pod_id in pod.items():
            for image in pod[pod_id[0]]['containers']:
                if not pod[pod_id[0]]['docker_password']:
                    images[image] = {"docker_password": []}
                else:
                    images[image] = {"docker_password": pod[pod_id[0]]['docker_password']}
            for image in pod[pod_id[0]]['init_containers']:
                if not pod[pod_id[0]]['docker_password']:
                    images[image] = {"docker_password": []}
                else:
                    images[image] = {"docker_password": pod[pod_id[0]]['docker_password']}
    return images


def enqueue():
    images = unique_images()
    for image in images:
        QUEUE.put({image: images[image]})


def parse_scan(image):
    with open("{}/{}.json".format(TRIVY_REPORT_DIR, image), "r") as f:
        try:
            vul_list = json.loads(f.read())
        except json.decoder.JSONDecodeError:
            log.error("Error decoding trivy output scan: {}".format(image))
            return {}
    return vul_list


def scan():
    while True:
        item = QUEUE.get()
        image = list(item.keys())[0]
        safe_image = image.replace("/", "__")
        log.info("Scanning image: {}".format(image))
        cmd_clear_cache = ["{}".format(TRIVY_BIN_PATH),
                           "image",
                           "-c",
                           "{}".format(image)]
        cmd = ["{}".format(TRIVY_BIN_PATH),
               "image",
               "--format=json",
               "--ignore-unfixed=true",
               "--output={}/{}.json".format(TRIVY_REPORT_DIR, safe_image),
               "{}".format(image)]

        if "quay.io" in image:
            docker_pull_cmd = [
                "docker",
                "pull",
                image
            ]
            docker_pull = subprocess.Popen(docker_pull_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            docker_pull.wait()
            log.debug("Docker pull stdout: {}".format(docker_pull.stdout.read().decode()))
            log.debug("Docker pull stderr: {}".format(docker_pull.stderr.read().decode()))
            log.debug("Docker pull status code: {}".format(docker_pull.returncode))

        log.debug(cmd)
        trivy_clear_cache = subprocess.Popen(cmd_clear_cache, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.debug("STDOUT Clean Cache: {}".format(trivy_clear_cache.stdout.read().decode()))
        log.debug("STDERR Clean Cache: {}".format(trivy_clear_cache.stderr.read().decode()))
        log.debug("STATUS CODE Clean Cache {}".format(trivy_clear_cache.returncode))
        trivy_clear_cache.wait()

        if len(item[image]['docker_password']) > 0:
            log.info("Auth on registry...")
            env = {"TRIVY_USERNAME": item[image]['docker_password'][0]['username'],
                   "TRIVY_PASSWORD": item[image]['docker_password'][0]['password']}
        else:
            env = {}
        trivy_scan = subprocess.Popen(cmd,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      env=env)
        trivy_scan.wait()
        log.debug("STDOUT: {}".format(trivy_scan.stdout.read().decode()))
        log.debug("STDERR: {}".format(trivy_scan.stderr.read().decode()))
        log.debug("STATUS CODE: {}".format(trivy_scan.returncode))
        log.debug("Parse scan: {}".format(parse_scan(safe_image)))
        VUL_LIST[image] = parse_scan(safe_image)
        QUEUE.task_done()


def convert_label_selector(label):
    lbl = str()
    if type(label) is not dict:
        raise TypeError("Label must be a dict")

    for key in label:
        converted_label = "=".join([str(key), str(label[key])])
        if lbl == '':
            lbl = converted_label
        else:
            lbl = ",".join([lbl, converted_label])

    return lbl


def get_pods_associated_with_ingress():
    pods = list()
    extensions = client.ExtensionsV1beta1Api()
    v1 = client.CoreV1Api()
    ingresses = extensions.list_ingress_for_all_namespaces()

    # Poderia ser um list comprehension? Sim, mas ficaria tão dificil de ler...
    for ingress in ingresses.items:
        for rule in ingress.spec.rules:
            for path in rule.http.paths:
                service = v1.read_namespaced_service(name=path.backend.service_name,
                                                     namespace=ingress.metadata.namespace)
                endpoint = v1.list_namespaced_endpoints(namespace=ingress.metadata.namespace,
                                                        label_selector=convert_label_selector(service.spec.selector))
                for ep in endpoint.items:
                    if ep.subsets is None:
                        log.warning("The endpoint of service {} comes empty. Skiping verification".format(
                            path.backend.service_name))
                        continue
                    for subset in ep.subsets:
                        for address in subset.addresses:
                            if address.target_ref.name not in pods:
                                pods.append(address.target_ref.name)
    log.debug("Pods associated with ingress: {}".format(pods))
    return pods


def create_prom_points():
    registry = CollectorRegistry()
    to_sec = list()
    vulnerability_gauge = Gauge("pod_security_issue", "CVE found in all images associated with pod",
                                ["PodName",
                                 "Namespace",
                                 "Image",
                                 "IsPublic",
                                 "BaseOS",
                                 "VulnerabilityID",
                                 "PkgName",
                                 "InstalledVersion",
                                 "FixedVersion",
                                 "Severity"], registry=registry)
    pods = parse_pods()
    public_pods = get_pods_associated_with_ingress()
    for pod in pods:
        p = list(pod.keys())[0]
        for container in pod[p]['containers']:
            try:
                info_to_sec = {
                    "docker_image": container,
                    "pod": p,
                    "is_public": p in public_pods,
                    "namespace": pod[p]['namespace'],
                    "vulnerabilities": VUL_LIST[container]
                }
                to_sec.append(info_to_sec)
                for t in VUL_LIST[container]:
                    for v in t["Vulnerabilities"]:
                        log.info("Prom point pod: {}".format(p))
                        vulnerability_gauge.labels(
                            p,
                            pod[p]['namespace'],
                            container,
                            str(p in public_pods),
                            t["Type"],
                            v["VulnerabilityID"],
                            v["PkgName"],
                            v["InstalledVersion"],
                            v["FixedVersion"],
                            v["Severity"]
                        ).set(1)
                        log.debug("Set Point to pod: {} with values: |"
                                  "namespace: {} |"
                                  "image: {} | "
                                  "is public? {} | "
                                  "base os: {} | "
                                  "CVE: {} |"
                                  "Package: {} |"
                                  "Installed Version: {} |"
                                  "Fixed in Version: {} |"
                                  "Severity: {}".format(p,
                                                        pod[p]['namespace'],
                                                        container,
                                                        str(p in public_pods),
                                                        t["Type"],
                                                        v["VulnerabilityID"],
                                                        v["PkgName"],
                                                        v["InstalledVersion"],
                                                        v["FixedVersion"],
                                                        v["Severity"])
                                  )

            except TypeError:
                log.info("Prom point pod: {}".format(p))
                log.debug("Set Point to pod: {} with values: |"
                          "namespace: {}|"
                          "image: {} | "
                          "is public? {} | "
                          "base os: {} | "
                          "CVE: {} |"
                          "Package: {} |"
                          "Installed Version: {} |"
                          "Fixed in Version: {} |"
                          "Severity: {}".format(p,
                                                pod[p]['namespace'],
                                                container,
                                                str(p in public_pods),
                                                "NA",
                                                "NA",
                                                "NA",
                                                "NA",
                                                "NA",
                                                "NA")
                          )
                vulnerability_gauge.labels(
                    p,
                    pod[p]['namespace'],
                    container,
                    str(p in public_pods),
                    "NA",
                    "NA",
                    "NA",
                    "NA",
                    "NA",
                    "NA"
                ).set(0)
                info_to_sec = {
                    "docker_image": container,
                    "pod": p,
                    "is_public": p in public_pods,
                    "namespace": pod[p]['namespace'],
                    "vulnerabilities": None
                }
                to_sec.append(info_to_sec)
                write_sec_report(to_sec)
            except KeyError:
                log.warning("The container {} was not scanned. Wait until next round...".format(container))
    return generate_latest(registry)


def write_sec_report(report):
    with open("{}/sec_report.json".format(SEC_REPORT_DIR), 'w') as f:
        f.write(json.dumps(report))


def start_threads():
    enqueue()
    num_threads = os.getenv("NUM_THREADS", 2)
    for _ in range(0, num_threads):
        threading.Thread(target=scan, daemon=True).start()
    QUEUE.join()


def main():
    if 'KUBERNETES_PORT' in os.environ:
        config.load_incluster_config()
        log.debug("using incluster config")
    else:
        log.debug("using kube config")
        config.load_kube_config()

    start_threads()
    global VUL_POINTS
    VUL_POINTS = create_prom_points()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class VulnerabilityHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/metrics':
            try:
                self.send_response(200)
                self.send_header('Content-Type', CONTENT_TYPE_LATEST)
                self.end_headers()
                self.wfile.write(VUL_POINTS)
            except BaseException:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(traceback.format_exc())
        elif url.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"""<html>
            <head><title>Container Runtime Vulnerability Scan</title></head>
            <body>
            <h1>Hi,</h1>
            <p>Take a look at <code>/metrics</code> to get metrics.</p>
            </body>
            </html>""")
        elif url.path == '/report':
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(read_sec_report())
            except FileNotFoundError:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"message": "Report is not available yet. Please come back in fell minutes."}).encode())
        else:
            self.send_response(404)
            self.end_headers()


def read_sec_report():
    with open("{}/sec_report.json".format(SEC_REPORT_DIR), 'r') as f:
        return f.read().encode()


def http_server_handler(*args, **kwargs):
    return VulnerabilityHandler(*args, **kwargs)


def start_http_server(port):
    server = ThreadedHTTPServer(('', port), http_server_handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()


def cleanup():
    global VUL_LIST
    VUL_LIST = dict()
    if os.path.exists(TRIVY_REPORT_DIR):
        for f in glob.glob("{}/*.json".format(TRIVY_REPORT_DIR)):
            os.remove(f)


def setup():
    if not os.path.exists(SEC_REPORT_DIR):
        os.makedirs(SEC_REPORT_DIR)

    if not os.path.exists(TRIVY_REPORT_DIR):
        os.makedirs(TRIVY_REPORT_DIR)

    if not os.path.exists(TRIVY_BIN_PATH):
        raise FileNotFoundError("Trivy binary not found at: {}".format(TRIVY_BIN_PATH))


if __name__ == '__main__':
    try:
        setup()
    except BaseException as e:
        log.error(e)
        sys.exit(1)
    start_http_server(int(HTTP_SERVER_PORT))
    while True:
        try:
            log.info("looping")
            main()
            cleanup()
            log.info("Sleeping...")
            time.sleep(int(SCAN_INTERVAL))
        except KeyboardInterrupt:
            log.info("Bye...")
            break
        except BaseException as e:
            log.error(e)
