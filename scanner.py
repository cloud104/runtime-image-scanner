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
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from prometheus_client import Gauge, generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST

from version import VERSION

QUEUE = queue.Queue()
VUL_LIST = dict()
VUL_POINTS = bytes()
LOG_LEVEL = os.getenv("LOG_LEVEL", "info").replace(" ", "").lower()
TRIVY_REPORT_DIR = os.getenv("TRIVY_REPORT_DIR", "/tmp/trivyreport")
SCAN_INTERVAL = os.getenv("SCAN_INTERVAL", "120")
HTTP_SERVER_PORT = os.getenv("HTTP_PORT", "8080")
TRIVY_BIN_PATH = os.getenv("TRIVY_BIN_PATH", "./trivy")
log = logging.getLogger(__name__)
log_format = '%(asctime)s - [%(levelname)s] [%(threadName)s] [%(funcName)s:%(lineno)d]- %(message)s'

log_config = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "fatal": logging.FATAL
}

try:
    logging.basicConfig(level=log_config[LOG_LEVEL], format=log_format)
except KeyError:
    logging.basicConfig(level=logging.CRITICAL, format=log_format)


class DockerConfigNotFound(Exception):
    pass


class KApiException(Exception):
    pass


def list_all_pods():
    log.debug("list all pods")
    v1 = client.CoreV1Api()
    return v1.list_pod_for_all_namespaces().items


def read_secret(namespace, secret):
    log.debug("read secret: {}/{}".format(namespace, secret))
    v1 = client.CoreV1Api()
    try:
        secret_obj = v1.read_namespaced_secret(secret, namespace)
    except ApiException as err:
        raise KApiException(err)
    try:
        decoded_password = base64.b64decode(secret_obj.data['.dockerconfigjson']).decode()
    except KeyError:
        raise DockerConfigNotFound("Not found .dockerconfigjson key")
    load_auth_config = json.loads(decoded_password)
    registry_addr = list(load_auth_config['auths'].keys())[0]

    if ("username" not in load_auth_config['auths'][registry_addr]) and \
            ("password" not in load_auth_config['auths'][registry_addr]):
        log.debug("username and password empty. Decoding")
        auth_decoded = base64.b64decode(load_auth_config['auths'][registry_addr]["auth"]).decode()
        username = auth_decoded.split(":")[0]
        password = auth_decoded.split(":")[1]
        auth = {"username": username,
                "password": password,
                "registry_url": registry_addr.replace("https://", "").replace("http://", "")
                }
    else:
        auth = {"username": load_auth_config['auths'][registry_addr]['username'],
                "password": load_auth_config['auths'][registry_addr]['password'],
                "registry_url": registry_addr.replace("https://", "").replace("http://", "")
                }
    log.debug("end read secret")
    return auth


def parse_pods(get_docker_auth=True):
    log.debug("parse pods")
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
                    if get_docker_auth:
                        a[pod.metadata.name]['docker_password'] \
                            .append(read_secret(pod.metadata.namespace, secret.name))
                except DockerConfigNotFound:
                    log.info("The Secret {} don't have .dockerconfigjson key.".format(secret.name))
                except KApiException as err:
                    log.info("Error reading secret found on pod. The error returned by "
                             "kubernetes api was: {}".format(err))
                except KeyError:
                    log.info("POD: {} | "
                             "Namespace: {} | "
                             "Invalid docker auth on secret {}".format(pod.metadata.name,
                                                                       pod.metadata.namespace,
                                                                       secret.name))
    log.debug("end parse pods")
    return parsed_pod


def unique_images():
    log.debug("unique images")
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
    log.debug("end unique images")
    return images


def enqueue():
    log.debug("enqueue")
    images = unique_images()
    for image in images:
        log.debug("enqueue: {}".format({image: images[image]}))
        QUEUE.put({image: images[image]})


def parse_scan(image):
    log.debug("parse scan")
    with open("{}/{}.json".format(TRIVY_REPORT_DIR, image), "r") as f:
        try:
            vul_list = json.loads(f.read())
        except json.decoder.JSONDecodeError:
            log.error("Error decoding trivy output scan: {}".format(image))
            return {}
    log.debug("end parse scan")
    return vul_list


class Scan:
    RUNNING = True

    def trivy(self):
        log.debug("trivy scan")
        while self.RUNNING and not QUEUE.empty():
            item = QUEUE.get()
            image = list(item.keys())[0]
            safe_image = image.replace("/", "__")
            log.info("Scanning image: {}".format(image))
            system_environment = os.environ.copy()
            cmd_clear_cache = ["{} image -c {}".format(TRIVY_BIN_PATH, image)]
            cmd = ["{} image --format=json --ignore-unfixed=true --output={}/{}.json {}".format(TRIVY_BIN_PATH,
                                                                                                TRIVY_REPORT_DIR,
                                                                                                safe_image,
                                                                                                image)]

            log.debug("Trivy clear cache cmd: {}".format(cmd_clear_cache))
            trivy_clear_cache = subprocess.Popen(cmd_clear_cache, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 shell=True, env=system_environment)
            log.debug("STDOUT Clean Cache: {}".format(trivy_clear_cache.stdout.read().decode()))
            log.debug("STDERR Clean Cache: {}".format(trivy_clear_cache.stderr.read().decode()))
            log.debug("STATUS CODE Clean Cache {}".format(trivy_clear_cache.returncode))
            trivy_clear_cache.wait()

            log.debug("Image: {} password len: {}".format(image, len(item[image]['docker_password'])))
            log.debug("Image {} password content: {}".format(image, item[image]['docker_password']))

            if len(item[image]['docker_password']) > 0:
                log.debug("Image {} has password".format(image))
                if image.split('/')[0] in item[image]['docker_password'][0]['registry_url']:
                    log.info("Auth on registry {}".format(item[image]['docker_password'][0]['registry_url']))
                    system_environment["TRIVY_USERNAME"] = item[image]['docker_password'][0]['username']
                    system_environment["TRIVY_PASSWORD"] = item[image]['docker_password'][0]['password']

            log.debug("Trivy scan cmd: {}".format(cmd))
            trivy_scan = subprocess.Popen(cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          env=system_environment,
                                          shell=True)
            trivy_scan.wait()
            log.debug("STDOUT: {}".format(trivy_scan.stdout.read().decode()))
            log.debug("STDERR: {}".format(trivy_scan.stderr.read().decode()))
            log.debug("STATUS CODE: {}".format(trivy_scan.returncode))
            # log.debug("Parse scan: {}".format(parse_scan(safe_image)))
            VUL_LIST[image] = parse_scan(safe_image)
            # log.debug(VUL_LIST)
            QUEUE.task_done()
            log.debug("passou o task_done")


def convert_label_selector(label):
    lbl = str()
    if type(label) is not dict:
        raise TypeError("Label must be a dict")

    for key, value in label.items():
        converted_label = "=".join([str(key), str(value)])
        if lbl == '':
            lbl = converted_label
        else:
            lbl = ",".join([lbl, converted_label])

    return lbl


def get_pods_associated_with_ingress():
    log.debug("get pods associated with ingress")
    pods = list()
    extensions = client.ExtensionsV1beta1Api()
    v1 = client.CoreV1Api()
    ingresses = extensions.list_ingress_for_all_namespaces()
    # Poderia ser um list comprehension? Sim, mas ficaria tão dificil de ler...
    for ingress in ingresses.items:
        for rule in ingress.spec.rules:
            if rule.http is None:
                log.warning("Ingress: {} Rule: is None".format(rule.host))
                continue
            for path in rule.http.paths:
                try:
                    service = v1.read_namespaced_service(name=path.backend.service_name,
                                                         namespace=ingress.metadata.namespace)
                except ApiException as err:
                    log.error("Ingress: {}, error getting service: {}".format(rule.host, err))
                    continue
                try:
                    endpoint = v1.list_namespaced_endpoints(namespace=ingress.metadata.namespace,
                                                            label_selector=convert_label_selector(
                                                                service.spec.selector))
                except ApiException as err:
                    log.error("Ingress: {}, error getting endpoints. ".format(rule.host, err))
                    continue
                for ep in endpoint.items:
                    if ep.subsets is None:
                        log.warning("The endpoint of service {} comes empty. Skipping verification".format(
                            path.backend.service_name))
                        continue
                    for subset in ep.subsets:
                        if subset.addresses is None:
                            log.error("The endpoint subset of service {} has no address. Skipping verification".format(
                                path.backend.service_name
                            ))
                            continue
                        for address in subset.addresses:
                            if address.target_ref is None:
                                log.error(
                                    "The target ref of address {} is none. Skipping verification".format(
                                        subset.addresses
                                    ))
                                continue
                            if address.target_ref.name not in pods:
                                pods.append(address.target_ref.name)
    log.debug("Pods associated with ingress: {}".format(pods))
    return pods


def create_prom_points():
    log.debug("create prom points")
    registry = CollectorRegistry()
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
    pods = parse_pods(get_docker_auth=False)
    public_pods = get_pods_associated_with_ingress()
    for pod in pods:
        p = list(pod.keys())[0]
        for container in pod[p]['containers']:
            try:
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
            except KeyError:
                log.warning("The container {} was not scanned. Wait until next round...".format(container))
    log.debug("finished create prom points")
    return generate_latest(registry)


def start_threads():
    log.debug("start threads")
    enqueue()
    scan = Scan()
    t1 = threading.Thread(target=scan.trivy)
    t2 = threading.Thread(target=scan.trivy)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def main():
    if 'KUBERNETES_PORT' in os.environ:
        config.load_incluster_config()
        log.debug("using in cluster config")
    else:
        log.debug("using kube config")
        config.load_kube_config()
    client.rest.logger.setLevel(logging.WARNING)
    start_threads()
    global VUL_POINTS
    VUL_POINTS = create_prom_points()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class VulnerabilityHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(VUL_POINTS)
        elif url.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"""<html>
            <head><title>Container Runtime Vulnerability Scan</title></head>
            <body>
            <h1>Hi,</h1>
            <p>Take a look at <code>/metrics</code> to get metrics.</p>
            <p>You can get a full report here: <code>/report</code></p>
            </body>
            </html>""")
        else:
            self.send_response(404)
            self.end_headers()


def http_server_handler(*args, **kwargs):
    return VulnerabilityHandler(*args, **kwargs)


def start_http_server(port):
    server = ThreadedHTTPServer(('', port), http_server_handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()


def cleanup():
    log.debug("Executing CleanUP")
    global VUL_LIST
    VUL_LIST = dict()
    if os.path.exists(TRIVY_REPORT_DIR):
        for f in glob.glob("{}/*.json".format(TRIVY_REPORT_DIR)):
            log.debug("removing file: {}".format(f))
            os.remove(f)


def setup():
    log.debug("Executing Setup step")
    if not os.path.exists(TRIVY_REPORT_DIR):
        os.makedirs(TRIVY_REPORT_DIR)

    if not os.path.exists(TRIVY_BIN_PATH):
        raise FileNotFoundError("Trivy binary not found at: {}".format(TRIVY_BIN_PATH))
    cmd_download_db = ["{} image --download-db-only".format(TRIVY_BIN_PATH)]
    log.debug("Trivy Download db cmd: {}".format(cmd_download_db))
    system_environment = os.environ.copy()
    trivy_clear_cache = subprocess.Popen(cmd_download_db, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                         env=system_environment)
    log.debug("Trivy Download db return code: {}".format(trivy_clear_cache.returncode))
    log.debug("Trivy Download db stdout {}".format(trivy_clear_cache.stdout.read().decode()))
    log.debug("Trivy Download db stderr {}".format(trivy_clear_cache.stderr.read().decode()))


if __name__ == '__main__':
    log.info("Starting Image Scanner version: {}".format(VERSION))
    try:
        setup()
    except BaseException as e:
        log.error(e)
        sys.exit(1)
    start_http_server(int(HTTP_SERVER_PORT))
    # while True:
    #     try:
    #         main()
    #         cleanup()
    #         log.info("Sleeping for {}s".format(SCAN_INTERVAL))
    #         time.sleep(int(SCAN_INTERVAL))
    #     except KeyboardInterrupt:
    #         log.info("Bye...")
    #         break
    #     except BaseException as e:
    #         log.error(e)

    main()
    cleanup()
    # config.load_kube_config()
    # print(parse_pods(get_docker_auth=False))
    # print(read_secret("novas-solucoes-totvs-sign", "robot-pull-docker-totvs-io"))
    # print(get_pods_associated_with_ingress())
