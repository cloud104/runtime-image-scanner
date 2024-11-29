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
TRIVY_DEBUG=os.getenv("TRIVY_DEBUG", "false")
TRIVY_REPORT_DIR = os.getenv("TRIVY_REPORT_DIR", "/tmp/trivyreport")
SCAN_INTERVAL = os.getenv("SCAN_INTERVAL", "120")
HTTP_SERVER_PORT = os.getenv("HTTP_PORT", "8080")
TRIVY_BIN_PATH = os.getenv("TRIVY_BIN_PATH", "./trivy")
IGNORE_UNFIXED = os.getenv("IGNORE_UNFIXED", "true")
DB_REPOSITORY= os.getenv("DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-db,aquasec/trivy-db,ghcr.io/aquasecurity/trivy-db")
JAVA_DB_REPOSITORY=os.getenv("JAVA_DB_REPOSITORY", "public.ecr.aws/aquasecurity/trivy-java-db,aquasec/trivy-java-db,ghcr.io/aquasecurity/trivy-java-db")
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
    log.debug(f"read secret: {namespace}/{secret}")
    v1 = client.CoreV1Api()
    try:
        secret_obj = v1.read_namespaced_secret(secret, namespace)
    except ApiException as err:
        if '"reason":"NotFound"' in err.body:
            raise KApiException("SECRET NOT FOUND")
        else:
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
                    log.info(f"The Secret {secret.name} don't have .dockerconfigjson key.")
                except KApiException as err:
                    log.info("Error reading secret found on pod. The error returned by "
                             f"kubernetes api was: {err}")
                    log.debug(f"Error reading secret {secret.name}  found on pod: {pod.metadata.name} in namespace {pod.metadata.namespace}. The error returned by "
                             f"kubernetes api was: {err}")
                except KeyError:
                    log.info(f"POD: {pod.metadata.name} | "
                             f"Namespace: {pod.metadata.namespace} | "
                             f"Invalid docker auth on secret {secret.name}")
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
    with open(f"{TRIVY_REPORT_DIR}/{image}.json", "r") as f:
        try:
            vul_list = json.loads(f.read())
        except json.decoder.JSONDecodeError:
            log.error(f"Error decoding trivy output scan: {image}")
            return {}
    log.debug("end parse scan")
    return vul_list


class Scan:
    RUNNING = True

    def trivy(self, cache_id):
        log.debug("trivy scan")
        while self.RUNNING and not QUEUE.empty():
            item = QUEUE.get()
            image = list(item.keys())[0]
            cache_dir = str("~/.cache/trivy_"+cache_id)
            safe_image = image.replace("/", "__")
            log.info(f"Scanning image: {image}")
            system_environment = os.environ.copy()
            cmd_clear_cache = [f"{TRIVY_BIN_PATH} clean --scan-cache  {image}"]
            if TRIVY_DEBUG == "true" :
                cmd_clear_cache = [f"{TRIVY_BIN_PATH} --debug clean --scan-cache  {image}"]
            cmd = [f"{TRIVY_BIN_PATH} image --cache-dir {cache_dir} --format=json --ignore-unfixed={IGNORE_UNFIXED} --db-repository {DB_REPOSITORY} --java-db-repository {JAVA_DB_REPOSITORY} --output={TRIVY_REPORT_DIR}/{safe_image}.json {image}"]
            if TRIVY_DEBUG == "true" :
                cmd = [f"{TRIVY_BIN_PATH} image --format=json --debug --ignore-unfixed={IGNORE_UNFIXED} --db-repository {DB_REPOSITORY} --java-db-repository {JAVA_DB_REPOSITORY} --output={TRIVY_REPORT_DIR}/{safe_image}.json {image}"]
            log.debug(f"Trivy clear cache cmd: {cmd_clear_cache}")
            trivy_clear_cache = subprocess.Popen(cmd_clear_cache, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 shell=True, env=system_environment)
            log.debug(f"STDOUT Clean Cache: {trivy_clear_cache.stdout.read().decode()}")
            log.debug(f"STDERR Clean Cache: {trivy_clear_cache.stderr.read().decode()}")
            log.debug(f"STATUS CODE Clean Cache {trivy_clear_cache.returncode}")
            trivy_clear_cache.wait()

            log.debug(f"Image: {image} password len: {len(item[image]['docker_password'])}")
            log.debug(f"Image {image} password content: {item[image]['docker_password']}")

            if len(item[image]['docker_password']) > 0:
                log.debug(f"Image {image} has password")
                if image.split('/')[0] in item[image]['docker_password'][0]['registry_url']:
                    log.info(f"Auth on registry {item[image]['docker_password'][0]['registry_url']}")
                    system_environment["TRIVY_USERNAME"] = item[image]['docker_password'][0]['username']
                    system_environment["TRIVY_PASSWORD"] = item[image]['docker_password'][0]['password']

            log.debug(f"Trivy scan cmd: {cmd}")
            trivy_scan = subprocess.Popen(cmd,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          env=system_environment,
                                          shell=True)
            trivy_scan.wait()
            log.debug(f"STDOUT: {trivy_scan.stdout.read().decode()}")
            log.debug(f"STDERR: {trivy_scan.stderr.read().decode()}")
            log.debug(f"STATUS CODE: {trivy_scan.returncode}")
            if trivy_scan.returncode == 0:
                #log.debug(f"PARSE SCAN: {parse_scan(safe_image)}")
                VUL_LIST[image] = parse_scan(safe_image)
            if trivy_scan.returncode == 1:
                log.debug(f"SCAN: {image} finished with errors, Wait until next round.....   ")
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
    v1 = client.CoreV1Api()
    net = client.NetworkingV1Api()
    ingresses = net.list_ingress_for_all_namespaces()
    # Poderia ser um list comprehension? Sim, mas ficaria tão dificil de ler...
    for ingress in ingresses.items:
        for rule in ingress.spec.rules:
            if rule.http is None:
                log.warning(f"Ingress: {rule.host} Rule: is None")
                continue
            for path in rule.http.paths:
                try:
                    service = v1.read_namespaced_service(name=path.backend.service.name,
                                                         namespace=ingress.metadata.namespace)
                except ApiException as err:
                    log.error(f"Ingress: {rule.host}, error getting service: {err}")
                    continue
                if service.spec.type == "ExternalName" and service.spec.selector == None:
                    log.warning(f"The Ingress {ingress.metadata.name} is pointing to the service {service.metadata.name} and this service is of type {service.spec.type} and does not contain a selector.  Skipping verification")
                if service.spec.type != "ExternalName":
                    try:
                        endpoint = v1.list_namespaced_endpoints(namespace=ingress.metadata.namespace,
                                                                label_selector=convert_label_selector(
                                                                    service.spec.selector))
                    except ApiException as err:
                        log.error(f"Ingress: {rule.host}, error getting endpoints.{err} ")
                        continue
                    for ep in endpoint.items:
                        if ep.subsets is None:
                            log.warning(f"The endpoint of service {path.backend.service.name} comes empty. Skipping verification")
                            continue
                        for subset in ep.subsets:
                            if subset.addresses is None:
                                log.error(f"The endpoint subset of service {path.backend.service.name} has no address. Skipping verification")
                                continue
                            for address in subset.addresses:
                                if address.target_ref is None:
                                    log.error(
                                        f"The target ref of address {subset.addresses} is none. Skipping verification")
                                    continue
                                if address.target_ref.name not in pods:
                                    pods.append(address.target_ref.name)
    log.debug(f"Pods associated with ingress: {pods}")
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
                                 "Status",
                                 "Severity"], registry=registry)
    pods = parse_pods(get_docker_auth=False)
    public_pods = get_pods_associated_with_ingress()
    for pod in pods:
        p = list(pod.keys())[0]
        for container in pod[p]['containers']:
            try:
                for t in VUL_LIST[container]["Results"]:
                    if not ("Vulnerabilities" in t):
                        log.debug("Vulnerabilities keys not found. Passing to next list item")
                        continue
                    for v in t["Vulnerabilities"]:
                        log.info(f"Prom point pod: {p}")
                        vulnerability_gauge.labels(
                            p,
                            pod[p]['namespace'],
                            container,
                            str(p in public_pods),
                            t["Type"],
                            v["VulnerabilityID"],
                            v["PkgName"],
                            v["InstalledVersion"],
                            v.get("FixedVersion", "NA"),
                            v["Status"],
                            v["Severity"]
                        ).set(1)
                        log.debug(f"Set Point to pod: {p} with values: |"
                                  f"namespace: {pod[p]['namespace']} |"
                                  f"image: {container} | "
                                  f"is public? {str(p in public_pods)} | "
                                  f"base os: {t['Type']} | "
                                  f"CVE: {v['VulnerabilityID']} |"
                                  f"Package: {v['PkgName']} |"
                                  f"Installed Version: {v['InstalledVersion']} |"
                                  f"Fixed in Version: {v.get('FixedVersion', 'NA')} |"
                                  f"Status: {v['Status']} |"
                                  f"Severity: {v['Severity']}"
                                  )

            except TypeError:
                log.info(f"Prom point pod: {p}")
                log.debug(f"Set Point to pod: {pod[p]['namespace']} with values: |"
                          f"namespace: {container}|"
                          f"image: {str(p in public_pods)} | "
                          f'is public? {"NA"} | '
                          f'base os: {"NA"} | '
                          f'CVE: {"NA"} |'
                          f'Package: {"NA"} |'
                          f'Installed Version: {"NA"} |'
                          f'Fixed in Version: {"NA"} |'
                          f'Status: {"NA"} |'
                          f'Severity: {"NA"}')
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
                    "NA",
                    "NA"
                ).set(0)
            except KeyError:
                log.warning(f"The container {container} was not scanned. Wait until next round...")
    log.debug("finished create prom points")
    return generate_latest(registry)


def start_threads():
    log.debug("start threads")
    enqueue()
    scan = Scan()
    t1 = threading.Thread(target=scan.trivy(1))
    t2 = threading.Thread(target=scan.trivy(2))
    t3 = threading.Thread(target=scan.trivy(3))
    t4 = threading.Thread(target=scan.trivy(4))
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t1.join()
    t2.join()
    t3.join()
    t4.join()


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
        for f in glob.glob(f"{TRIVY_REPORT_DIR}/*.json"):
            log.debug(f"removing file: {f}")
            os.remove(f)


def setup():
    log.debug("Executing Setup step")
    if not os.path.exists(TRIVY_REPORT_DIR):
        os.makedirs(TRIVY_REPORT_DIR)

    if not os.path.exists(TRIVY_BIN_PATH):
        raise FileNotFoundError(f"Trivy binary not found at: {TRIVY_BIN_PATH}")
    cmd_download_db = [f"{TRIVY_BIN_PATH} image --download-db-only --db-repository {DB_REPOSITORY}"]
    if TRIVY_DEBUG == "true" :
        cmd_download_db = [f"{TRIVY_BIN_PATH} image --debug --download-db-only --db-repository {DB_REPOSITORY}"]
    log.debug(f"Trivy Download db cmd: {cmd_download_db}")
    system_environment = os.environ.copy()
    trivy_clear_cache = subprocess.Popen(cmd_download_db, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                         env=system_environment)
    log.debug(f"Trivy Download db return code: {trivy_clear_cache.returncode}")
    log.debug(f"Trivy Download db stdout {trivy_clear_cache.stdout.read().decode()}")
    log.debug(f"Trivy Download db stderr {trivy_clear_cache.stderr.read().decode()}")


if __name__ == '__main__':
    log.info(f"Starting Image Scanner version: {VERSION}")
    try:
        setup()
    except BaseException as e:
        log.error(e)
        sys.exit(1)
    start_http_server(int(HTTP_SERVER_PORT))
    while True:
        try:
            main()
            cleanup()
            log.info(f"Sleeping for {SCAN_INTERVAL}s")
            time.sleep(int(SCAN_INTERVAL))
        except KeyboardInterrupt:
            log.info("Bye...")
            break
        except BaseException as e:
            log.error(e)
            time.sleep(int(SCAN_INTERVAL))
