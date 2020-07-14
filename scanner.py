from kubernetes import client, config
import logging
import os
import queue
import threading
import subprocess
import json
import base64

QUEUE = queue.Queue()
VUL_LIST = dict()
DEBUG = os.getenv("DEBUG", "y").replace(" ", "").lower()
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
        return base64.b64decode(secret.data['.dockerconfigjson']).decode()
    except KeyError:
        raise DockerConfigNotFound("Not found .dockerconfigjson key")


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
                    images[image] = {"docker_password": [].append(pod[pod_id[0]]['docker_password'])}
            for image in pod[pod_id[0]]['init_containers']:
                if not pod[pod_id[0]]['docker_password']:
                    images[image] = {"docker_password": []}
                else:
                    images[image] = {"docker_password": [].append(pod[pod_id[0]]['docker_password'])}
    return images


def enqueue():
    images = unique_images()
    for image in images:
        QUEUE.put({image: images[image]})


def parse_scan(image):
    with open("/tmp/{}.json".format(image), "r") as f:
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
        cmd_clear_cache = ["./trivy",
                           "image",
                           "-c",
                           "{}".format(image)]
        cmd = ["./trivy",
               "image",
               "--format=json",
               "--ignore-unfixed=true",
               "--output=/tmp/{}.json".format(safe_image),
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
        trivy_scan = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        trivy_clear_cache.wait()
        trivy_scan.wait()
        log.debug("STDOUT: {}".format(trivy_scan.stdout.read().decode()))
        log.debug("STDERR: {}".format(trivy_scan.stderr.read().decode()))
        log.debug("STATUS CODE: {}".format(trivy_scan.returncode))
        log.debug("Parse scan: {}".format(parse_scan(safe_image)))
        VUL_LIST[image] = parse_scan(safe_image)
        QUEUE.task_done()


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
                endpoint = v1.list_namespaced_endpoints(namespace=ingress.metadata.namespace, label_selector=)


def create_prom_points():
    pods = parse_pods()
    for pod in pods:

        p = list(pod.keys())[0]
        print("*********")
        print("-- " + p)
        for container in pod[p]['containers']:
            print("--- " + container)
            print("---- VULNERABILIDADES:")
            try:
                for t in VUL_LIST[container]:
                    for v in t["Vulnerabilities"]:
                        print("##########################")
                        print("      VID " + v["VulnerabilityID"])
                        print("      PKG Name " + v["PkgName"])
                        print("      Instaled Version " + v["InstalledVersion"])
                        print("      Fixed in " + v["FixedVersion"])
                        print("      Severity " + v["Severity"])
                        print("##########################")
            except TypeError:
                print("      No vulnerabilities found")
        print("$$$$$$$$$$")


def start_threads():
    enqueue()
    num_threads = os.getenv("NUM_THREADS", 5)
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
    create_prom_points()


if __name__ == '__main__':
    main()
