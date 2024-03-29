import json
import time
import unittest
import os

import kubernetes.client

import scanner
from unittest import mock
from kubernetes import client
import requests


class TestSetup(unittest.TestCase):
    def tearDown(self) -> None:
        os.rmdir("/tmp/trivyreporttest1")

    @mock.patch('subprocess.Popen')
    def test_setup_dirs(self, mock_popen):
        scanner.TRIVY_BIN_PATH = "/bin/bash"
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreporttest1"
        scanner.SEC_REPORT_DIR = "/tmp/secreportdirtest1"
        stdout = mock.Mock(read=lambda x=b"Stdout - Just a test": x)
        stderr = mock.Mock(read=lambda x=b"Stderr - Just a test": x)
        mock_popen.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        s = scanner.setup()
        self.assertIsNone(s)
        scanner.TRIVY_BIN_PATH = "/tmp/fake"
        self.assertRaises(FileNotFoundError, scanner.setup)


class TestCleanup(unittest.TestCase):
    def setUp(self) -> None:
        os.makedirs("/tmp/trivyreportstest2")
        with open("/tmp/trivyreportstest2/file1.json", "a"):
            os.utime("/tmp/trivyreportstest2/file1.json", None)

    def tearDown(self) -> None:
        os.rmdir("/tmp/trivyreportstest2")

    def test_cleanup(self):
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreportstest2"
        self.assertIsNone(scanner.cleanup())
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreportstest2w2222"
        self.assertIsNone(scanner.cleanup())


class TestConvertLabelSelector(unittest.TestCase):
    def test_one_entry(self):
        data = {"one": "one"}
        lbl = scanner.convert_label_selector(data)
        if "," in lbl:
            has_comma = True
        else:
            has_comma = False

        size = len(lbl.split("="))
        if size == 2:
            invalid_split = False
        else:
            invalid_split = True

        self.assertEqual(has_comma, False)
        self.assertEqual(invalid_split, False)

    def test_more_entries(self):
        data = {"one": "one", "two": "two"}
        lbl = scanner.convert_label_selector(data)
        last_char = lbl[-1:]
        self.assertNotEqual(last_char, ",")
        size = len(lbl.split(","))
        if size == 2:
            invalid_split = False
        else:
            invalid_split = True
        self.assertEqual(invalid_split, False)

    def test_invalid_entry(self):
        data = '{"ola": "tudo", "bem": "com", "voce": "?"}'
        self.assertRaises(TypeError, scanner.convert_label_selector, data)


class TestParsePods(unittest.TestCase):
    @mock.patch("scanner.list_all_pods")
    @mock.patch("scanner.read_secret")
    def test_pods_no_errors(self, mock_read_secret, mock_list_all_pods):
        pod1 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod1", namespace="teste1"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:1")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:1")])
                            )
        pod2 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod2", namespace="teste2"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:2")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:2")],
                                                  image_pull_secrets=[client.V1LocalObjectReference(name="teste2")])
                            )

        mock_list_all_pods.return_value = client.V1PodList(items=[pod1, pod2]).items
        mock_read_secret.return_value = "mocked_pass"
        parsed = scanner.parse_pods()

        self.assertEqual(parsed[0]["pod1"]["namespace"], "teste1")
        self.assertEqual(parsed[0]["pod1"]["containers"][0], "teste:1")
        self.assertEqual(parsed[0]["pod1"]["init_containers"][0], "init_teste:1")

        self.assertEqual(parsed[1]["pod2"]["namespace"], "teste2")
        self.assertEqual(parsed[1]["pod2"]["containers"][0], "teste:2")
        self.assertEqual(parsed[1]["pod2"]["init_containers"][0], "init_teste:2")
        self.assertEqual(parsed[1]["pod2"]["docker_password"][0], "mocked_pass")

    @mock.patch("scanner.list_all_pods")
    @mock.patch("scanner.read_secret")
    def test_pods_with_errors(self, mock_read_secret, mock_list_all_pods):
        pod1 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod1", namespace="teste1"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:1")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:1")])
                            )
        pod2 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod2", namespace="teste2"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:2")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:2")],
                                                  image_pull_secrets=[client.V1LocalObjectReference(name="teste2")])
                            )

        mock_list_all_pods.return_value = client.V1PodList(items=[pod1, pod2]).items
        mock_read_secret.side_effect = scanner.DockerConfigNotFound(Exception)
        parsed = scanner.parse_pods()
        self.assertEqual(parsed[1]["pod2"]["docker_password"], [])
        mock_read_secret.side_effect = KeyError
        parsed = scanner.parse_pods()
        self.assertEqual(parsed[1]["pod2"]["docker_password"], [])


class TestUniqueImages(unittest.TestCase):
    @mock.patch("scanner.parse_pods")
    def test_unique(self, mock_parse_pods):
        mock_parse_pods.return_value = [
            {
                "pod1": {
                    "namespace": "teste1",
                    "containers": ["contaner:1", "container:2"],
                    "init_containers": ["contaner:1", "container:2"],
                    "docker_password": []
                }
            },
            {
                "pod2": {
                    "namespace": "teste1",
                    "containers": ["contaner:1", "container:2"],
                    "init_containers": ["contaner:1", "container:2"],
                    "docker_password": ["fake"]
                }
            }
        ]
        size = len(scanner.unique_images())
        self.assertEqual(size, 2)


class TestParseTrivyScan(unittest.TestCase):
    def test_parse_trivy_scan(self):
        scanner.TRIVY_REPORT_DIR = "./tests/trivy_report"
        v = scanner.parse_scan("debian:10")
        self.assertEqual(v[0]['Type'], "debian")

    def test_parse_trivy_scan_error(self):
        scanner.TRIVY_REPORT_DIR = "./tests/trivy_report"
        e = scanner.parse_scan("empty_json")
        self.assertEqual(e, {})


class TestScan(unittest.TestCase):
    @mock.patch('subprocess.Popen')
    @mock.patch("scanner.unique_images")
    def test_quay_disabled(self, mock_unique_images, mock_popen):
        sentinel = mock.PropertyMock(side_effect=[True, False])
        mock_unique_images.return_value = {"quay.io/test/fake:1": {"docker_password": []}}
        scanner.NUM_THREADS = 1
        scanner.DISABLE_QUAYIO_SCAN = "yes"
        scanner.enqueue()
        stdout = mock.Mock(read=lambda x=b"Stdout - Just a test": x)
        stderr = mock.Mock(read=lambda x=b"Stderr - Just a test": x)
        mock_popen.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        scan = scanner.Scan()
        type(scan).RUNNING = sentinel
        self.assertIsNone(scan.trivy())

    @mock.patch('subprocess.Popen')
    @mock.patch("scanner.unique_images")
    def test_simple_scan(self, mock_unique_images, mock_popen):
        sentinel = mock.PropertyMock(side_effect=[True, False])
        mock_unique_images.return_value = {"debian:10": {"docker_password": []}}
        scanner.NUM_THREADS = 1
        scanner.DISABLE_QUAYIO_SCAN = "no"
        scanner.enqueue()
        stdout = mock.Mock(read=lambda x=b"Stdout - Just a test": x)
        stderr = mock.Mock(read=lambda x=b"Stderr - Just a test": x)
        mock_popen.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        scan = scanner.Scan()
        type(scan).RUNNING = sentinel
        self.assertIsNone(scan.trivy())

    @mock.patch('subprocess.Popen')
    @mock.patch("scanner.unique_images")
    def test_quay_enabled(self, mock_unique_images, mock_popen):
        sentinel = mock.PropertyMock(side_effect=[True, False])
        mock_unique_images.return_value = {"quay.io/test/fake:1": {"docker_password": []}}
        scanner.NUM_THREADS = 1
        scanner.DISABLE_QUAYIO_SCAN = "no"
        scanner.enqueue()
        stdout = mock.Mock(read=lambda x=b"Stdout - Just a test": x)
        stderr = mock.Mock(read=lambda x=b"Stderr - Just a test": x)
        mock_popen.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        scan = scanner.Scan()
        type(scan).RUNNING = sentinel
        self.assertIsNone(scan.trivy())

    @mock.patch('subprocess.Popen')
    @mock.patch("scanner.unique_images")
    def test_auth_registry(self, mock_unique_images, mock_popen):
        sentinel = mock.PropertyMock(side_effect=[True, False])
        mock_unique_images.return_value = {"quay.io/test/fake:1": {"docker_password": [{"username": "fake",
                                                                                        "password": "fakepass",
                                                                                        "registry_url": "fake.io"}]}}
        scanner.NUM_THREADS = 1
        scanner.DISABLE_QUAYIO_SCAN = "no"
        scanner.enqueue()
        stdout = mock.Mock(read=lambda x=b"Stdout - Just a test": x)
        stderr = mock.Mock(read=lambda x=b"Stderr - Just a test": x)
        mock_popen.return_value = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        scan = scanner.Scan()
        type(scan).RUNNING = sentinel
        self.assertIsNone(scan.trivy())


class TestPromPoints(unittest.TestCase):
    @mock.patch('scanner.parse_pods')
    @mock.patch('scanner.get_pods_associated_with_ingress')
    def test_prom_points_wait_next_round(self, mock_public_ingress, mock_parse_pods):
        mock_public_ingress.return_value = ["pod2"]
        mock_parse_pods.return_value = [
            {
                "pod1": {
                    "namespace": "teste1",
                    "containers": ["contaner:1", "container:2"],
                    "init_containers": ["contaner:1", "container:2"],
                    "docker_password": []
                }
            },
            {
                "pod2": {
                    "namespace": "teste1",
                    "containers": ["contaner:1", "container:2"],
                    "init_containers": ["contaner:1", "container:2"],
                    "docker_password": ["fake"]
                }
            }
        ]

        p = scanner.create_prom_points().decode()

        if ("container:1" in p) or ("container:2" in p):
            has_container = True
        else:
            has_container = False
        self.assertFalse(has_container)

    @mock.patch('scanner.parse_pods')
    @mock.patch('scanner.get_pods_associated_with_ingress')
    def test_prom_points_with_vulnerabilities(self, mock_public_ingress, mock_parse_pods):
        scanner.LOG_LEVEL = "fatal"
        scanner.SEC_REPORT_DIR = "/tmp"
        mock_public_ingress.return_value = ["pod2"]
        mock_parse_pods.return_value = [
            {
                "pod1": {
                    "namespace": "teste1",
                    "containers": ["container:1", "container:2"],
                    "init_containers": ["contaner:1", "container:2"],
                    "docker_password": []
                }
            },
            {
                "pod2": {
                    "namespace": "teste1",
                    "containers": ["container:1", "container:2"],
                    "init_containers": ["container:1", "container:2"],
                    "docker_password": ["fake"]
                }
            }
        ]

        scanner.VUL_LIST = {
            "container:1": [
                {
                    "Target": "container:1 (test 1.0)",
                    "Type": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-TEST-0000",
                            "PkgName": "testPKG",
                            "InstalledVersion": "0.0.0.0",
                            "FixedVersion": "1.0.0.0",
                            "Severity": "HIGH"
                        }
                    ]
                }
            ],
            "container:2": [
                {
                    "Target": "container:2 (test 1.0)",
                    "Type": "test",
                    "Vulnerabilities": None
                }
            ]
        }
        p = scanner.create_prom_points().decode()
        if ("container:1" in p) and ("container:2" in p):
            has_container = True
        else:
            has_container = False

        self.assertTrue(has_container)


class TestHTTPServer(unittest.TestCase):
    def test_http_ok(self):
        scanner.SEC_REPORT_DIR = "./tests/sec_reports/01"
        scanner.start_http_server(12345)
        r = requests.get("http://127.0.0.1:12345/metrics")
        self.assertTrue(r.ok)
        r2 = requests.get("http://127.0.0.1:12345/xxxxxx")
        self.assertFalse(r2.ok)
        r3 = requests.get("http://127.0.0.1:12345/")
        self.assertTrue(r3.ok)


class TestListAllPods(unittest.TestCase):
    @mock.patch('kubernetes.client.CoreV1Api')
    def test_list_all_pods(self, mock_core_api):
        pod1 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod1", namespace="teste1"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:1")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:1")])
                            )
        pod2 = client.V1Pod(metadata=client.V1ObjectMeta(name="pod2", namespace="teste2"),
                            spec=client.V1PodSpec(containers=[client.V1Container(name="test", image="teste:2")],
                                                  init_containers=[client.V1Container(name="test",
                                                                                      image="init_teste:2")],
                                                  image_pull_secrets=[client.V1LocalObjectReference(name="teste2")])
                            )
        mock_core_api.return_value = mock.Mock(list_pod_for_all_namespaces=lambda x=client.V1PodList(
            items=[pod1, pod2]): x)
        size = len(scanner.list_all_pods())
        self.assertEqual(size, 2)


def return_secret_obj(namespace, name, pass_key='.dockerconfigjson'):
    secret1 = client.V1Secret(metadata=client.V1ObjectMeta(namespace=namespace,
                                                           name=name),
                              type='kubernetes.io/dockerconfigjson',
                              data={
                                  pass_key: 'eyJhdXRocyI6eyJmYWtlLnJlZ2lzdHJ5LmlvIjp7InVzZXJuYW1lIjoidGVz'
                                            'dHVzZXIiLCJwYXNzd29yZCI6IjEyMzQ1NiIsImVtYWlsIjoidGVzdGVAdGVz'
                                            'dGUuY29tIiwiYXV0aCI6ImRHVnpkSFZ6WlhJNk1USXpORFUyIn19fQ=='}
                              )
    return secret1


class TestReadSecrets(unittest.TestCase):
    @mock.patch('kubernetes.client.CoreV1Api')
    def test_read_secret(self, mock_core_api):
        mock_core_api.return_value = mock.Mock(read_namespaced_secret=lambda ns, n: return_secret_obj(ns, n))
        s = scanner.read_secret("teste1", "registry")

        self.assertEqual(s["username"], "testuser")
        self.assertEqual(s["password"], "123456")

    @mock.patch('kubernetes.client.CoreV1Api')
    def test_error_read_secret(self, mock_core_api):
        mock_core_api.return_value = mock.Mock(read_namespaced_secret=lambda ns, n: return_secret_obj(ns, n, "invalid"))
        self.assertRaises(scanner.DockerConfigNotFound, scanner.read_secret, "teste1", "registry")


class TestPodsAssociatedWithIngress(unittest.TestCase):
    @mock.patch('kubernetes.client.NetworkingV1Api')
    @mock.patch('kubernetes.client.CoreV1Api')
    def test_pods_associated_with_ingress(self, mock_core_api, mock_extensions_api):
        ingress_list = client.V1IngressList(
            kind="IngressList",
            items=[
                client.V1Ingress(
                    metadata=client.V1ObjectMeta(
                        name="ingress1",
                        namespace="teste1"
                    ),
                    spec=client.V1IngressSpec(
                        rules=[
                            client.V1IngressRule(
                                host="test1.local.int",
                                http=client.V1HTTPIngressRuleValue(
                                    paths=[
                                        client.V1HTTPIngressPath(
                                            path="/teste1",
                                            path_type="Prefix",
                                            backend=client.V1IngressBackend(
                                                service=client.V1IngressServiceBackend(
                                                    name="service-teste1",
                                                    port=client.V1ServiceBackendPort(
                                                        number=80
                                                    )
                                                )
                                            )
                                        )
                                    ]
                                )
                            )
                        ]
                    )
                )
            ]
        )
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name="service-teste1",
                namespace="teste1"
            ),
            spec=client.V1ServiceSpec(
                cluster_ip="10.20.30.40",
                ports=[
                    client.V1ServicePort(
                        name="http",
                        port=80,
                        target_port=80
                    )
                ],
                selector={
                    "app": "teste1"
                }
            )
        )
        endpoint = client.V1EndpointsList(
            kind='EndpointsList',
            items=[
                client.V1Endpoints(
                    metadata=client.V1ObjectMeta(
                        name="service-teste1",
                        namespace="teste1"
                    ),
                    subsets=[
                        client.V1EndpointSubset(
                            addresses=[
                                client.V1EndpointAddress(
                                    ip="40.30.20.10",
                                    node_name="node-test",
                                    target_ref=client.V1LocalObjectReference(
                                        name="pod1"
                                    )
                                )
                            ]
                        )
                    ]
                )
            ]
        )
        mock_extensions_api.return_value = mock.Mock(list_ingress_for_all_namespaces=lambda x=ingress_list: x)
        mock_core_api.return_value = mock.Mock(read_namespaced_service=lambda name, namespace: service,
                                               list_namespaced_endpoints=lambda namespace, label_selector: endpoint)

        i = scanner.get_pods_associated_with_ingress()
        self.assertEqual(len(i), 1)

    @mock.patch('kubernetes.client.NetworkingV1Api')
    @mock.patch('kubernetes.client.CoreV1Api')
    def test_no_pods_associated_with_ingress(self, mock_core_api, mock_extensions_api):
        ingress_list = client.V1IngressList(
            kind="IngressList",
            items=[
                client.V1Ingress(
                    metadata=client.V1ObjectMeta(
                        name="ingress1",
                        namespace="teste1"
                    ),
                    spec=client.V1IngressSpec(
                        rules=[
                            client.V1IngressRule(
                                host="test1.local.int",
                                http=client.V1HTTPIngressRuleValue(
                                    paths=[
                                        client.V1HTTPIngressPath(
                                            path_type="Prefix",
                                            path="/teste1",
                                            backend=client.V1IngressBackend(
                                                service=client.V1IngressServiceBackend(
                                                    name="service-teste1",
                                                    port=80
                                                )
                                            )
                                        )
                                    ]
                                )
                            )
                        ]
                    )
                )
            ]
        )
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name="service-teste1",
                namespace="teste1"
            ),
            spec=client.V1ServiceSpec(
                cluster_ip="10.20.30.40",
                ports=[
                    client.V1ServicePort(
                        name="http",
                        port=80,
                        target_port=80
                    )
                ],
                selector={
                    "app": "teste1"
                }
            )
        )
        endpoint = client.V1EndpointsList(
            kind='EndpointsList',
            items=[
                client.V1Endpoints(
                    metadata=client.V1ObjectMeta(
                        name="service-teste1",
                        namespace="teste1"
                    ),
                    subsets=None
                )
            ]
        )
        mock_extensions_api.return_value = mock.Mock(list_ingress_for_all_namespaces=lambda x=ingress_list: x)
        mock_core_api.return_value = mock.Mock(read_namespaced_service=lambda name, namespace: service,
                                               list_namespaced_endpoints=lambda namespace, label_selector: endpoint)

        i = scanner.get_pods_associated_with_ingress()
        self.assertEqual(len(i), 0)


if __name__ == '__main__':
    unittest.main()
