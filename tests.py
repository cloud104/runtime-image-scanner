import json
import unittest
import os
import scanner
from unittest import mock
from kubernetes import client


class TestSetup(unittest.TestCase):
    def test_setup(self):
        scanner.TRIVY_BIN_PATH = "/bin/bash"
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreporttest1"
        scanner.SEC_REPORT_DIR = "/tmp/secreportdirtest1"
        self.assertIsNone(scanner.setup())
        scanner.TRIVY_BIN_PATH = "/tmp/fake"
        self.assertRaises(FileNotFoundError, scanner.setup)


class TestCleanup(unittest.TestCase):
    def setUp(self) -> None:
        os.makedirs("/tmp/trivyreportstest2")

    def tearDown(self) -> None:
        os.rmdir("/tmp/trivyreportstest2")

    def test_cleanup(self):
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreportstest2"
        self.assertIsNone(scanner.cleanup())
        scanner.TRIVY_REPORT_DIR = "/tmp/trivyreportstest2w2222"
        self.assertIsNone(scanner.cleanup())


class TestReadSecReport(unittest.TestCase):
    def test_read_sec_report(self):
        scanner.SEC_REPORT_DIR = "./tests/sec_reports/01"
        self.assertEqual(type(scanner.read_sec_report()), bytes)
        scanner.SEC_REPORT_DIR = "./tests/fakedir"
        self.assertRaises(FileNotFoundError, scanner.read_sec_report)


class TestWriteSecReport(unittest.TestCase):
    def setUp(self) -> None:
        os.makedirs("/tmp/testcreatesecreport")

    def tearDown(self) -> None:
        os.remove("/tmp/testcreatesecreport/sec_report.json")
        os.rmdir("/tmp/testcreatesecreport")

    def test_write_sec_report(self):
        scanner.SEC_REPORT_DIR = "/tmp/testcreatesecreport"
        report = {"teste": "123"}
        self.assertIsNone(scanner.write_sec_report(report))
        with open("{}/sec_report.json".format(scanner.SEC_REPORT_DIR), "r") as f:
            t = json.loads(f.read())
        self.assertEqual(type(t), dict)


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


if __name__ == '__main__':
    unittest.main()
