import json
import unittest
import os
import scanner


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


if __name__ == '__main__':
    unittest.main()
