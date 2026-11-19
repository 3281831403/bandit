#
# SPDX-License-Identifier: Apache-2.0
"""The five CI report formats must present findings in the same order."""
import csv
import json
import re
import tempfile
from xml.etree import ElementTree as ET

import testtools

import bandit
from bandit.core import config
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import csv as b_csv
from bandit.formatters import html as b_html
from bandit.formatters import json as b_json
from bandit.formatters import sarif as b_sarif
from bandit.formatters import xml as b_xml


class CrossFormatOrderingTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp_files = []
        conf = config.BanditConfig()

        def make_manager(agg_type):
            mgr = manager.BanditManager(conf, agg_type)
            mgr.results = [self._issue("zebra_test", "z.py", "B002"),
                           self._issue("alpha_test", "a.py", "B001"),
                           self._issue("mid_test", "m.py", "B003")]
            mgr.skipped = [("z_bad.py", "syntax error"),
                           ("a_bad.py", "syntax error")]
            return mgr

        self.make_manager = make_manager

    def _issue(self, test_name, fname, test_id):
        new_issue = issue.Issue(
            bandit.MEDIUM, issue.Cwe.OS_COMMAND_INJECTION,
            bandit.HIGH, f"text of {test_name}", test_id=test_id,
        )
        new_issue.fname = fname
        new_issue.lineno = 1
        new_issue.linerange = [1]
        new_issue.test = test_name
        new_issue.col_offset = 0
        new_issue.end_col_offset = 1
        return new_issue

    def _render(self, mgr, module):
        fd, path = tempfile.mkstemp()
        self.tmp_files.append(path)
        with open(path, "w") as f:
            module.report(mgr, f, bandit.LOW, bandit.LOW)
        return path

    def test_vuln_ordering_identical(self):
        mgr = self.make_manager("vuln")

        json_path = self._render(mgr, b_json)
        csv_path = self._render(mgr, b_csv)
        xml_path = self._render(mgr, b_xml)
        sarif_path = self._render(mgr, b_sarif)
        html_path = self._render(mgr, b_html)

        json_order = [
            r["test_name"] for r in json.load(open(json_path))["results"]
        ]
        with open(csv_path) as f:
            csv_order = [
                r["test_name"] for r in csv.DictReader(f) if r["test_name"]
            ]
        xml_order = [
            t.get("name")
            for t in ET.parse(xml_path).getroot().findall("testcase")
            if t.get("name") != "skipped"
        ]
        sarif_doc = json.load(open(sarif_path))
        rules = {
            r["id"]: r["name"]
            for r in sarif_doc["runs"][0]["tool"]["driver"]["rules"]
        }
        sarif_order = [
            rules[r["ruleId"]]
            for r in sarif_doc["runs"][0]["results"]
        ]
        html_order = re.findall(
            r'class="issue-block [^"]+">\s*<b>([^<]+): </b>',
            open(html_path).read(),
        )

        expected = ["alpha_test", "mid_test", "zebra_test"]
        self.assertEqual(expected, json_order)
        self.assertEqual(expected, csv_order)
        self.assertEqual(expected, xml_order)
        self.assertEqual(expected, sarif_order)
        self.assertEqual(expected, html_order)

    def test_skipped_files_identical_and_sorted(self):
        mgr = self.make_manager("file")

        json_path = self._render(mgr, b_json)
        csv_path = self._render(mgr, b_csv)
        xml_path = self._render(mgr, b_xml)

        json_skips = [e["filename"] for e in
                      json.load(open(json_path))["errors"]]
        with open(csv_path) as f:
            csv_skips = [
                r["filename"] for r in csv.DictReader(f)
                if not r["test_name"]
            ]
        xml_skips = [
            t.get("classname")
            for t in ET.parse(xml_path).getroot().findall("testcase")
            if t.get("name") == "skipped"
        ]
        expected = ["a_bad.py", "z_bad.py"]
        self.assertEqual(expected, json_skips)
        self.assertEqual(expected, csv_skips)
        self.assertEqual(expected, xml_skips)
