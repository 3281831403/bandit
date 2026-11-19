#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.formatters import utils


class FormatterUtilsTests(testtools.TestCase):
    def test_report_sort_key_modes(self):
        self.assertEqual("test_name", utils.report_sort_key("vuln"))
        self.assertEqual("filename", utils.report_sort_key("file"))

    def test_report_sort_attr_modes(self):
        self.assertEqual("test", utils.report_sort_attr("vuln"))
        self.assertEqual("fname", utils.report_sort_attr("file"))

    def test_key_and_attr_agree_per_mode(self):
        # dict key (as_dict / JSON) and Issue attr must describe the
        # same field for every aggregation mode
        mapping = {
            "test_name": "test",
            "filename": "fname",
        }
        for agg_type in ("vuln", "file"):
            self.assertEqual(
                mapping[utils.report_sort_key(agg_type)],
                utils.report_sort_attr(agg_type),
            )
