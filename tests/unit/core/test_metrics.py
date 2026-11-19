#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import constants
from bandit.core import metrics


class MetricsTests(testtools.TestCase):
    def _expected_keys(self):
        keys = ["loc", "nosec", "skipped_tests"]
        for criteria, _ in constants.CRITERIA:
            for rank in constants.RANKING:
                keys.append(f"{criteria}.{rank}")
        return keys

    def test_totals_have_full_key_set(self):
        m = metrics.Metrics()
        self.assertEqual(
            sorted(self._expected_keys()), sorted(m.data["_totals"].keys())
        )

    def test_begin_creates_full_key_set(self):
        # a block created via begin() must have the same shape as _totals,
        # including for files that are skipped before any issue is counted
        m = metrics.Metrics()
        m.begin("syntax_error.py")

        self.assertEqual(
            sorted(self._expected_keys()), sorted(m.current.keys())
        )
        self.assertEqual(
            sorted(self._expected_keys()),
            sorted(m.data["syntax_error.py"].keys()),
        )
        # every value starts at zero
        self.assertTrue(all(v == 0 for v in m.current.values()))

    def test_aggregate_keeps_keys_for_skipped_file(self):
        m = metrics.Metrics()
        m.begin("syntax_error.py")  # no count_issues call, as on skip
        m.begin("ok.py")
        m.count_issues(
            [
                {
                    "SEVERITY": [0, 0, 5, 0],
                    "CONFIDENCE": [0, 0, 0, 10],
                }
            ]
        )
        m.aggregate()

        self.assertEqual(
            sorted(self._expected_keys()),
            sorted(m.data["syntax_error.py"].keys()),
        )
        self.assertEqual(11, len(m.data["_totals"]))
