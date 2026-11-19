#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import copy
import logging
import warnings

from bandit.core import constants
from bandit.core import context as b_context
from bandit.core import utils

warnings.formatwarning = utils.warnings_formatter
LOG = logging.getLogger(__name__)


class BanditTester:
    def __init__(self, testset, debug, nosec_lines, metrics):
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.metrics = metrics
        # line numbers whose blanket nosec comment has already been counted,
        # so a single suppressed line is only counted once however many
        # findings it hides
        self._blanket_nosec_counted = set()

    def run_tests(self, raw_context, checktype):
        """Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: a score based on the number and type of test results with
                extra metrics about nosec comments
        """

        scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # execute test with an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, "_config"):
                    result = test(context, test._config)
                else:
                    result = test(context)

                if result is not None:
                    nosec_records = self._get_nosec_records(
                        temp_context, test_result=result
                    )

                    if isinstance(temp_context["filename"], bytes):
                        result.fname = temp_context["filename"].decode("utf-8")
                    else:
                        result.fname = temp_context["filename"]
                    result.fdata = temp_context["file_data"]

                    if result.lineno is None:
                        result.lineno = temp_context["lineno"]
                    if result.linerange == []:
                        result.linerange = temp_context["linerange"]
                    if result.col_offset == -1:
                        result.col_offset = temp_context["col_offset"]
                    result.end_col_offset = temp_context.get(
                        "end_col_offset", 0
                    )
                    result.test = name
                    if result.test_id == "":
                        result.test_id = test._test_id

                    # decide whether a nosec comment suppresses this finding.
                    # Blanket (bare) nosec comments suppress the whole line;
                    # comments naming ids suppress only those ids; unknown
                    # ids never suppress anything.
                    suppressed = False
                    for lineno, nosec in nosec_records:
                        if nosec.blanket:
                            LOG.debug("skipped, nosec without test number")
                            if lineno not in self._blanket_nosec_counted:
                                self._blanket_nosec_counted.add(lineno)
                                self.metrics.note_nosec()
                            suppressed = True
                        elif result.test_id in nosec.test_ids:
                            LOG.debug(
                                f"skipped, nosec for test {result.test_id}"
                            )
                            self.metrics.note_skipped_test()
                            suppressed = True
                    if suppressed:
                        continue

                    self.results.append(result)

                    LOG.debug("Issue identified by %s: %s", name, result)
                    sev = constants.RANKING.index(result.severity)
                    val = constants.RANKING_VALUES[result.severity]
                    scores["SEVERITY"][sev] += val
                    con = constants.RANKING.index(result.confidence)
                    val = constants.RANKING_VALUES[result.confidence]
                    scores["CONFIDENCE"][con] += val
                else:
                    nosec_records = self._get_nosec_records(temp_context)
                    if any(
                        test._test_id in nosec.test_ids
                        for _, nosec in nosec_records
                    ):
                        LOG.warning(
                            f"nosec encountered ({test._test_id}), but no "
                            f"failed test on file "
                            f"{temp_context['filename']}:"
                            f"{temp_context['lineno']}"
                        )

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    def _get_nosec_records(self, context, test_result=None):
        """Collect the nosec comments applicable to this context.

        Nosec comments are matched both on the result's own line and on every
        line of the enclosing statement (its linerange).

        :param context: temp context
        :param test_result: optional test result
        :return: list of (line number, NosecRecord) tuples for the context
        """
        linenos = set(context["linerange"])
        if test_result is not None:
            linenos.add(test_result.lineno)
        return [
            (lineno, self.nosec_lines[lineno])
            for lineno in linenos
            if lineno in self.nosec_lines
        ]

    @staticmethod
    def report_error(test, context, error):
        what = "Bandit internal error running: "
        what += f"{test} "
        what += "on file %s at line %i: " % (
            context._context["filename"],
            context._context["lineno"],
        )
        what += str(error)
        import traceback

        what += traceback.format_exc()
        LOG.error(what)
