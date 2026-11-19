#
# SPDX-License-Identifier: Apache-2.0
r"""
=============
CSV Formatter
=============

This formatter outputs the issues in a comma separated values format.

:Example:

.. code-block:: none

    filename,test_name,test_id,issue_severity,issue_confidence,issue_cwe,
    issue_text,line_number,line_range,more_info
    examples/yaml_load.py,blacklist_calls,B301,MEDIUM,HIGH,
    https://cwe.mitre.org/data/definitions/20.html,"Use of unsafe yaml
    load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().
    ",5,[5],https://bandit.readthedocs.io/en/latest/

.. versionadded:: 0.11.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

.. versionchanged:: 1.8.0
    An empty ``issue_cwe`` is reported as an empty value instead of raising
    a ``KeyError`` when a plugin sets no CWE, and skipped files are appended
    as rows carrying only ``filename`` and ``issue_text``

"""
# Necessary for this formatter to work when imported on Python 2. Importing
# the standard library's csv module conflicts with the name of this module.
import csv
import logging
import sys

from bandit.core import docs_utils
from bandit.formatters import utils as formatter_utils

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in CSV format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    results = manager.get_issue_list(
        sev_level=sev_level, conf_level=conf_level
    )
    sort_attr = formatter_utils.report_sort_attr(manager.agg_type)
    results = sorted(results, key=lambda i: getattr(i, sort_attr))
    skipped = sorted(manager.get_skipped(), key=lambda s: s[0])

    with fileobj:
        fieldnames = [
            "filename",
            "test_name",
            "test_id",
            "issue_severity",
            "issue_confidence",
            "issue_cwe",
            "issue_text",
            "line_number",
            "col_offset",
            "end_col_offset",
            "line_range",
            "more_info",
        ]

        writer = csv.DictWriter(
            fileobj, fieldnames=fieldnames, extrasaction="ignore"
        )
        writer.writeheader()
        for result in results:
            r = result.as_dict(with_code=False)
            # a plugin may omit the CWE, in which case JSON carries an
            # empty dict; mirror that instead of raising a KeyError
            r["issue_cwe"] = r["issue_cwe"].get("link", "")
            r["more_info"] = docs_utils.get_url(r["test_id"])
            writer.writerow(r)

        # report skipped files (e.g. syntax errors) so CSV stays consistent
        # with the errors section of the JSON report; only the columns that
        # carry meaning for a skipped file are filled in
        for fname, reason in skipped:
            writer.writerow({"filename": fname, "issue_text": reason})

    if fileobj.name != sys.stdout.name:
        LOG.info("CSV output written to file: %s", fileobj.name)
