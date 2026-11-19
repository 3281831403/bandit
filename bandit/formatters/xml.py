#
# SPDX-License-Identifier: Apache-2.0
r"""
=============
XML Formatter
=============

This formatter outputs the issues as XML.

:Example:

.. code-block:: xml

    <?xml version='1.0' encoding='utf-8'?>
    <testsuite name="bandit" tests="1"><testcase
    classname="examples/yaml_load.py" name="blacklist_calls"
    test_id="B301" line="5"><error
    message="Use of unsafe yaml load. Allows instantiation of arbitrary
    objects. Consider yaml.safe_load().&#10;" type="MEDIUM"
    more_info="https://bandit.readthedocs.io/en/latest/">Test ID: B301
    Severity: MEDIUM Confidence: HIGH
    CWE: CWE-20 (https://cwe.mitre.org/data/definitions/20.html) Use of unsafe
    yaml load.
    Allows instantiation of arbitrary objects. Consider yaml.safe_load().

    Location examples/yaml_load.py:5</error></testcase></testsuite>

.. versionadded:: 0.12.0

.. versionchanged:: 1.5.0
    New field `more_info` added to output

.. versionchanged:: 1.7.3
    New field `CWE` added to output

.. versionchanged:: 1.8.0
    ``testcase`` elements carry ``test_id`` and ``line`` attributes matching
    the JSON report, and skipped files are emitted as their own testcases

"""
import logging
import sys
from xml.etree import ElementTree as ET  # nosec: B405

from bandit.core import docs_utils
from bandit.formatters import utils as formatter_utils

LOG = logging.getLogger(__name__)


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Prints issues in XML format

    :param manager: the bandit manager object
    :param fileobj: The output file object, which may be sys.stdout
    :param sev_level: Filtering severity level
    :param conf_level: Filtering confidence level
    :param lines: Number of lines to report, -1 for all
    """

    issues = manager.get_issue_list(sev_level=sev_level, conf_level=conf_level)
    sort_attr = formatter_utils.report_sort_attr(manager.agg_type)
    issues = sorted(issues, key=lambda i: getattr(i, sort_attr))

    # skipped files are part of the test count: one testcase per file,
    # matching the entries reported as "errors" by the JSON formatter
    skipped = manager.get_skipped()
    skipped = sorted(skipped, key=lambda s: s[0])
    root = ET.Element(
        "testsuite", name="bandit", tests=str(len(issues) + len(skipped))
    )

    for issue in issues:
        test = issue.test
        testcase = ET.SubElement(
            root,
            "testcase",
            classname=issue.fname,
            name=test,
            test_id=issue.test_id,
            line=str(issue.lineno),
        )

        text = (
            "Test ID: %s Severity: %s Confidence: %s\nCWE: %s\n%s\n"
            "Location %s:%s"
        )
        text %= (
            issue.test_id,
            issue.severity,
            issue.confidence,
            issue.cwe,
            issue.text,
            issue.fname,
            issue.lineno,
        )
        ET.SubElement(
            testcase,
            "error",
            more_info=docs_utils.get_url(issue.test_id),
            type=issue.severity,
            message=issue.text,
        ).text = text

    for fname, reason in skipped:
        testcase = ET.SubElement(
            root,
            "testcase",
            classname=fname,
            name="skipped",
            test_id="",
            line="0",
        )
        ET.SubElement(testcase, "error", message=reason).text = (
            f"Skipped {fname}: {reason}"
        )

    tree = ET.ElementTree(root)

    if fileobj.name == sys.stdout.name:
        fileobj = sys.stdout.buffer
    elif fileobj.mode == "w":
        fileobj.close()
        fileobj = open(fileobj.name, "wb")

    with fileobj:
        tree.write(fileobj, encoding="utf-8", xml_declaration=True)

    if fileobj.name != sys.stdout.name:
        LOG.info("XML output written to file: %s", fileobj.name)
