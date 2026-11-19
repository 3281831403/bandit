# Copyright (c) 2016 Rackspace, Inc.
# Copyright (c) 2016 Hewlett Packard Enterprise
#
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for formatting plugins for Bandit."""
import io


def wrap_file_object(fileobj):
    """If the fileobj passed in cannot handle text, use TextIOWrapper
    to handle the conversion.
    """
    if isinstance(fileobj, io.TextIOBase):
        return fileobj
    return io.TextIOWrapper(fileobj)


def report_sort_key(agg_type):
    """Return the sort key every formatter must use for its issue list.

    All report formats have to order findings identically so that the
    JSON gate, SARIF upload, XML, CSV and HTML reports line up. With
    ``-a vuln`` the aggregation is by vulnerability, otherwise by file.

    The returned name matches the key used in the dict produced by
    ``Issue.as_dict()`` (e.g. the JSON report); use
    :func:`report_sort_attr` when sorting ``Issue`` objects directly.
    """
    if agg_type == "vuln":
        return "test_name"
    return "filename"


def report_sort_attr(agg_type):
    """Return the ``Issue`` attribute corresponding to the sort key."""
    if agg_type == "vuln":
        return "test"
    return "fname"
