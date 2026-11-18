# Copyright 2016 IBM Corp.
#
# SPDX-License-Identifier: Apache-2.0
import os
import shutil
import subprocess

import fixtures
import testtools

new_candidates_all_total_lines = "Total lines of code: 12"
new_candidates_some_total_lines = "Total lines of code: 9"
new_candidates_no_nosec_lines = "Total lines skipped (#nosec): 0"
new_candidates_skip_nosec_lines = "Total lines skipped (#nosec): 3"
baseline_no_skipped_files = "Files skipped (0):"
baseline_no_issues_found = "No issues identified."
xml_sax_issue_id = "Issue: [B317:blacklist]"
yaml_load_issue_id = "Issue: [B506:yaml_load]"
shell_issue_id = "Issue: [B602:subprocess_popen_with_shell_equals_true]"
candidate_example_one = "subprocess.Popen('/bin/ls *', shell=True)"
candidate_example_two = "subprocess.Popen('/bin/ls *', shell=True) # nosec"
candidate_example_three = "y = yaml.load(temp_str)"
candidate_example_four = "y = yaml.load(temp_str) # nosec"
candidate_example_five = "xml.sax.make_parser()"
candidate_example_six = "xml.sax.make_parser() # nosec"


class BaselineFunctionalTests(testtools.TestCase):
    """Functional tests for Bandit baseline.

    This set of tests is used to verify that the baseline comparison handles
    finding and comparing results appropriately. The only comparison is the
    number of candidates per file, meaning that any candidates found may
    already exist in the baseline. In this case, all candidates are flagged
    and a user will need to investigate the candidates related to that file.
    """

    def setUp(self):
        super().setUp()
        self.examples_path = "examples"
        self.baseline_commands = ["bandit", "-r"]
        self.baseline_report_file = "baseline_report.json"

    def _run_bandit_baseline(self, target_directory, baseline_file):
        """A helper method to run bandit baseline

        This method will run the bandit baseline test provided an existing
        baseline report and the target directory containing the content to be
        tested.
        :param target_directory: Directory containing content to be compared
        :param baseline_file: File containing an existing baseline report
        :return The baseline test results and return code
        """
        cmds = self.baseline_commands + ["-b", baseline_file, target_directory]
        process = subprocess.Popen(
            cmds,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        stdout, stderr = process.communicate()
        return (stdout.decode("utf-8"), process.poll())

    def _create_baseline(self, baseline_paired_files):
        """A helper method to create a baseline to use during baseline test

        This method will run bandit to create an initial baseline that can
        then be used during the bandit baseline test. Since the file contents
        of the baseline report can be extremely dynamic and difficult to create
        ahead of time, we do this at runtime to reduce the risk of missing
        something. To do this, we must temporary replace the file contents
        with different code which will produce the proper baseline results to
        be used during the baseline test.
        :param baseline_paired_files A dictionary based set of files for which
        to create the baseline report with. For each key file, a value file
        is provided, which contains content to use in place of the key file
        when the baseline report is created initially.
        :return The target directory for the baseline test and the return code
        of the bandit run to help determine whether the baseline report was
        populated
        """
        target_directory = self.useFixture(fixtures.TempDir()).path
        baseline_results = os.path.join(
            target_directory, self.baseline_report_file
        )
        for key_file, value_file in baseline_paired_files.items():
            shutil.copy(
                os.path.join(self.examples_path, value_file),
                os.path.join(target_directory, key_file),
            )
        cmds = self.baseline_commands + [
            "-f",
            "json",
            "-o",
            baseline_results,
            target_directory,
        ]
        process = subprocess.Popen(
            cmds,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        stdout, stderr = process.communicate()
        return_code = process.poll()
        for key_file, value_file in baseline_paired_files.items():
            shutil.copy(
                os.path.join(self.examples_path, key_file),
                os.path.join(target_directory, key_file),
            )
        return (target_directory, return_code)

    def test_no_new_candidates(self):
        """Tests when there are no new candidates

        Test that bandit returns no issues found, as there are no new
        candidates found compared with those found from the baseline.
        """
        baseline_report_files = {
            "new_candidates-all.py": "new_candidates-all.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found results
        self.assertEqual(1, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were no results (no candidates found)
        self.assertEqual(0, return_code)
        self.assertIn(new_candidates_all_total_lines, return_value)
        self.assertIn(new_candidates_skip_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(baseline_no_issues_found, return_value)

    def test_no_existing_no_new_candidates(self):
        """Tests when there are no new or existing candidates

        Test file with no existing candidates from baseline and no new
        candidates.
        """
        baseline_report_files = {"okay.py": "okay.py"}
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found nothing
        self.assertEqual(0, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were no results (no candidates found)
        self.assertEqual(0, return_code)
        self.assertIn("Total lines of code: 1", return_value)
        self.assertIn(new_candidates_no_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(baseline_no_issues_found, return_value)

    def test_no_existing_with_new_candidates(self):
        """Tests when there are new candidates and no existing candidates

        Test that bandit returns issues found in file that had no existing
        candidates from baseline but now contain candidates.
        """
        baseline_report_files = {
            "new_candidates-all.py": "new_candidates-none.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found nothing
        self.assertEqual(0, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were results (candidates found)
        self.assertEqual(1, return_code)
        self.assertIn(new_candidates_all_total_lines, return_value)
        self.assertIn(new_candidates_skip_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(xml_sax_issue_id, return_value)
        self.assertIn(yaml_load_issue_id, return_value)
        self.assertIn(shell_issue_id, return_value)
        # candidate #1
        self.assertIn(candidate_example_one, return_value)
        # candidate #3
        self.assertIn(candidate_example_three, return_value)
        # candidate #5
        self.assertIn(candidate_example_five, return_value)

    def test_existing_and_new_candidates(self):
        """Tests when tere are new candidates and existing candidates

        Test that bandit returns issues found in file with existing
        candidates. The new candidates should be returned in this case.
        """
        baseline_report_files = {
            "new_candidates-all.py": "new_candidates-some.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found results
        self.assertEqual(1, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were results (candidates found)
        self.assertEqual(1, return_code)
        self.assertIn(new_candidates_all_total_lines, return_value)
        self.assertIn(new_candidates_skip_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(xml_sax_issue_id, return_value)
        self.assertIn(yaml_load_issue_id, return_value)
        # candidate #3
        self.assertIn(candidate_example_three, return_value)
        # candidate #5
        self.assertIn(candidate_example_five, return_value)

    def test_no_new_candidates_include_nosec(self):
        """Test to check nosec references with no new candidates

        Test that nosec references are included during a baseline test, which
        would normally be ignored. In this test case, there are no new
        candidates even while including the nosec references.
        """
        self.baseline_commands.append("--ignore-nosec")
        baseline_report_files = {
            "new_candidates-all.py": "new_candidates-all.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found results
        self.assertEqual(1, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were no results (candidates found)
        self.assertEqual(0, return_code)
        self.assertIn(new_candidates_all_total_lines, return_value)
        self.assertIn(new_candidates_no_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(baseline_no_issues_found, return_value)

    def test_new_candidates_include_nosec_only_nosecs(self):
        """Test to check nosec references with new only nosec candidates

        Test that nosec references are included during a baseline test, which
        would normally be ignored. In this test case, there are new candidates
        which are specifically nosec references.
        """
        self.baseline_commands.append("--ignore-nosec")
        baseline_report_files = {
            "new_candidates-nosec.py": "new_candidates-none.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found nothing
        self.assertEqual(0, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were results (candidates found)
        self.assertEqual(1, return_code)
        self.assertIn(new_candidates_some_total_lines, return_value)
        self.assertIn(new_candidates_no_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(xml_sax_issue_id, return_value)
        self.assertIn(yaml_load_issue_id, return_value)
        self.assertIn(shell_issue_id, return_value)
        # candidate #2
        self.assertIn(candidate_example_two, return_value)
        # candidate #4
        self.assertIn(candidate_example_four, return_value)
        # candidate #6
        self.assertIn(candidate_example_six, return_value)

    def test_new_candidates_include_nosec_new_nosecs(self):
        """Test to check nosec references with new candidates, including nosecs

        Test that nosec references are included during a baseline test, which
        would normally be ignored. In this test case, there are new candidates
        that also includes new nosec references as well.
        """
        self.baseline_commands.append("--ignore-nosec")
        baseline_report_files = {
            "new_candidates-all.py": "new_candidates-none.py"
        }
        target_directory, baseline_code = self._create_baseline(
            baseline_report_files
        )
        # assert the initial baseline found nothing
        self.assertEqual(0, baseline_code)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        return_value, return_code = self._run_bandit_baseline(
            target_directory, baseline_report
        )
        # assert there were results (candidates found)
        self.assertEqual(1, return_code)
        self.assertIn(new_candidates_all_total_lines, return_value)
        self.assertIn(new_candidates_no_nosec_lines, return_value)
        self.assertIn(baseline_no_skipped_files, return_value)
        self.assertIn(xml_sax_issue_id, return_value)
        self.assertIn(yaml_load_issue_id, return_value)
        self.assertIn(shell_issue_id, return_value)
        # candidate #1
        self.assertIn(candidate_example_one, return_value)
        # candidate #2
        self.assertIn(candidate_example_two, return_value)
        # candidate #3
        self.assertIn(candidate_example_three, return_value)
        # candidate #4
        self.assertIn(candidate_example_four, return_value)
        # candidate #5
        self.assertIn(candidate_example_five, return_value)
        # candidate #6
        self.assertIn(candidate_example_six, return_value)

    def _run_bandit(self, args, cwd=None):
        """Run a bandit command and return the output and return code."""
        process = subprocess.Popen(
            ["bandit"] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            close_fds=True,
        )
        stdout, stderr = process.communicate()
        return (stdout.decode("utf-8"), process.poll())

    def _create_baseline_from_contents(self, contents):
        """Populate a directory with the given contents and baseline it."""
        target_directory = self.useFixture(fixtures.TempDir()).path
        for name, data in contents.items():
            with open(os.path.join(target_directory, name), "w") as fd:
                fd.write(data)
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        _, return_code = self._run_bandit(
            ["-r", "-f", "json", "-o", baseline_report, target_directory]
        )
        return target_directory, baseline_report, return_code

    def test_added_duplicate_issue_is_a_candidate(self):
        """An extra occurrence of an existing issue counts as new.

        Adding a second identical assert statement to a file produces an issue
        that is equal to the one in the baseline. It must still be reported,
        otherwise increased counts pass the gate unnoticed.
        """
        contents = {"duplicate.py": "assert True\n"}
        target_directory, baseline_report, baseline_code = (
            self._create_baseline_from_contents(contents)
        )
        self.assertEqual(1, baseline_code)

        target_file = os.path.join(target_directory, "duplicate.py")

        # unchanged content must produce no candidates
        output, return_code = self._run_bandit(
            ["-b", baseline_report, target_file]
        )
        self.assertEqual(0, return_code)
        self.assertIn(baseline_no_issues_found, output)

        # an extra identical issue must be reported
        with open(target_file, "w") as fd:
            fd.write("assert True\nassert True\n")
        output, return_code = self._run_bandit(
            ["-b", baseline_report, target_file]
        )
        self.assertEqual(1, return_code)
        self.assertIn("Issue: [B101:assert_used]", output)

    def test_baseline_matches_alternate_path_spellings(self):
        """How a path is spelled must not affect baseline matching."""
        contents = {
            "assert-example.py": "assert True\n",
            "yaml-example.py": "import yaml\nyaml.load('a')\n",
        }
        target_directory, baseline_report, _ = (
            self._create_baseline_from_contents(contents)
        )

        parent = os.path.dirname(target_directory)
        directory_name = os.path.basename(target_directory)
        spelled_paths = [
            directory_name,
            "./" + directory_name,
            directory_name + "/",
            target_directory,
        ]
        for path in spelled_paths:
            output, return_code = self._run_bandit(
                ["-r", "-b", baseline_report, path], cwd=parent
            )
            self.assertEqual(
                0,
                return_code,
                f"alternate spelling {path!r} reported new candidates:\n"
                f"{output}",
            )
            self.assertIn(baseline_no_issues_found, output)

    def test_baseline_issue_text_is_stable_across_processes(self):
        """Regenerating a baseline and rerunning must report nothing new.

        Issue texts that embed process-specific data (such as the memory
        address of an object) make every run look like a new finding.
        """
        with open("examples/tarfile_extractall.py") as fd:
            contents = {"tarfile_extractall.py": fd.read()}

        target_directory, baseline_report, baseline_code = (
            self._create_baseline_from_contents(contents)
        )
        self.assertEqual(1, baseline_code)

        output, return_code = self._run_bandit(
            ["-r", "-b", baseline_report, target_directory]
        )
        self.assertEqual(0, return_code)
        self.assertIn(baseline_no_issues_found, output)

    def test_baseline_with_severity_filter(self):
        """Severity filtering must not create false candidates."""
        with open("examples/tarfile_extractall.py") as fd:
            contents = {"tarfile_extractall.py": fd.read()}

        target_directory = self.useFixture(fixtures.TempDir()).path
        baseline_report = os.path.join(
            target_directory, self.baseline_report_file
        )
        target_file = os.path.join(target_directory, "tarfile_extractall.py")
        with open(target_file, "w") as fd:
            fd.write(contents["tarfile_extractall.py"])

        _, baseline_code = self._run_bandit(
            [
                "-ll",
                "-r",
                "-f",
                "json",
                "-o",
                baseline_report,
                target_directory,
            ]
        )
        self.assertEqual(1, baseline_code)

        output, return_code = self._run_bandit(
            ["-ll", "-r", "-b", baseline_report, target_directory]
        )
        self.assertEqual(0, return_code)
        self.assertIn(baseline_no_issues_found, output)
