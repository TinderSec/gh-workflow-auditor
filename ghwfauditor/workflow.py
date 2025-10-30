# Built-in imports
import json
import re
import importlib.resources
import sys

# External library imports
import yaml


class WorkflowParser:
    """Parse YAML workflow content"""

    def __init__(self, logger, yaml_content: str):
        self.logger = logger
        try:
            self.parsed_content = yaml.safe_load(
                yaml_content
            )  # We don't want a vulnerability ;)
        except:
            self.parsed_content = {"failed": True}

    def get_event_triggers(self) -> list:
        # Check what starts a workflow. Can be list or dict
        if self.parsed_content.get(True, None):
            if isinstance(self.parsed_content[True], list):
                return self.parsed_content[True]
            elif isinstance(self.parsed_content[True], dict):
                return list(self.parsed_content[True].keys())
            else:
                return [self.parsed_content[True]]

    def get_jobs(self) -> dict:
        return self.parsed_content.get("jobs", None)

    def get_jobs_count(self) -> int:
        # list how many jobs execute. Jobs run on their own individual runners.
        return len(self.parsed_content["jobs"].keys())

    def get_steps_for_jobs(self, job_dict: dict) -> list:
        # return a list of steps in a given job dictionary
        return job_dict.get("steps", None)

    def analyze_step(self, step: dict) -> tuple:
        actions = step.get("uses", None)
        run_command = step.get("run", None)
        with_input = step.get("with", None)
        step_environ = step.get(
            "env", None
        )  # you can define environment variables per step.
        return actions, run_command, with_input, step_environ


class WorkflowRisks:
    """Analyze various aspects of workflows to identify if it is risky."""

    def __init__(self, logger):
        """WorkflowRisks constructor

        Initialize a WorkflowRisks object from the scan configuration.
        This file is provided in the config directory.

        """
        self.logger = logger
        # get scan config regex ready
        self.unsafe_input = {}
        self.malicious_commits = {}
        try:
            scan_config = json.loads(
                importlib.resources.read_text("ghwfauditor.config", "scan.json")
            )
        except:
            self.logger.error("")
            sys.exit()
        self.triggers = scan_config["risky_events"]
        self.secrets = re.compile(scan_config["secrets"])
        for risky_input in scan_config["rce_risks"]["unsafe_inputs"]:
            self.unsafe_input[risky_input] = re.compile(
                scan_config["rce_risks"]["unsafe_inputs"][risky_input]
            )
        for commit_to_watch in scan_config["rce_risks"]["malicious_commits"]:
            self.malicious_commits[commit_to_watch] = re.compile(
                scan_config["rce_risks"]["malicious_commits"][commit_to_watch]
            )
        self.vulnerable = {"vulnerable": True}

    def risky_command(self, command_string) -> list:
        """Analyze commands and return risky commands"""
        found_matches = {}
        for regex in self.unsafe_input:
            if matches := self.unsafe_input[regex].finditer(command_string):
                matched_commands = [command.group() for command in matches]
                if matched_commands:
                    found_matches[regex] = matched_commands
        return found_matches

    def risky_trigger(self, trigger_name: str) -> bool:
        return bool(trigger_name in self.triggers)

    def risky_commit(self, referenced):
        """Analyze commits and return malicious commits"""
        found_matches = {}
        for regex in self.malicious_commits:
            if matches := self.malicious_commits[regex].finditer(referenced):
                matched_commits = [commit.group() for commit in matches]
                if matched_commits:
                    found_matches[regex] = matched_commits
        return found_matches

    def get_secrets(self, full_yaml: str) -> list:
        """Find and return every secrets being used in this workflow.

        If there is a RCE we can pull these secrets.

        """
        found_matches = []
        if matches := self.secrets.findall(full_yaml):
            for match in matches:
                if match not in found_matches:
                    found_matches.append(match)
        return found_matches


class WorkflowAuditor:
    """Analyze various aspects of workflows to identify if it is risky."""

    def __init__(self, logger):
        """WorkflowRisks constructor"""
        self.logger = logger
        self.workflow_risks = WorkflowRisks(logger)

    def risky_trigger_analysis(self, identified_triggers):
        """Return risky triggers from identified triggers"""
        return_triggers = []
        for trigger in identified_triggers:
            risky = self.workflow_risks.risky_trigger(trigger_name=trigger)
            if risky:
                return_triggers.append(trigger)
        return return_triggers

    def content_analyzer(self, content, action_file):
        """Identify risks in a YAML workflow

        This is the critical part of the whole tool. It parses the
        YAML content to identify security issues. It does so by
        parsing YAML to JSON and identifying keys such as event triggers,
        jobs and steps. It then checks the identified key-value pairs
        against known risks through WorkflowParser.

        Arguments:
            content - YAML content read from the workflow files.
            logger - configured logger
        Returns:
            scan result (if any) in scan.log file.
        """
        risky_triggers = []
        all_actions = []
        commands = []
        environs = {}
        # checked_action = []
        workflow_client = WorkflowParser(self.logger, content)
        if workflow_client.parsed_content and not workflow_client.parsed_content.get(
            "failed", None
        ):  # Sanity check to make sure proper YAML was given.
            event_triggers = (
                workflow_client.get_event_triggers()
            )  # Identify what event(s) will start the workflow.
            secrets = self.workflow_risks.get_secrets(
                content
            )  # get all the secrets in the workflow. (Uses regex). This helps understand impact.
            all_jobs = (
                workflow_client.get_jobs()
            )  # Identify all jobs in the workflow. Stored as dictionary

            counter = 1  # Counter used to identify which line of code is vulnerable.
            if secrets:
                self.logger.success(
                    f"Found secrets used in workflow: {','.join(secrets)}"
                )

            # Retrieve and store all needed information for a workflow run for analysis.
            if all_jobs:
                for job in all_jobs:
                    steps = all_jobs[job].get("steps", None)
                    if not steps:
                        steps = [all_jobs[job]]
                    try:
                        environs.update(all_jobs[job].get("env", {}))
                    except:
                        self.logger.error("Environ variable is malformed")
                    for step_number, step in enumerate(steps):
                        actions, run_command, with_input, step_environ = (
                            workflow_client.analyze_step(step)
                        )
                        if actions:
                            all_actions.append(
                                {f"Job{counter}.Step{step_number+1}": step}
                            )
                        if step_environ:
                            if isinstance(step_environ, str):
                                step_environ = {f"{step_number}{step}": step_environ}
                            environs.update(step_environ)
                        if run_command:
                            commands.append({f"Job{counter}.Step{step_number+1}": step})
                    counter += 1

                # Start analyzing the retrieved information.
                try:
                    # Analyzes event triggers to see if they are user controlled.
                    risky_triggers = self.risky_trigger_analysis(
                        identified_triggers=event_triggers
                    )

                    # Analyzes commands called by Steps.
                    for command in commands:
                        for step_number, step_dict in command.items():
                            risky_command = self.workflow_risks.risky_command(
                                command_string=step_dict["run"]
                            )
                            if risky_command:
                                for regex, matched_strings in risky_command.items():
                                    if (
                                        regex == "environ_regex"
                                    ):  # not all environments are bad. Check if this environment is user controlled.
                                        # get the key out of the matched strings. We use this to check if the environ variable stores any user controlled input.
                                        for environ_variable in matched_strings:
                                            environ_variable = (
                                                environ_variable.strip("${{")
                                                .strip("}}")
                                                .split(".")[1]
                                                .strip()
                                            )
                                            # get environ value
                                            environ_var_value = environs.get(
                                                environ_variable, None
                                            )
                                            if environ_var_value:
                                                risky_env = (
                                                    self.workflow_risks.risky_command(
                                                        command_string=environ_var_value
                                                    )
                                                )
                                                if (
                                                    risky_env
                                                    and list(risky_env.keys())[0]
                                                    != "environ_regex"
                                                ):
                                                    self.logger.warning(
                                                        f">>> Security Issue: RCE detected with {regex} in {step_number}: ENV variable {environ_variable} is called through GitHub context and takes user input {environ_var_value}"
                                                    )
                                    else:
                                        self.logger.warning(
                                            f"RCE detected with {regex} in {step_number}: Usage of {','.join(matched_strings)} found."
                                        )

                    # Some actions combined with triggers can be bad. Check for those cases.
                    action_storage = action_file
                    for action in all_actions:
                        for step_number, step_dict in action.items():
                            action_name = step_dict.get("uses", None)
                            action_storage.write(f"{action_name}\n")
                            if "actions/checkout" in action_name:
                                # check if specific branch is checked out
                                if step_dict.get("with", None):
                                    if step_dict["with"].get("ref", None):
                                        ref_value = step_dict["with"].get("ref")
                                        risky_commits = (
                                            self.workflow_risks.risky_commit(
                                                referenced=ref_value
                                            )
                                        )
                                        if risky_commits:
                                            if "pull_request_target" in risky_triggers:
                                                self.logger.warning(
                                                    f"Malicious pull request used in actions/checkout. Vulnerable step: {step_number} "
                                                )
                except Exception as workflow_err:
                    self.logger.error(
                        f"Parsing workflow went wrong. {str(workflow_err)}"
                    )
