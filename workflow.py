import json
import re
import yaml

class WorkflowParser():
    def __init__(self, yaml_content: str):
        try:
            self.parsed_content = yaml.safe_load(yaml_content) # We don't want a vulnerability ;)
        except:
            self.parsed_content= {'failed':True}

    def get_event_triggers(self) -> list:
        # Check what starts a workflow. Can be list or dict
        if self.parsed_content.get(True,None):
            if isinstance(self.parsed_content[True], list):
                return self.parsed_content[True]
            elif isinstance(self.parsed_content[True], dict):
                return list(self.parsed_content[True].keys())
            else:
                return [self.parsed_content[True]]

    def get_jobs(self) -> dict:
        return self.parsed_content.get('jobs',None)

    def get_jobs_count(self) -> int:
        # list how many jobs execute. Jobs run on their own individual runners.
        return len(self.parsed_content['jobs'].keys())

    def get_steps_for_jobs(self, job_dict: dict) -> list:
        # return a list of steps in a given job dictionary
        return job_dict.get('steps',None)

    def analyze_step(self, step:dict) -> tuple:
        actions = step.get('uses',None)
        run_command = step.get('run',None)
        with_input = step.get('with',None)
        step_environ = step.get('env', None) # you can define environment variables per step.
        return actions, run_command, with_input, step_environ


# Analyze various aspects of workflows to identify if it is risky.
class WorkflowVulnAudit():
    def __init__(self):
        # get scan config regex ready
        self.unsafe_input = {}
        self.malicious_commits = {}
        with open('scan_config.json','r') as scan_file:
            scan_config = json.loads(scan_file.read())
            self.triggers = scan_config['risky_events']
            self.secrets = re.compile(scan_config['secrets'])
        for risky_input in scan_config['rce_risks']['unsafe_inputs']:
            self.unsafe_input[risky_input] = re.compile(scan_config['rce_risks']['unsafe_inputs'][risky_input])
        for commit_to_watch in scan_config['rce_risks']['malicious_commits']:
            self.malicious_commits[commit_to_watch] = re.compile(scan_config['rce_risks']['malicious_commits'][commit_to_watch])
        self.vulnerable = {'vulnerable':True}
    
    def risky_command(self, command_string) -> list:
        found_matches = {}
        for regex in self.unsafe_input:
            if matches := self.unsafe_input[regex].finditer(command_string):
                matched_commands = [command.group() for command in matches]
                if matched_commands:
                    found_matches[regex] = matched_commands
        return found_matches

    def risky_trigger(self, trigger_name: str) -> bool:
        return bool(trigger_name in self.triggers)
    
    # Find and return every secrets being used in this workflow. If there is a RCE we can pull these secrets.
    def get_secrets(self, full_yaml: str) -> list:
        found_matches = []
        if matches:= self.secrets.findall(full_yaml):
            for match in matches:
                if match not in found_matches:
                    found_matches.append(match)
        return found_matches
    
    def risky_commit(self, referenced):
        found_matches = {}
        for regex in self.malicious_commits:
            if matches := self.malicious_commits[regex].finditer(referenced):
                matched_commits = [commit.group() for commit in matches]
                if matched_commits:
                    found_matches[regex] = matched_commits
        return found_matches
