import os

# Local imports
from auditor import content_analyzer
from action_auditor import action_audit
from github_wrapper import GHWrapper
from lib.logger import AuditLogger


"""
Input:
    repo_dict - dictionary defining repo information
Output:
    scan result (if any) in scan.log file.
Summary:
    For a given workflow dictionary (name, content) this
    function will call content_analyzer to audit the workflow
    for any potential vulnerabilities. 
"""
def repo_analysis(repo_workflow):
    for workflow in repo_workflow:
        workflow_name = workflow['name']
        workflow_content = workflow['content']
        AuditLogger.info(f">> Scanning: {workflow_name}")
        content_analyzer(content=workflow_content) # will print out security issues

def main():
    target_type = os.environ.get('TARGET_TYPE',None) #repo, org, or user
    target_input = os.environ.get('REPOSITORY',None) #can be repo url, or a username for org/user
    
    AuditLogger.warning(f"> target type {target_type},  target_input {target_input}.\n")
    AuditLogger.warning(f"Test")
    exit()
    gh = GHWrapper()

    
    if target_type == 'repo':
        repos = gh.get_single_repo(repo_name=target_input)
    else:
        count, repos = gh.get_multiple_repos(target_name=target_input,
                                    target_type=target_type)
        AuditLogger.info(f"Metric: Scanning total {count} repos")
    
    AuditLogger.warning(f"> Scanning workflow. If no warning messages appear below, you're clear.\n")
    
    for repo_dict in repos:
        AuditLogger.info(f"\n\n> Starting audit of {repo_dict}")
        repo_workflows = repos[repo_dict]
        repo_analysis(repo_workflows)

    AuditLogger.info(f"> Checking for supply chain attacks.")
    action_audit()

main()
