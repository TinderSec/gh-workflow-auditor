import argparse

# Local imports
from auditor import content_analyzer
from action_auditor import action_audit
from github_wrapper import GHWrapper
from lib.logger import AuditLogger


gh = GHWrapper()

"""
Input:
   repo_dict - dictionary defining repo information
   scan_folder - Location where the repo is cloned
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
    # Supporting user provided arguments: type, and scan target.
    parser = argparse.ArgumentParser(description='Identify vulnerabilities in GitHub Actions workflow')
    parser.add_argument('--type',choices=['repo','org','user'],
                        help='Type of entity that is being scanned.')
    parser.add_argument('input',help='Org, user or repo name (owner/name)')
    args = parser.parse_args()

    target_type = args.type #repo, org, or user
    target_input = args.input #can be repo url, or a username for org/user
    
    if target_type == 'repo':
        repos = gh.get_single_repo(repo_name=target_input)
    else:
        count, repos = gh.get_multiple_repos(target_name=target_input,
                                    target_type=target_type)
        AuditLogger.info(f"Metric: Scanning total {count} repos")

    for repo_dict in repos:
        AuditLogger.info(f"> Starting audit of {repo_dict}")
        repo_workflows = repos[repo_dict]
        repo_analysis(repo_workflows)

    AuditLogger.info(f"> Checking for supply chain attacks.")
    action_audit()

main()
