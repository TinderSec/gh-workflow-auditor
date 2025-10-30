# Built-in imports
import argparse
import os
import sys
from urllib.parse import urlparse
import tempfile

# External library imports
from loguru import logger

# Local imports
from ghwfauditor.action_auditor import ActionAuditor
from ghwfauditor.workflow import WorkflowAuditor
from ghwfauditor.gh_wrapper import GHWrapper


def repo_analysis(vuln_analyzer, repo_workflows, action_file):
    """Iterate over workflows to log security issues

    For a given workflow dictionary (name, content) this
    function will call content_analyzer to audit the workflow
    for any potential vulnerabilities.

    Arguments:
        vuln_analyzer - WorkflowAuditor object.
        repo_workflow - Dictionary defining repo information.
        action_file - Temporary file where the results are stored.
    Returns:
        scan result (if any) in scan.log file.
    """
    for workflow in repo_workflows:
        workflow_name = workflow["name"]
        workflow_content = workflow["content"]
        logger.info(f"Scanning {workflow_name}")
        vuln_analyzer.content_analyzer(
            content=workflow_content, action_file=action_file
        )  # will print out security issues


def set_log_level(level):
    """Set the log level to display to the user."""
    LOG_FORMAT = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    logger.remove()  # Remove any default handlers
    logger.add(sys.stderr, format=LOG_FORMAT, level=level.upper())
    logger.add(
            "scan.log",
            rotation="10 MB",
            retention="30 days", 
            level=level.upper(),
            format=LOG_FORMAT,
        )
    logger.debug("Logger initialized")


@logger.catch
def run() -> None:
    parser = argparse.ArgumentParser(
        prog="ghwfauditor",
        description="Identify vulnerabilities in GitHub Actions workflow.",
        add_help=True,
    )
    # Helpful to scan instances of GitHub enterprise
    parser.add_argument(
        "--endpoint",
        type=str,
        default="https://api.github.com/",
        help="GitHub endpoint to use.",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Level of debug you wish to display.",
    )
    parser.add_argument(
        "--type",
        choices=["repo", "org", "user"],
        help="Type of entity that is being scanned.",
    )

    parser.add_argument("input", help="Organization, repository or user name.")
    args = parser.parse_args()

    target_type = args.type  # repo, org, or user
    target_endpoint = args.endpoint  # Instance of GitHub to audit
    auth_token = os.environ.get("GITHUB_TOKEN", None)  # Token used to authenticate the audit actions
    target_input = args.input  # can be repo url, or a username for org/user
    log_level = args.log_level

    set_log_level(log_level)

    try:
        parsed_url = urlparse(target_endpoint)
        target_endpoint = f"{parsed_url.scheme}://{parsed_url.netloc}"
    except:
        logger.error("The URL provided isn't correctly formatted")
        sys.exit()

    if auth_token is None:
        logger.error(
            "No GitHub token provided with the GITHUB_TOKEN environment variable. Exiting."
        )
        sys.exit()

    gh = GHWrapper(logger, auth_token, target_endpoint)

    if target_type == "repo":
        repos = gh.get_single_repo(repo_name=target_input)
    else:
        count, repos = gh.get_multiple_repos(
            target_name=target_input, target_type=target_type
        )
        logger.info(f"Scanning {count} repos")

    tmp_action_file = tempfile.NamedTemporaryFile(mode="a+")
    vuln_analyzer = WorkflowAuditor(logger)
    for repo_dict in repos:
        logger.info(f"Starting audit of {repo_dict}")
        repo_workflows = repos[repo_dict]
        repo_analysis(vuln_analyzer, repo_workflows, tmp_action_file)

    logger.info(f"Checking for supply chain attacks.")
    action_auditor = ActionAuditor(logger, gh, tmp_action_file)
    action_auditor.action_audit()
    tmp_action_file.close()
