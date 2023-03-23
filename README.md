<p align="center">
  <img width=50% height=50% src="static/TinderSecurity.png">
</p>

# GitHub Workflow Auditor
Workflow auditing tools to identify security issues in GitHub workflows

# Usage

```
usage: main.py [-h] [--type {repo,org,user}] input

Identify vulnerabilities in GitHub Actions workflow

positional arguments:
  input                 User/Org Name or Repo name (owner/repo).

optional arguments:
  -h, --help            show this help message and exit
  --type {repo,org,user}
                        Type of entity that is being scanned.
```

Example: 
* org - `python3 main.py --type org google`
* user - `python3 main.py --type user test_user`
* repo: `python3 main.py --type repo TinderSec/gh-workflow-auditor`

# Setup

GitHub Workflow Auditor uses GitHub's GraphQL endoint. Due to this, an API token is required. You can generate a basic PAT token with no read access for this.

```
export PAT=ghp_YOUR_TOKEN
```

# Enhancements
- Output as JSON, so I can programatically do something with it
- Output as CSV, so it's user friendly to security managers
- List actions that must be reviewed and aknowleged due to use of secrets != GITHUB_TOKEN
- Improve RCA message
- [Convert to action](https://shipyard.build/blog/your-first-python-github-action/) that will block merge if issues are found
- Add scan for intentional deprecated commands [ACTIONS_ALLOW_UNSECURE_COMMANDS](https://docs.boostsecurity.io/rules/cicd-gha-unsecure-commands.html)
- Check for [GitHub Action evaluates curl's output](https://docs.boostsecurity.io/rules/cicd-gha-curl-eval.html)
- Check for [workflow inputs](https://docs.boostsecurity.io/rules/cicd-gha-workflow-dispatch-inputs.html)
- Check for [write-all](https://docs.boostsecurity.io/rules/cicd-gha-write-all-permissions.html)


# About
GitHub Workflow Auditor identifies vulnerability in GitHub Workflows. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process. The tool supports scanning individual repositories or all accessibe repositories of a user or organization. The output of the scan is saved as `scan.log`.