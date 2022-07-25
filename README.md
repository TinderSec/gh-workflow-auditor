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

# About
GitHub Workflow Auditor identifies vulnerability in GitHub Workflows. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process. The tool supports scanning individual repositories or all accessibe repositories of a user or organization. The output of the scan is saved as `scan.log`.