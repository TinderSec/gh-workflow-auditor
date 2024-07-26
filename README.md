<p align="center">
  <img width=50% height=50% src="static/TinderSecurity.png">
</p>

# GitHub Workflow Auditor
Workflow auditing tools to identify security issues in GitHub workflows

# Usage

```
usage: main.py [-h] [--type {repo,org,user}] [--log-level {debug,info,warning,error,critical}] input

Identify vulnerabilities in GitHub Actions workflow

positional arguments:
  input                 User/Org Name or Repo name (owner/repo).

optional arguments:
  -h, --help            show this help message and exit
  --type {repo,org,user}
                        Type of entity that is being scanned.
  --log-level {debug,info,warning,error,critical}
                        Log level for output
```

Example:
* org - `python3 main.py --type org google`
* user - `python3 main.py --type user test_user`
* repo: `python3 main.py --type repo TinderSec/gh-workflow-auditor`

# Setup

GitHub Workflow Auditor uses GitHub's GraphQL endoint. Due to this, an API token is required. The program will read it from the `PAT` environment variable. You can generate a basic PAT token (https://github.com/settings/tokens/new) without any scope. Note that you may have to "Configure SSO" for the token to be usable on some organizations.

```
export PAT=ghp_YOUR_TOKEN
```

# About
GitHub Workflow Auditor identifies vulnerability in GitHub Workflows. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process. The tool supports scanning individual repositories or all accessibe repositories of a user or organization. The output of the scan is saved as `scan.log`.
