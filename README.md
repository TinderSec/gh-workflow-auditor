<p align="center">
  <img width=50% height=50% src="static/TinderSecurity.png">
</p>

# GitHub Workflow Auditor

Workflow auditing tools to identify security issues in GitHub workflows

## Description
GitHub Workflow Auditor identifies vulnerability in GitHub Workflows. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process. The tool supports scanning individual repositories or all accessibe repositories of a user or organization. The output of the scan is saved as `scan.log`.

## Usage

```
usage: ghwfauditor [-h] [--endpoint ENDPOINT] [--log-level {debug,info,warning,error,critical}] [--type {repo,org,user}] input

Identify vulnerabilities in GitHub Actions workflow.

positional arguments:
  input                 Organization, repository or user name.

options:
  -h, --help            show this help message and exit.
  --endpoint ENDPOINT   GitHub endpoint to use.
  --log-level {debug,info,warning,error,critical}
                        Level of debug you wish to display.
  --type {repo,org,user}
                        Type of entity that is being scanned.
```

### Examples

* org - `ghwfauditor --type org google`
* user - `ghwfauditor --type user test_user`
* repo - `ghwfauditor --type repo TinderSec/gh-workflow-auditor`
* enterprise instance - `ghwfauditor --endpoint https://github.tinder.com --type user test_user`

## Setup

> :information_source: We recommend using `pipx` over `pip` for system-wide installations.

```shell
pipx install 'git+https://github.com/TinderSec/gh-workflow-auditor.git'
```

```shell
pip install 'ghwfauditor@git+https://github.com/TinderSec/gh-workflow-auditor.git'
```


GitHub Workflow Auditor uses GitHub's GraphQL endoint. Due to this, an API token is required. The program will read it from the `GITHUB_TOKEN` environment variable. You can [generate a basic Personal Access Token](https://github.com/settings/tokens/new) without any scope. Note that you may have to "Configure SSO" for the token to be usable on some organizations.

```
export GITHUB_TOKEN=ghp_YOUR_TOKEN
```

