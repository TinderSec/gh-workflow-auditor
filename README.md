# SAST for Github Workflows

This tool identifies vulnerability in GitHub Workflows. It does so by scanning the workflow files for anti-patterns such as ingesting user inputs in an unsafe manner or using malicious commits in build process.

## Usage

Example

## Future plans

* Check for [GitHub Action evaluates curl's output](https://docs.boostsecurity.io/rules/cicd-gha-curl-eval.html)
* Check for [workflow inputs](https://docs.boostsecurity.io/rules/cicd-gha-workflow-dispatch-inputs.html)
* Check for [write-all](https://docs.boostsecurity.io/rules/cicd-gha-write-all-permissions.html)
* Add scan for intentional deprecated commands [ACTIONS_ALLOW_UNSECURE_COMMANDS](https://docs.boostsecurity.io/rules/cicd-gha-unsecure-commands.html) and `save-state` and `set-outout`?

## Notice

This was originally forked from [this repo](https://github.com/magmanu/gh-workflow-auditor) and converted to a GitHub Action, which means changes were made to the original code. I'm in good faith reproducing the original copyright and making explicit that code changes were made, which I believe is enough to fullfill the original copyright requirements.  
