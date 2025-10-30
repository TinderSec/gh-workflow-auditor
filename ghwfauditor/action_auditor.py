# Built-in imports
import re
from pathlib import Path


class ActionAuditor:
    """Class used to audit GitHub actions

    Attributes:
        logger: Configured logger.
        gh_wrapper (GHWrapper): Object handling the connection to the GitHub API.
        action_file: Temporary file used to store potentially vulnerable results.

    """

    def __init__(self, logger, gh_wrapper, action_file):
        """ActionAuditor constructor

        Arguments:
            logger: Configured logger.
            gh_wrapper (GHWrapper): Object handling the connection to the GitHub API.
            action_file: Temporary file used to store actions.

        """
        self.logger = logger
        self.gh = gh_wrapper
        self.action_file = action_file

    def check_usernames(self, username_list):
        for username in username_list:
            renamed_or_not = self.gh.stale_checker(username=username)
            if not renamed_or_not:
                self.logger.success(
                    f"Security Issue: Supply chain. {username} was renamed but used in workflows. Signup the username to make sure."
                )

    def action_audit(self):
        """Check that action file still exists and audit content"""
        if Path(self.action_file.name).exists():
            usernames = self.read_actions_file()
            self.check_usernames(usernames)
        else:
            self.logger.error(
                "The temporary file has been deleted by an external program"
            )

    def read_actions_file(self):
        """Read action file and return a list of username"""
        array_of_usernames = []
        self.action_file.seek(0)
        lines = self.action_file.readlines()
        for line in lines:
            username = line.split("/")[0]
            username_regex = re.compile("[A-Za-z0-9-]*")
            if username_regex.fullmatch(username):
                if username not in array_of_usernames:
                    array_of_usernames.append(username)
        return array_of_usernames
