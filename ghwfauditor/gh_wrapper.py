# Built-in imports
import sys

# External library imports
import httpx

# Local imports
from ghwfauditor.query_data import return_query, validation_query


class GHWrapper:
    """GitHub wrapper that expose the GraphQL API

    This wrapper uses GitHub's GraphQL API and repository(ies)
    for the provided scan target. In addition, it is also used
    at the end of the workflow for stale account checks.

    Attributes:
        logger: Configured logger.
        token: GitHub Personal Access Token.
        api_endpoint: Endpoint used to validate the GitHub credentials.
        graphql_endpoint: Endpoint used to retrieve information about the workflows.

    """

    def __init__(self, logger, token, api_url):
        """GHWrapper constructor

        Arguments:
            logger: Configured logger.
            gh_wrapper (GHWrapper): Object handling the connection to the GitHub API.
            action_file: Temporary file used to store potentially vulnerable results.

        """
        self.token = token
        self.logger = logger
        if api_url != "https://api.github.com":
            self.logger.debug("Custom GitHub instance used")
            self.api_endpoint = api_url + "/api/v3"
            self.graphql_endpoint = api_url + "/api/graphql"
        else:
            self.api_endpoint = api_url
            self.graphql_endpoint = api_url + "/graphql"
        if self.validate_token():
            self.logger.debug("GitHub token is valid")
        else:
            self.logger.warning("GitHub token provided is invalid. Exiting.")
            sys.exit()

    def validate_token(self):
        header = {"Authorization": f"token {self.token}"}
        url = self.api_endpoint
        try:
            validation_req = httpx.get(url=url, headers=header)
        except:
            self.logger.error(f"Connection issue with the GitHub instance")
            sys.exit()
        # Can be 403 if the account is suspended, 401 if the credentials are incorrect
        self.logger.debug(f"{url} reponse status code is {validation_req.status_code}")
        return validation_req.status_code == 200

    def call_graphql(self, query):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        query_request = httpx.post(
            url=self.graphql_endpoint,
            json={"query": query},
            headers=headers,
        )
        if query_request.status_code == 200:
            return query_request.json()
        else:
            message = query_request.text
            self.logger.error(f"GitHub GraphQL Query failed: {message}")
            sys.exit(1)

    def repo_node_parser(self, repo_node):
        workflow_object = repo_node["object"]
        repo_workflows = []
        if workflow_object:
            workflows = workflow_object["entries"]
            for workflow in workflows:
                workflow_name = workflow["name"]
                if workflow.get("object", None):
                    workflow_text = workflow["object"].get("text", None)
                workflow_ext = workflow_name.split(".")[-1]
                if workflow_ext == "yml" or workflow_ext == "yaml":
                    repo_workflows.append(
                        {"name": workflow_name, "content": workflow_text}
                    )
        return repo_workflows

    def get_single_repo(self, repo_name):
        repos_all = {}
        repo_query = return_query("repository", repo_name)
        repos = self.call_graphql(repo_query)
        if repos.get("errors") is None:
            repo_node = repos["data"]["repository"]
            repo_name = repo_node["nameWithOwner"]
            repo_workflows = self.repo_node_parser(repo_node)
            if repo_workflows:  # this repo has workflows
                repos_all[repo_name] = repo_workflows
            else:
                self.logger.debug(f"Repo {repo_name} has no workflow.")
        return repos_all

    def get_multiple_repos(self, target_name, target_type="org"):
        self.logger.info(f"---- Getting repos for {target_name}----")
        repos_all = {}
        query_type = {"org": "organization", "user": "user", "repo": "repository"}
        try:
            next_cursor = None
            has_more = True  # for pagination loop
            count = 0
            while has_more:
                query = return_query(query_type[target_type], target_name, next_cursor)
                repos = self.call_graphql(query)
                if repos.get("errors") is None:
                    for repo in repos["data"][query_type[target_type]]["repositories"][
                        "edges"
                    ]:
                        repo_node = repo["node"]
                        repo_name = repo_node["nameWithOwner"]
                        repo_workflows = self.repo_node_parser(repo_node)
                        if repo_workflows:
                            repos_all[repo_name] = repo_workflows
                            count += 1
                        else:
                            self.logger.debug(f"Repo {repo_name} has no workflow.")
                    has_more = repos["data"][query_type[target_type]]["repositories"][
                        "pageInfo"
                    ]["hasNextPage"]
                    next_cursor = repos["data"][query_type[target_type]][
                        "repositories"
                    ]["pageInfo"]["endCursor"]
                    if has_more:
                        self.logger.info("Retrieving next batch of 25 repos.")
                else:
                    self.logger.error(f"GraphQL response had error.")
                    sys.exit(1)
        except Exception as repo_err:
            self.logger.error(f"Error parsing data. Message: {str(repo_err)}")
        return count, repos_all

    def stale_checker(self, username):
        valid = False
        if username:
            user_query = validation_query(username, "user")
            is_it_user = self.call_graphql(query=user_query)["data"]["user"]
            org_query = validation_query(username, "organization")
            is_it_org = self.call_graphql(query=org_query)["data"]["organization"]
            if is_it_user or is_it_org:
                valid = True
        return valid
