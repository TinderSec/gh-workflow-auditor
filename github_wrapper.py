import os
import sys
import requests
from lib.logger import AuditLogger

from query_data import return_query, validation_query

"""
Input:
    token - GitHub PAT. Retrieved from environment variable.

Summary:
    This wrapper uses GitHub's GraphQL API and repository(ies)
    for the provided scan target. In addition, it is also used
    at the end of the workflow for stale account checks.
"""
class GHWrapper():
    def __init__(self):
        self.token = os.environ.get('TOKEN',None)
        self.token = self.token if self.validate_token() else None
        if self.token is None:
            AuditLogger.warning("No valid GitHub API Key was supplied this time.")
            sys.exit()

    def validate_token(self):
        header = {"Authorization":f"token {self.token}"}
        url = "https://api.github.com"
        validation_req = requests.get(url=url, headers=header)
        valid_status = True
        if validation_req.status_code == 401:
            valid_status = False
        else:
            valid_status = True
        return valid_status

    def call_graphql(self, query):
        headers = {'Authorization':f"Bearer {self.token}",
                'Content-Type':'application/json'}
        query_request = requests.post(url='https://api.github.com/graphql',
                                    json = {'query':query},
                                    headers = headers)
        if query_request.status_code == 200:
            return query_request.json()
        else:
            message = query_request.text
            AuditLogger.error(f"GitHub GraphQL Query failed: {message}")
            sys.exit(1)
    
    def repo_node_parser(self,repo_node):
        workflow_object = repo_node['object']
        repo_workflows = []
        if workflow_object:
            workflows = workflow_object['entries']
            for workflow in workflows:
                workflow_name = workflow['name']
                if workflow.get('object',None):
                    workflow_text = workflow['object'].get('text',None)
                workflow_ext = workflow_name.split('.')[-1]
                if workflow_ext == "yml" or workflow_ext == "yaml":
                    repo_workflows.append({'name':workflow_name,'content':workflow_text})
        return repo_workflows
    
    def get_single_repo(self, repo_name):
        repos_all = {}
        repo_query = return_query('repository',
                                repo_name)
        repos = self.call_graphql(repo_query)
        if repos.get('errors') is None:
            repo_node  = repos['data']['repository']
            repo_name = repo_node['nameWithOwner']
            repo_workflows = self.repo_node_parser(repo_node)
            if repo_workflows: # this repo has workflows
                repos_all[repo_name] = repo_workflows
            else:
                AuditLogger.debug(f"Repo {repo_name} has no workflow.")
        return repos_all

    def get_multiple_repos(self,target_name,target_type='org'):
        AuditLogger.info(f"---- Getting repos for {target_name}----")
        repos_all = {}
        query_type = {'org':'organization','user':'user','repo':'repository'}
        try:
            next_cursor = None
            has_more = True # for pagination loop
            count = 0
            while has_more:
                query = return_query(query_type[target_type],
                                target_name, next_cursor)
                repos = self.call_graphql(query)
                if repos.get('errors') is None:
                    for repo in repos['data'][query_type[target_type]]['repositories']['edges']:
                        repo_node = repo['node']
                        repo_name = repo_node['nameWithOwner']
                        repo_workflows = self.repo_node_parser(repo_node)
                        if repo_workflows:
                            repos_all[repo_name] = repo_workflows
                            count += 1
                        else:
                            AuditLogger.debug(f"Repo {repo_name} has no workflow.")
                    has_more = repos['data'][query_type[target_type]]['repositories']['pageInfo']['hasNextPage']
                    next_cursor = repos['data'][query_type[target_type]]['repositories']['pageInfo']['endCursor']
                    if has_more:
                        AuditLogger.info("> Retrieve next batch of 100 repos.")
                else:
                    AuditLogger.error(f"GraphQL response had error.")
                    sys.exit(1)
        except Exception as repo_err:
            AuditLogger.debug(f"Error parsing data. Message: {str(repo_err)}")
        return count, repos_all

    def stale_checker(self,username):
        valid = False
        if username:
            user_query = validation_query(username, 'user')
            is_it_user = self.call_graphql(query=user_query)['data']['user']
            org_query = validation_query(username, 'organization')
            is_it_org = self.call_graphql(query = org_query)['data']['organization']
            if is_it_user or is_it_org:
                valid = True
        return valid
            
            

