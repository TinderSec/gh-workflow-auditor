def return_query(query_type,name,after=None):
    if query_type == 'repository':
        owner,name = name.split('/')
        return f"""query {{
                    repository(owner: "{owner}",name: "{name}") {{
                        nameWithOwner
                        object(expression: "HEAD:.github/workflows/") {{
                            ... on Tree {{
                                entries {{
                                    name
                                    lineCount
                                    object {{
                                        ... on Blob {{
                                            text
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }}
        }}"""
    else:
        after_query = f",after:\"{after}\"" if after else ""
        return f"""query {{
        {query_type}(login:"{name}"){{
            repositories(first:100 {after_query}){{
            edges{{
                node{{
                nameWithOwner,
                object(expression: "HEAD:.github/workflows/") {{
                    ... on Tree {{
                    entries {{
                        name
                        lineCount
                        object {{
                                ... on Blob {{
                            text
                        }}
                        }}
                    }}
                    }}
                }}
                }}
            }}
            pageInfo {{
                startCursor
                hasNextPage
                endCursor
            }}
            }}
        }}
        }}"""

def validation_query(username, guess_type):
    return f"""query {{ 
                {guess_type}(login:"{username}"){{
                    repositories(first:1){{
                        edges{{
                            node{{
                                nameWithOwner
                            }}
                        }}
                    }}
                }}
            }}"""