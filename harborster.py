#!/bin/env python3

# Harbor CVE Harvester
# Prints out all the CVEs for all the artifacts stored in a project from Harbor

import logging
import math
import urllib.parse
import os

import requests
import requests.auth
from rich.live import Live
from rich.table import Table

#  logging.basicConfig(level=logging.DEBUG)


class HarborClient:
    def __init__(self, hostname: str, username: str, password: str, protocol: str = 'https') -> None:
        self.base_endpoint = f'{protocol}://{hostname}'
        self.api_endpoint = f'{self.base_endpoint}/api/v2.0'
        self.username = username
        self.password = password

    def get_project(self, project: str):
        endpoint = f'{self.api_endpoint}/projects/{project}'
        logging.debug(f'getting project {project} from endpoint: {endpoint}')
        response = requests.get(endpoint, auth=requests.auth.HTTPBasicAuth(self.username, self.password))
        logging.debug(response)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f'failed to get details for project {project}')

    def get_project_repositories(self, project_name: str):
        project = self.get_project(project_name)
        logging.debug(project)
        total_pages = math.ceil(project["repo_count"] / 100.0)
        logging.debug(f'total pages to fetch: {total_pages}')
        for page in range(total_pages):
            endpoint = f'{self.api_endpoint}/projects/{project_name}/repositories'
            params = {'page': page, 'page_size': 100}
            logging.debug(f'getting repositories list for project {project_name} from endpoint: {endpoint}')
            response = requests.get(endpoint, auth=requests.auth.HTTPBasicAuth(self.username, self.password), params=params)
            logging.debug(response)
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f'failed to get repositories for project {project}')

    def get_repository_artifacts(self, project_name: str, repository_name: str):
        # For some reason, urlib.quote replaces / with %2f in python but golang uses %252f (double escape)
        # and harbor expects the double escaped format.
        encoded_repository_name = urllib.parse.quote_plus(repository_name).replace("%2F", "%252F")
        endpoint = f'{self.api_endpoint}/projects/{project_name}/repositories/{encoded_repository_name}/artifacts'
        params = {'page_size': 100}
        logging.debug(f'getting list of artifacts for repository {repository_name} from endpoint: {endpoint}')
        response = requests.get(endpoint, auth=requests.auth.HTTPBasicAuth(self.username, self.password), params=params)
        logging.debug(response)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f'failed to get artifacts for repository {repository_name}')

    def get_artifact_vulnerabilities(self, artifact_endpoint: str):
        # encoded_repository_name = {urllib.parse.quote_plus(repository_name).replace("%2F", "%252F")}
        # endpoint = f'{self.api_endpoint}/projects/{project_name}/repositories/{encoded_repository_name}/artifacts/{artifact_digest}/additions/vulnerabilities'
        endpoint = f'{self.base_endpoint}/{artifact_endpoint}'
        params = {'page_size': 100}
        logging.debug(f'getting list of vulnerabilities for artifact from endpoint: {endpoint}')
        response = requests.get(endpoint, auth=requests.auth.HTTPBasicAuth(self.username, self.password), params=params)
        logging.debug(response)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error('failed to get vulnerabilities for artifact')


if __name__ == '__main__':
    table = Table(title="List of CVEs in Project")
    table.add_column("Project")
    table.add_column("Repository")
    table.add_column("Artifact")
    table.add_column("Tags")
    table.add_column("CVEs")

    with Live(table, refresh_per_second=4, vertical_overflow='visible') as live:
        project_name = os.environ.get('HARBOR_PROJECT_NAME', '')
        hc = HarborClient(hostname=os.environ.get('HARBOR_HOSTNAME', ''),
                          username=os.environ.get('HARBOR_USERNAME', ''),
                          password=os.environ.get('HARBOR_PASSWORD', ''),
                          )
        repositories = hc.get_project_repositories(project_name)
        for repository in repositories:
            repository_name = repository["name"].lstrip(project_name + "/")
            artifacts = hc.get_repository_artifacts(project_name, repository_name)
            for artifact in artifacts:
                # live.console.print(f"getting vulnerabilities list for {repository['name']}/{artifact['digest']}")
                vulnerabilities = hc.get_artifact_vulnerabilities(artifact["addition_links"]["vulnerabilities"]["href"])
                logging.debug(vulnerabilities)
                if vulnerabilities.get('application/vnd.security.vulnerability.report; version=1.1'):
                    vulns = vulnerabilities.get('application/vnd.security.vulnerability.report; version=1.1')["vulnerabilities"]
                else:
                    logging.info(f'there are no vulnerabilities information for artifact {artifact}. Skipping.')
                    continue
                tags_list = []
                if artifact.get("tags"):
                    for tag in artifact.get("tags"):
                        if tag.get("name"):
                            tags_list.append(tag.get("name"))
                table.add_row(project_name,
                              repository_name,
                              f'{artifact["digest"]}',
                              ", ".join(tags_list),
                              ", ".join([v["id"] for v in vulns if vulns is not None]),
                              )
