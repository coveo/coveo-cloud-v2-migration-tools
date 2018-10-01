import enum
import json

import requests


class Environment(enum.Enum):
    DEV = 'dev'
    QA = 'qa'
    PROD = 'prod'

    def __str__(self):
        return self.name

    @staticmethod
    def from_string(s: str):
        try:
            return Environment[s]
        except KeyError:
            raise ValueError()


class CloudClient:
    def __init__(self, name, env, org_id, access_token):
        self.env = env
        self.name = name
        self.org_id = org_id
        self.headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        self.platform_url = ''

    def __get_url(self, url):
        return f'{self.platform_url}/{url}'

    def __do_request(self, method: str, url: str, data):
        url = self.__get_url(url)
        print(f'>> {method} request to "{url}"')
        response = requests.request(method, url, headers=self.headers, data=json.dumps(data))
        print(f'>> {method} response (status: {response.status_code}): {response.text}')
        if not response.ok:
            raise Exception(f'Error accessing {url}: {response.reason}')
        if response.text:
            return json.loads(response.text)

    def do_get(self, url):
        return self.__do_request('get', url, None)

    def do_post(self, url, data):
        return self.__do_request('post', url, data)

    def do_put(self, url, data):
        return self.__do_request('put', url, data)

    def do_delete(self, url):
        return self.__do_request('delete', url, None)

