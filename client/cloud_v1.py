import json
import requests


class CloudV1:
    def __set_platform_url(self, env):
        if env == env.DEV:
            url = 'cloudplatformdev.coveo.com'
        elif env == env.QA:
            url = 'cloudplatformstaging.coveo.com'
        elif env == env.PROD:
            url = 'cloudplatform.coveo.com'
        else:
            raise ValueError(f'Unsupported environment: {env}')
        self.platform_url = f'https://{url}'
        print(f'[CloudV1] Using environement {env}')

    def __get_url(self, url):
        return f'{self.platform_url}/{url}'

    def __init__(self, env, org_id, access_token):
        self.__set_platform_url(env)
        self.org_id = org_id
        self.headers = {'Authorization': f'Bearer {access_token}'}

    def sources_get(self):
        url = self.__get_url(f'rest/workgroups/{self.org_id}/sources')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV1] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def fields_get(self) -> list:
        url = self.__get_url(f'rest/workgroups/{self.org_id}/fields')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV1] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def fields_get_for_source(self, sourceId):
        fields = self.fields_get()
        return [field for field in fields if field["sourceId"] == sourceId]
