from client.environment import Environment
import json
import requests


class CloudV2:
    """
    Client for CloudV2
    """
    FIELDS_BY_PAGE = 500

    def __set_platform_url(self, env: Environment):
        if env == env.DEV:
            url = 'platformdev.cloud.coveo.com'
        elif env == env.QA:
            url = 'platformqa.cloud.coveo.com'
        elif env == env.PROD:
            url = 'platform.cloud.coveo.com'
        else:
            raise ValueError(f'Unsupported environment: {env}')
        self.platform_url = f'https://{url}'
        print(f'[CloudV2] Using environement {env}')

    def __init__(self, env: Environment, org_id: str, access_token: str):
        self.__set_platform_url(env)
        self.org_id = org_id
        self.headers = {'Authorization': f'Bearer {access_token}'}

    def __get_url(self, url: str):
        return f'{self.platform_url}/{url}'

    def __do_get(self, url):
        url = self.__get_url(url)
        print(f'>> Get request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Get response (status: {response.status_code}): {response.text}')
        if not response.ok:
            raise Exception(f'Error accessing {url}: {response.reason}')
        return json.loads(response.text)

    def __do_post(self, url, data):
        url = self.__get_url(url)
        self.headers['Content-Type'] = 'application/json'
        print(f'>> Post request to "{url}", data:{json.dumps(data)}')
        response = requests.post(url, data=json.dumps(data), headers=self.headers)
        print(f'>> Post response (status: {response.status_code}): {response.text}')
        if not response.ok:
            raise Exception(f'Error accessing {url}: {response.reason}')
        return json.loads(response.text)

    def mappings_get(self, source_id: str):
        url = self.__get_url(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV2] Error retrieving mappings for org id {self.org_id} and source id {source_id}')
        return json.loads(response.text)

    def mappings_common_add(self, source_id: str, rebuild: bool, mapping: dict):
        return self.__do_post(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings/common/rules?rebuild={rebuild}', mapping)

    def __fields_get_by_page(self, page_number: int):
        url = self.__get_url(f'rest/organizations/fmireaultfree0ak52ztjg/indexes/page/fields?page={page_number}&perPage={CloudV2.FIELDS_BY_PAGE}')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV2] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def fields_get(self):
        fields_page = self.__fields_get_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__fields_get_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def fields_update(self, fields: dict):
        url = self.__get_url(f'rest/organizations/{self.org_id}/indexes/fields/batch/update')
        self.headers['Content-Type'] = 'application/json'
        print(f'>> Request to "{url}", data:{json.dumps(fields)}')
        response = requests.put(url, data=json.dumps(fields), headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code not in (200, 204):
            raise Exception(f'[CloudV2] Error updating fields for org id {self.org_id}')

    def fields_create_batch(self, fields: list):
        url = self.__get_url(f'rest/organizations/{self.org_id}/indexes/fields/batch/create')
        self.headers['Content-Type'] = 'application/json'
        print(f'>> Request to "{url}", data:{json.dumps(fields)}')
        response = requests.post(url, data=json.dumps(fields), headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code not in (200, 204):
            raise Exception(f'[CloudV2] Error creating fields: {response.text}')

    def sources_get(self):
        return self.__do_get(f'rest/organizations/{self.org_id}/sources')