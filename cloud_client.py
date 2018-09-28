import json
import requests
import enum


class Environment(enum.Enum):
    DEV = 'dev'
    QA = 'qa'
    PROD = 'prod'

    def __str__(self):
        return self.name

    @staticmethod
    def from_string(s):
        try:
            return Environment[s]
        except KeyError:
            raise ValueError()


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

    def get_sources(self):
        url = self.__get_url(f'rest/workgroups/{self.org_id}/sources')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV1] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def get_fields(self):
        url = self.__get_url(f'rest/workgroups/{self.org_id}/fields')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV1] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def get_fields_for_source(self, sourceId):
        fields = self.get_fields()
        return [field for field in fields if field["sourceId"] == sourceId]


class CloudV2:
    FIELDS_BY_PAGE = 500

    def __set_platform_url(self, env):
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

    def __init__(self, env, org_id, access_token):
        self.__set_platform_url(env)
        self.org_id = org_id
        self.headers = {'Authorization': f'Bearer {access_token}'}

    def __get_url(self, url):
        return f'{self.platform_url}/{url}'

    def get_mappings(self, sourceId):
        url = self.__get_url(f'rest/organizations/{self.org_id}/sources/{sourceId}/mappings')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV2] Error retrieving mappings for org id {self.org_id} and source id {sourceId}')
        return json.loads(response.text)

    def __get_fields_by_page(self, pageNumber):
        url = self.__get_url(f'rest/organizations/fmireaultfree0ak52ztjg/indexes/page/fields?page={pageNumber}&perPage={CloudV2.FIELDS_BY_PAGE}')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV2] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)
    
    def __get_fields_with_mappings_by_page(self, pageNumber):
        url = self.__get_url(f'rest/organizations/{self.org_id}/sources/page/fields?page={pageNumber}&perPage={CloudV2.FIELDS_BY_PAGE}')
        print(f'>> Request to "{url}"')
        response = requests.get(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code != 200:
            raise Exception(f'[CloudV2] Error retrieving fields for org id {self.org_id}')
        return json.loads(response.text)

    def get_fields(self):
        fields_page = self.__get_fields_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__get_fields_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}
    
    def get_fields_with_mappings(self):
        fields_page = self.__get_fields_with_mappings_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__get_fields_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def update_fields(self, fields):
        url = self.__get_url(f'rest/organizations/{self.org_id}/indexes/fields/batch/update')
        payload = fields
        self.headers['Content-Type'] = 'application/json'
        print(f'>> Request to "{url}", data:{json.dumps(payload)}')
        response = requests.put(url, data=json.dumps(payload), headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code not in (200, 204):
            raise Exception(f'[CloudV2] Error updating fields for org id {self.org_id}')


    def delete_fields(self, unusedfields):
        url = self.__get_url(f'rest/organizations/{self.org_id}/indexes/fields/batch/delete?fields={unusedfields}')
        self.headers['Content-Type'] = 'application/json'
        print(f'>> Request to "{url}"')
        response = requests.delete(url, headers=self.headers)
        print(f'>> Response (status: {response.status_code}): {response.text}')
        if response.status_code not in (200, 204):
	        raise Exception(f'[CloudV2] Error deleting fields for org id {self.org_id}')
