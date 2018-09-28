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
        self.headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    def __get_url(self, url: str):
        return f'{self.platform_url}/{url}'

    def __do_request(self, method: str, url: str, data):
        url = self.__get_url(url)
        print(f'>> {method} request to "{url}"')
        # response = requests.get(url, headers=self.headers)
        response = requests.request(method, url, headers=self.headers, data=json.dumps(data))
        print(f'>> {method} response (status: {response.status_code}): {response.text}')
        if not response.ok:
            raise Exception(f'Error accessing {url}: {response.reason}')
        if response.text:
            return json.loads(response.text)

    def __do_get(self, url):
        return self.__do_request('get', url, None)

    def __do_post(self, url, data):
        return self.__do_request('post', url, data)

    def __do_put(self, url, data):
        return self.__do_request('put', url, data)

    def __do_delete(self, url):
        return self.__do_request('delete', url, None)

    def mappings_get(self, source_id: str):
        return self.__do_get(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings')

    def mappings_common_add(self, source_id: str, rebuild: bool, mapping: dict):
        return self.__do_post(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings/common/rules?rebuild={rebuild}', mapping)

    def __fields_get_by_page(self, page_number: int):
        return self.__do_get(f'rest/organizations/{self.org_id}/indexes/page/fields?page={page_number}&perPage={CloudV2.FIELDS_BY_PAGE}')

    def fields_get(self):
        fields_page = self.__fields_get_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__fields_get_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def __get_fields_with_mappings_by_page(self, page_number):
        return self.__do_get(f'rest/organizations/{self.org_id}/sources/page/fields?page={page_number}&perPage={CloudV2.FIELDS_BY_PAGE}')

    def fields_get_with_mappings(self):
        fields_page = self.__get_fields_with_mappings_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__get_fields_with_mappings_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def fields_update(self, fields: dict):
        return self.__do_put(f'rest/organizations/{self.org_id}/indexes/fields/batch/update', fields)

    def fields_create_batch(self, fields: list):
        return self.__do_post(f'rest/organizations/{self.org_id}/indexes/fields/batch/create', fields)

    def fields_delete(self, unused_fields):
        url = self.__do_delete(f'rest/organizations/{self.org_id}/indexes/fields/batch/delete?fields={unused_fields}')

    def sources_get(self):
        return self.__do_get(f'rest/organizations/{self.org_id}/sources')
