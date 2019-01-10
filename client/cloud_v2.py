from client.environment import Environment, CloudClient
import json
import requests


class CloudV2(CloudClient):
    """
    Client for CloudV2
    """
    FIELDS_BY_PAGE = 500

    def __init__(self, env: Environment, org_id: str, access_token: str):
        super().__init__('CloudV2', env, org_id, access_token)
        self.__set_platform_url(env)

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

    def mappings_get(self, source_id: str):
        return self.do_get(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings')

    def mappings_common_add(self, source_id: str, rebuild: bool, mapping: dict):
        return self.do_post(f'rest/organizations/{self.org_id}/sources/{source_id}/mappings/common/rules?rebuild={rebuild}', mapping)

    def __fields_get_by_page(self, page_number: int):
        return self.do_get(f'rest/organizations/{self.org_id}/indexes/page/fields?page={page_number}&perPage={CloudV2.FIELDS_BY_PAGE}')

    def fields_get(self):
        fields_page = self.__fields_get_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__fields_get_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def __get_fields_with_mappings_by_page(self, page_number):
        return self.do_get(f'rest/organizations/{self.org_id}/sources/page/fields?page={page_number}&perPage={CloudV2.FIELDS_BY_PAGE}')

    def fields_get_with_mappings(self):
        fields_page = self.__get_fields_with_mappings_by_page(0)
        pages_count = fields_page['totalPages']
        fields = fields_page['items']
        for page_index in range(1, pages_count):
            fields_page = self.__get_fields_with_mappings_by_page(page_index)
            fields.extend(fields_page['items'])
        return {'items': fields , 'totalPages': pages_count, 'totalEntries': len(fields)}

    def fields_update(self, fields: dict):
        return self.do_put(f'rest/organizations/{self.org_id}/indexes/fields/batch/update', fields)

    def fields_create_batch(self, fields: list):
        print (json.dumps(fields))
        return self.do_post(f'rest/organizations/{self.org_id}/indexes/fields/batch/create', fields)

    def fields_delete(self, unused_fields):
        url = self.do_delete(f'rest/organizations/{self.org_id}/indexes/fields/batch/delete?fields={unused_fields}')

    def sources_get(self):
        return self.do_get(f'rest/organizations/{self.org_id}/sources')

    def sources_delete(self, mid:str):
      url = f'rest/organizations/{self.org_id}/sources/{mid}'
      #print(url)
      return self.do_delete(url)

    def source_create(self, config):
      if config['MethodToUse']=='RAW':
        return self.do_post(f'rest/organizations/{self.org_id}/sources/raw?rebuild=false&updateSecurityProviders=false',config)
      else:
        return self.do_post(f'rest/organizations/{self.org_id}/sources?rebuild=false&updateSecurityProviders=false',config)

    def schedule_create(self, source_id, fields: dict):
        return self.do_post(f'rest/organizations/{self.org_id}/sources/{source_id}/schedules', fields)

    def schedule_get(self, source_id):
        return self.do_get(f'rest/organizations/{self.org_id}/sources/{source_id}/schedules')

    def schedule_delete(self, source_id, schedule_id):
        return self.do_delete(f'rest/organizations/{self.org_id}/sources/{source_id}/schedules/{schedule_id}')

    def dimension_create(self, name, event, fields: dict):
      #https://platform.cloud.coveo.com/rest/ua/v15/dimensions/custom?org=asdf&name=myname&event=searches&updatePastEvents=false
        return self.do_post(f'rest/ua/v15/dimensions/custom?org={self.org_id}&name={name}{event}', fields)

    def pipeline_create(self, fields: dict):
        return self.do_post(f'rest/search/v1/admin/pipelines/?organizationId={self.org_id}', fields)

    def pipelines_get(self):
        return self.do_get(f'rest/search/admin/pipelines/?organizationId={self.org_id}')

    def pipeline_delete(self, pipeline_id):
        return self.do_delete(f'rest/search/v1/admin/pipelines/{pipeline_id}?organizationId={self.org_id}')

    def pipeline_statements_get(self, pipeline_id):
        return self.do_get(f'rest/search/admin/pipelines/{pipeline_id}/statements?perPage=5000')

    def pipeline_statement_create(self, pipeline_id, fields: dict):
        return self.do_post(f'rest/search/v1/admin/pipelines/{pipeline_id}/statements?organizationId={self.org_id}', fields)

    def pipeline_statement_delete(self, pipeline_id, statement_id):
        return self.do_delete(f'rest/search/v1/admin/pipelines/{pipeline_id}/statements/{statement_id}?organizationId={self.org_id}')

    def statement_create(self, fields: dict):
        return self.do_post(f'rest/search/v1/admin/pipelines/statements?organizationId={self.org_id}', fields)

    def statements_get(self):
        return self.do_get(f'rest/search/admin/pipelines/statements?organizationId={self.org_id}&perPage=5000')

    def statement_delete(self, statement_id):
        return self.do_delete(f'rest/search/v1/admin/pipelines/statements/{statement_id}?organizationId={self.org_id}')
