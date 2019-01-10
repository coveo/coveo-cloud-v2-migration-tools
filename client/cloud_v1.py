import json
import requests

from client.environment import CloudClient


class CloudV1(CloudClient):
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

    def __init__(self, env, org_id, access_token):
        super().__init__('CloudV1', env, org_id, access_token)
        self.__set_platform_url(env)

    def sources_get(self):
        return self.do_get(f'rest/workgroups/{self.org_id}/sources')

    def dimensions_get(self):
        return self.do_get_direct(f'https://usageanalytics.coveo.com/rest/v14/dimensions/?org={self.org_id}&includeOnlyParents=true')

    def pipelines_get(self):
        return self.do_get(f'rest/search/admin/pipelines/')

    def pipeline_statements_get(self, pipeline_id):
        return self.do_get(f'rest/search/admin/pipelines/{pipeline_id}/statements?perPage=5000')

    def pipeline_statement_details_get(self, pipeline_id, statement_id):
        return self.do_get(f'rest/search/admin/pipelines/{pipeline_id}/statements/{statement_id}?organizationId={self.org_id}')

    def statements_get(self):
        return self.do_get(f'rest/search/admin/pipelines/statements?organizationId={self.org_id}&perPage=5000')

    def schedules_get(self, source_id):
        return self.do_get(f'rest/workgroups/{self.org_id}/sources/{source_id}/schedules')

    def source_get(self, source_id):
        return self.do_get(f'rest/workgroups/{self.org_id}/sources/{source_id}')

    def fields_get(self) -> list:
        return self.do_get(f'rest/workgroups/{self.org_id}/fields')

    def fields_get_for_source(self, source_id):
        fields = self.fields_get()
        return filter(lambda field: field['sourceId'] == source_id, fields)
