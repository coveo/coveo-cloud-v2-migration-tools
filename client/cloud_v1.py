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

    def fields_get(self) -> list:
        return self.do_get(f'rest/workgroups/{self.org_id}/fields')

    def fields_get_for_source(self, source_id):
        fields = self.fields_get()
        return [field for field in fields if field["sourceId"] == source_id]
