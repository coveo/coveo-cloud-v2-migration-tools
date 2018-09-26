#! /usr/bin/python3
from client.fields import Fields
from client.cloud_v2 import *
from cloud_client import *


class Auth:
    def __init__(self, org_id: str, auth_token: str, env: Environment):
        self.org_id = org_id
        self.auth_token = auth_token
        self.env = env


def copy_user_fields(v1_auth: Auth, v2_auth: Auth):
    def is_user_field(field: dict) -> bool:
        """
        >>> field = {'contentType': 'SYSTEM'}
        >>> is_user_field(field)
        false
        >>> field = {'fieldOrigin': 'CUSTOM'}
        >>> is_user_field(field)
        true
        """
        return field['fieldOrigin'] == 'CUSTOM'
    v1_client = CloudV1(v1_auth.env, v1_auth.org_id, v1_auth.auth_token)
    v1_user_fields = [field for field in v1_client.get_fields() if is_user_field(field)]
    v2_client = CloudV2(v2_auth.env, v2_auth.org_id, v2_auth.auth_token)
    v2_client.fields_create_batch([Fields.v1_to_v2(field) for field in v1_user_fields])


if __name__ == '__main__':
    import doctest
    if doctest.testmod().failed > 0:
        exit(-1)

    env = Environment.DEV
    v1_auth = Auth('coveodev', '6a5c8801-8996-4086-91cb-92b9141d0378', env)
    v2_auth = Auth('fmireaultfree0ak52ztjg', 'xd8b93dc6-21c6-46d1-9ebc-b2663c598e9a', env)
    copy_user_fields(v1_auth, v2_auth)