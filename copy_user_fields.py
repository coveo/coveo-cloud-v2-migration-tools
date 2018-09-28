#! /usr/bin/python3
import itertools

from client.cloud_v2 import *
from client.cloud_v1 import *
from client.fields import Fields


class Auth:
    def __init__(self, org_id: str, auth_token: str, env: Environment):
        self.org_id = org_id
        self.auth_token = auth_token
        self.env = env


def copy_user_fields(v1_auth: Auth, v2_auth: Auth):
    def v1_get_fields_by_name(v1_fields: list) -> dict:
        v1_fields_by_name = [(field['name'], field) for field in v1_fields]
        # deduplicate
        return dict([(field[0],
                      [f[1] for f in v1_fields_by_name if f[0] == field[0]])
                     for field in v1_fields_by_name])

    def is_user_field(field: dict) -> bool:
        return field['fieldOrigin'] == 'CUSTOM'

    def v1_get_valid_fields(fields: list) -> dict:
        def v1_field_validate_same_config(fields: list) -> bool:
            previous = fields[0]
            for i in range(1, len(fields)):
                current = fields[i]
                if not (previous['fieldType'] == fields[i]['fieldType'] and
                        previous['contentType'] == fields[i]['contentType'] and
                        previous['fieldQueries'] == fields[i]['fieldQueries'] and
                        previous['freeTextQueries'] == fields[i]['freeTextQueries'] and
                        previous['facet'] == fields[i]['facet'] and
                        previous['multivalueFacet'] == fields[i]['multivalueFacet'] and
                        previous['sort'] == fields[i]['sort'] and
                        previous['displayField'] == fields[i]['displayField']):
                    print(f'SKIPPING FIELD {current["name"]}. Found fields in CloudV1 with the same name but different configurations: {fields}')
                    return False
                previous = fields[i]
            return True

        fields_by_name = v1_get_fields_by_name(fields)
        valid_fields_by_name = \
            [t for t in
                [(field, fields_by_name[field])
                if v1_field_validate_same_config(fields_by_name[field]) else None
                for field in fields_by_name]
            if t is not None]
        return valid_fields_by_name

    v1_client = CloudV1(v1_auth.env, v1_auth.org_id, v1_auth.auth_token)
    v1_fields = [field for field in v1_client.fields_get() if is_user_field(field)]
    v1_valid_fields = v1_get_valid_fields(v1_fields)
    v2_client = CloudV2(v2_auth.env, v2_auth.org_id, v2_auth.auth_token)
    v2_fields_to_create = [Fields.v1_to_v2(field[1][0]) for field in v1_valid_fields]
    # v2_client.fields_create_batch(v2_fields_to_create)

    v1_fields_mapping = list(itertools.chain.from_iterable([field_list[1] for field_list in v1_valid_fields]))
    create_v2_mapping_from_v1_fields(v2_client, v1_client.sources_get(), v1_fields_mapping, v2_client.sources_get())


def create_v2_mapping_from_v1_fields(v2_client: CloudV2, v1_sources: object, v1_fields: list, v2_sources: list):
    # find common sources between v1 and v2
    v1_sources_by_id = dict([(source['id'].lower(), source) for source in v1_sources['sources']])
    v1_sources_by_name = dict([(source['name'].lower(), source) for source in v1_sources['sources']])
    v2_sources_by_name = dict([(source['name'].lower(), source) for source in v2_sources])

    common_sources = dict([(v2_source_key,
                       {'v1_id': v1_sources_by_name[v2_source_key]['id'],
                        'v2_id': v2_sources_by_name[v2_source_key]['id']})
                      for v2_source_key in v2_sources_by_name.keys()
                      if v2_source_key in v1_sources_by_name])
    print(f'Common source names ({len(common_sources)}): {json.dumps(common_sources)}')

    for field in v1_fields:
        # v1 source id -> v1 source name -> v2 source name
        v1_source_id = field['sourceId']
        v1_source_name = v1_sources_by_id[v1_source_id]['name'].lower()
        if v1_source_name in common_sources:
            v2_source_id = common_sources[v1_source_name]['v2_id']
            mapping_to_add = {'content': [f'%[{field["metadataName"]}]'], 'field': f'{field["name"]}'}
            v2_client.mappings_common_add(v2_source_id, False, mapping_to_add)
        else:
            print(f'SKIPPING MAPPING \'{field}\' because source \'{v1_source_name}\' does not exist in CloudV2')


if __name__ == '__main__':
    import doctest
    if doctest.testmod().failed > 0:
        exit(-1)

    env = Environment.DEV
    v1_auth = Auth('coveodev', '62e2cdec-b949-44d6-a642-f57273d6454f', env)
    v2_auth = Auth('fmireaultfree0ak52ztjg', 'x5547a972-2088-45bf-b5c7-ce5966da3f87', env)
    copy_user_fields(v1_auth, v2_auth)