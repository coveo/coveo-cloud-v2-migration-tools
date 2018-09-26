#! /usr/bin/python3
"""
Migrate field configuration from CloudV1 to CloudV2.
To be used on a CloudV2 source having the same schema version as CloudV1.

TODO: Move filtering of type date and sort=false sooner in the process
"""

from cloud_client import *
import argparse

# v1 -> v2
FIELDS_KEYS_V1_V2 = {'fieldQueries': 'includeInQuery',
                     'freeTextQueries': 'mergeWithLexicon',
                     'facet': 'facet',
                     'multivalueFacet': 'multiValueFacet',
                     'sort': 'sort',
                     'displayField': 'includeInResults'}

KEY_V1_CONFIGNAME = 'v1ConfigName'
KEY_V2_CONFIGNAME = 'v2ConfigName'
KEY_V1_FIELD = 'v1Field'
KEY_V2_FIELD = 'v2Field'
KEY_V1_VALUE = 'v1Value'
KEY_V2_VALUE = 'v2Value'
KEY_CONFIG_DIFF = 'configDiff'


def v1_get_source_id(sources, source_name):
    """ Get a source id from a source name (CloudV1)
    >>> v1_get_source_id([{'id': '0', 'name': 'FOO'}, {'id': '1', 'name': 'BAR'}], 'bar')
    '1'
    >>> v1_get_source_id([{'id': '0', 'name': 'FOO'}, {'id': '1', 'name': 'BAR'}], 'new')
    Traceback (most recent call last):
        ...
    ValueError: Source new does not exist
    >>> v1_get_source_id([{'id': '0', 'name': 'FOO'}, {'id': '1', 'name': 'FOO'}], 'foo')
    Traceback (most recent call last):
        ...
    ValueError: More than one source foo found. This should not happen.
    """
    source_ids = [source['id'] for source in sources
                  if source['name'].lower() == source_name.lower()]
    if not source_ids:
        raise ValueError(f'Source {source_name} does not exist')
    if len(source_ids) > 1:
        raise ValueError(f'More than one source {source_name} found. This should not happen.')
    return source_ids[0]

def v1_get_fields_by_name(fields):
    """ Get a dictionary of fields by name (field name -> field) (CloudV1)
     >>> v1_get_fields_by_name(( \
        {'id': '0', 'name': 'FOO'}, \
        {'id': '1', 'name': 'bAr'}, \
        {'id': '2', 'name': 'foobar'}))
     {'foo': {'id': '0', 'name': 'FOO'}, 'bar': {'id': '1', 'name': 'bAr'}, 'foobar': {'id': '2', 'name': 'foobar'}}
    """
    return dict([(f['name'].lower(), f) for f in fields])


def v2_get_fields_in_use(fields, mappings):
    """ Get a dictionary of fields that are used in the mappings provided (field name -> field) (CloudV2)
    >>> v2_get_fields_in_use(({'items': ({'name': 'FOO'}, {'name': 'bar'}, {'name': 'foobar'})}), ('foo', 'BAR'))
    {'foo': {'name': 'FOO'}, 'bar': {'name': 'bar'}}
    """
    return dict((field['name'].lower(), field) for field in
                fields['items'] if field['name'].lower() in
                [mapping.lower() for mapping in mappings])


def v2_get_mappings_fieldname(mappings):
    """ Get a dictionary of mappings (field name -> field) (CloudV2)
    >>> v2_get_mappings_fieldname({'common': {'rules': []}})
    []
    >>> v2_get_mappings_fieldname({'common': {'rules': [{'field': 'FOO'}, {'field': 'bAr'}]}})
    ['foo', 'bar']
    >>> v2_get_mappings_fieldname({'types': []})
    []
    >>> v2_get_mappings_fieldname({'types': [{'rules': []}]})
    []
    >>> v2_get_mappings_fieldname({'types': [ \
        {'rules': [{'field': 'foo0'}, {'field': 'fOO1'}]}, \
        {'rules': [{'field': 'bar0'}]}]})
    ['foo0', 'foo1', 'bar0']
    >>> v2_get_mappings_fieldname({'common': {'rules': [{'field': 'FOO'}, {'field': 'bAr'}]}, \
                                  'types': [ \
                                      {'rules': [{'field': 'foo0'}, {'field': 'fOO1'}]}, \
                                      {'rules': [{'field': 'bar0'}]}]})
    ['foo', 'bar', 'foo0', 'foo1', 'bar0']
    """
    # get common mappings
    common_mappings = mappings['common']['rules'] if 'common' in mappings and 'rules' in mappings['common'] else []
    # get type specifc mappings
    type_mappings = list()
    type_rules = [rule['rules'] if 'rules' in rule else [] for rule in mappings['types']] if 'types' in mappings else []
    [[type_mappings.append(field) for field in type_rule] for type_rule in type_rules]
    # all v2 mappings
    v2_all_mappings = common_mappings + type_mappings
    return [mapping['field'].lower() for mapping in v2_all_mappings]


def get_fields_difference(v1_field, v2_field):
    """ Get the differences between 2 fields
    >>> get_fields_difference({}, {})
    []
    >>> v1_field = {'sort': True}
    >>> v2_field = {'sort': True}
    >>> get_fields_difference(v1_field, v2_field)
    []
    >>> v1_field = {'fieldQueries': True}
    >>> v2_field = {'includeInQuery': False}
    >>> get_fields_difference(v1_field, v2_field)
    [{'v1ConfigName': 'fieldQueries', 'v2ConfigName': 'includeInQuery', 'v1Value': True, 'v2Value': False}]
    >>> v1_field = {'fieldQueries': True, 'sort': False}
    >>> v2_field = {'includeInQuery': False, 'sort': True}
    >>> get_fields_difference(v1_field, v2_field)
    [{'v1ConfigName': 'fieldQueries', 'v2ConfigName': 'includeInQuery', 'v1Value': True, 'v2Value': False}, {'v1ConfigName': 'sort', 'v2ConfigName': 'sort', 'v1Value': False, 'v2Value': True}]
    """
    field_diff = [{KEY_V1_CONFIGNAME: diff,
                   KEY_V2_CONFIGNAME: FIELDS_KEYS_V1_V2[diff],
                   KEY_V1_VALUE: v1_field[diff],
                   KEY_V2_VALUE: v2_field[FIELDS_KEYS_V1_V2[diff]]}
                  for diff in FIELDS_KEYS_V1_V2
                    if diff in v1_field and FIELDS_KEYS_V1_V2[diff] in v2_field and v1_field[diff] != v2_field[FIELDS_KEYS_V1_V2[diff]]]
    return field_diff


def get_fields_differences(v1_fields, v2_fields):
    """ Get a list of differences between 2 fields list
    >>> get_fields_differences({}, {})
    []
    >>> v1_fields = {'field0': {'sort': True, 'facet': False}, 'field1': {'sort': True, 'facet': True}}
    >>> v2_fields = {'field1': {'sort': False, 'facet': False}, 'field2': {'sort': True, 'facet': True}}
    >>> get_fields_differences(v1_fields, v2_fields)
    [('field1', {'v1Field': {'sort': True, 'facet': True}, 'v2Field': {'sort': False, 'facet': False}, 'configDiff': [{'v1ConfigName': 'facet', 'v2ConfigName': 'facet', 'v1Value': True, 'v2Value': False}, {'v1ConfigName': 'sort', 'v2ConfigName': 'sort', 'v1Value': True, 'v2Value': False}]})]
    """
    v1_field_names = v1_fields.keys()
    v2_field_names = v2_fields.keys()
    diffs = list()
    for v1_field_name in v1_field_names:
        if v1_field_name in v2_field_names:
            v1_field = v1_fields[v1_field_name]
            v2_field = v2_fields[v1_field_name]
            diff = get_fields_difference(v1_field, v2_fields[v1_field_name])
            if diff:
                diffs.append((v1_field_name, {KEY_V1_FIELD: v1_field, KEY_V2_FIELD: v2_field, KEY_CONFIG_DIFF: diff}))
    return diffs


def v2_get_updated_field(field_difference):
    """ Get a modified field according to the differences provided (CloudV2)
    >>> diffs = ('field1', {'v1Field': {'sort': True, 'facet': True}, 'v2Field': {'name': 'field1', 'sort': False, 'facet': False, 'type': 'SOMETYPE'}, 'configDiff': [{'v1ConfigName': 'facet', 'v2ConfigName': 'facet', 'v1Value': True, 'v2Value': False}, {'v1ConfigName': 'sort', 'v2ConfigName': 'sort', 'v1Value': True, 'v2Value': False}]})
    >>> v2_get_updated_field(diffs)
    {'name': 'field1', 'sort': True, 'facet': True, 'type': 'SOMETYPE'}
    """
    for diff in field_difference[1][KEY_CONFIG_DIFF]:
        if field_difference[1][KEY_V2_FIELD]['type'].lower() == 'date' and \
                diff[KEY_V2_CONFIGNAME].lower() == 'sort' and \
                diff[KEY_V1_VALUE] == False:
            print(f'\t-> Field "{field_difference[1][KEY_V2_FIELD]["name"]}" is of type date and cannot be set to sort = false. Skipping this change.')
        else:
            field_difference[1][KEY_V2_FIELD][diff[KEY_V2_CONFIGNAME]] = diff[KEY_V1_VALUE]
    return field_difference[1][KEY_V2_FIELD]


def v2_get_updated_fields(field_differences):
    """ Get a list of modified fields according to the differences provided (CloudV2)
    """
    return [v2_get_updated_field(diff) for diff in field_differences]


if __name__ == '__main__':
    import doctest
    if doctest.testmod().failed > 0:
        exit(-1)

    parser = argparse.ArgumentParser(description='Migrate fields configuration from CloudV1 to CloudV2')
    parser.add_argument('--env', required=True, type=Environment, choices=list(Environment))
    parser.add_argument('--v1_org_id', required=True)
    parser.add_argument('--v1_source_name', required=True)
    parser.add_argument('--v1_access_token', required=True)
    parser.add_argument('--v2_org_id', required=True)
    parser.add_argument('--v2_source_id', required=True)
    parser.add_argument('--v2_access_token', required=True)
    opts = parser.parse_args()

    # args
    env = opts.env
    v1_org_id = opts.v1_org_id
    v1_source_name = opts.v1_source_name
    v1_access_token = opts.v1_access_token
    v2_org_id = opts.v2_org_id
    v2_source_id = opts.v2_source_id
    v2_access_token = opts.v2_access_token

    v1_client = CloudV1(env, v1_org_id, v1_access_token)
    v1_sources = v1_client.get_sources()
    v1_source_id = v1_get_source_id(v1_sources['sources'], v1_source_name)
    v1_fields = v1_get_fields_by_name(v1_client.get_fields_for_source(v1_source_id))
    print(f'Fields present in CloudV1 ({len(v1_fields)}): {v1_fields}')

    v2_client = CloudV2(env, v2_org_id, v2_access_token)
    v2_mappings = v2_get_mappings_fieldname(v2_client.get_mappings(v2_source_id))
    print(f'Mapping present in CloudV2 ({len(v2_mappings)}): {v2_mappings}')

    common_fields = [v2_mapping for v2_mapping in v2_mappings if v2_mapping in v1_fields.keys()]
    print(f'Common field names between v1 and v2 ({len(common_fields)}): {common_fields}')

    v2_fields_by_name = v2_get_fields_in_use(v2_client.get_fields(), v2_mappings)
    print(f'Fields to compare in v2 ({len(v2_fields_by_name)}): {v2_fields_by_name}')

    fields_difference_to_apply = get_fields_differences(v1_fields, v2_fields_by_name)
    print(f'Found {len(fields_difference_to_apply)} fields to update: {fields_difference_to_apply}')

    v2_fields_updated = v2_get_updated_fields(fields_difference_to_apply)
    if v2_fields_updated:
        print(f'CloudV2 fields to update ({len(v2_fields_updated)}): {v2_fields_updated}')
        v2_client.update_fields(v2_fields_updated)
    else:
        print('No fields to update.')
    print('Migration completed.')