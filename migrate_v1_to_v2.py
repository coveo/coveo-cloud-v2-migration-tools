#! /usr/bin/python3
"""
Migrate field configuration from CloudV1 to CloudV2.
To be used on a CloudV2 source having the same schema version as CloudV1.

TODO: Move filtering of mytype date and sort=false sooner in the process
"""

import json
import itertools
import re
from client.cloud_v1 import *
from client.cloud_v2 import *
from client.fields import Fields
import argparse
import jiphy
import jsbeautifier

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
    # get mytype specifc mappings
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
    >>> v1_fields = {'field0': {'sort': True, 'fieldType':'STRING', 'facet': False, 'multivalueFacet': False}, 'field1': {'sort': True, 'fieldType':'STRING', 'facet': True, 'multivalueFacet': False}}
    >>> v2_fields = {'field1': {'sort': False, 'facet': False, 'type':'STRING', 'multiValueFacet': False}, 'field2': {'sort': True, 'facet': True, 'type':'STRING', 'multiValueFacet': False }}
    >>> get_fields_differences(v1_fields, v2_fields)
    [('field1', {'v1Field': {'sort': True, 'fieldType': 'STRING', 'facet': True, 'multivalueFacet': False}, 'v2Field': {'sort': False, 'facet': False, 'type': 'STRING', 'multiValueFacet': False}, 'configDiff': [{'v1ConfigName': 'facet', 'v2ConfigName': 'facet', 'v1Value': True, 'v2Value': False}, {'v1ConfigName': 'sort', 'v2ConfigName': 'sort', 'v1Value': True, 'v2Value': False}]})]
    """
    v1_field_names = v1_fields.keys()
    v2_field_names = v2_fields.keys()
    diffs = list()
    for v1_field_name in v1_field_names:
        if v1_field_name in v2_field_names:
            v1_field = v1_fields[v1_field_name]
            #Fix v1_field facet and Multifacet
            if v1_field['facet'] and v1_field['multivalueFacet']:
              v1_field['facet'] = False
            #Fix sorting
            mysort = v1_field['sort']
            if v1_field['fieldType']=='DATE' or v1_field['fieldType']=='INTEGER' or v1_field['fieldType']=='DOUBLE' or v1_field['fieldType']=='LONG_64':
              mysort = True
            v1_field['sort']=mysort
            myfieldtype = v1_field['fieldType']
            #fix field types
            if myfieldtype=='INTEGER':
              myfieldtype='LONG'
            v1_field['fieldType']=myfieldtype
            v2_field = v2_fields[v1_field_name]
            diff = get_fields_difference(v1_field, v2_fields[v1_field_name])
            if diff:
                diffs.append((v1_field_name, {KEY_V1_FIELD: v1_field, KEY_V2_FIELD: v2_field, KEY_CONFIG_DIFF: diff}))
    return diffs


def v2_get_updated_field(field_difference):
    global finalreport
    """ Get a modified field according to the differences provided (CloudV2)
    >>> diffs = ('field1', {'v1Field': {'sort': True, 'facet': True}, 'v2Field': {'name': 'field1', 'sort': False, 'facet': False, 'type': 'SOMEtype'}, 'configDiff': [{'v1ConfigName': 'facet', 'v2ConfigName': 'facet', 'v1Value': True, 'v2Value': False}, {'v1ConfigName': 'sort', 'v2ConfigName': 'sort', 'v1Value': True, 'v2Value': False}]})
    >>> v2_get_updated_field(diffs)
    {'name': 'field1', 'sort': True, 'facet': True, 'type': 'SOMEtype'}
    """
    for diff in field_difference[1][KEY_CONFIG_DIFF]:
        if field_difference[1][KEY_V2_FIELD]['type'].lower() == 'date' and \
                diff[KEY_V2_CONFIGNAME].lower() == 'sort' and \
                diff[KEY_V1_VALUE] == False:
            print(f'\t-> Field "{field_difference[1][KEY_V2_FIELD]["name"]}" is of type date and cannot be set to sort = false. Skipping this change.')
            finalreport += f'\n\t-> Field "{field_difference[1][KEY_V2_FIELD]["name"]}" is of type date and cannot be set to sort = false. Skipping this change.'
        else:
            field_difference[1][KEY_V2_FIELD][diff[KEY_V2_CONFIGNAME]] = diff[KEY_V1_VALUE]
    return field_difference[1][KEY_V2_FIELD]


def v2_get_updated_fields(field_differences):
    """ Get a list of modified fields according to the differences provided (CloudV2)
    """
    return [v2_get_updated_field(diff) for diff in field_differences]


def get_unused_fields(fields):
    global finalreport
    unused_fields = []
    for item in fields['items']:
        if not item['sources'] and not item['system']: 
            unused_fields.append(item['name'])
            print(f'\t-> Field "{item["name"]}" is unused')
            finalreport += f'\n\t-> Field "{item["name"]}" is unused'
    return ",".join(unused_fields)


def v1_get_unique_fields(fields: list) -> list:
    """
    # >>> fields = [{'name': 'f0', 'fieldType': 'STRING', 'contentType': 'METADATA', 'sort': True, 'facet': False}, \
    # {'name': 'f0', 'fieldType': 'STRING', 'contentType': 'METADATA', 'sort': False, 'facet': True}, \
    # {'name': 'f1', 'fieldType': 'STRING', 'contentType': 'METADATA'}]
    # >>> v1_get_unique_fields(fields)
    # [('f0', [{'name': 'f0', 'fieldType': 'STRING', 'contentType': 'METADATA', 'sort': True, 'facet': False}, {'name': 'f0', 'fieldType': 'STRING', 'contentType': 'METADATA', 'sort': False, 'facet': True}]), ('f1', [{'name': 'f1', 'fieldType': 'STRING', 'contentType': 'METADATA'}])]
    """
    def get_fields_by_name() -> dict:
        fields_by_name = dict()
        for field in fields:
            name = field['name']
            if name in fields_by_name:
                fields_by_name[name].append(field)
            else:
                fields_by_name[name] = [field]
        return fields_by_name

    def merge_fields_config(fields: list) -> dict:
        new_field = {'fieldQueries': False, 'freeTextQueries': False, 'facet': False, 'multivalueFacet': False, 'sort': False, 'displayField': False}
        mappings = list()
        for field in fields:
            #print (field)
            if (field['contentType']=='SCRIPT'):
              mapping = {'name': field['name'], 'contentType':field['contentType'], 'metadataName': field['scriptParams'], 'sourceId': field['sourceId']}
            else:
              mapping = {'name': field['name'], 'contentType':field['contentType'], 'metadataName': field['metadataName'], 'sourceId': field['sourceId']}
            for flag in new_field:
                new_field[flag] |= field[flag]
            mappings.append(mapping)
        new_field['mappings'] = mappings
        return new_field

    def validate_field_config(fields: list) -> bool:
        expected_length = len(fields)
        field_type = fields[0]['fieldType']
        content_type = fields[0]['contentType']
        if expected_length != len(list(filter(lambda f: f['fieldType'] == field_type and
                                                        f['contentType'] == content_type, fields))):
            return False
        return True

    fields_by_name = get_fields_by_name()
    unique_fields_by_name = list()
    for field_name in fields_by_name:
        field = fields_by_name[field_name]
        if validate_field_config(field):
            merged = merge_fields_config(field)
            merged['name'] = field_name
            merged['fieldType'] = field[0]['fieldType']
            merged['contentType'] = field[0]['contentType']
            unique_fields_by_name.append((field_name, merged))
    return unique_fields_by_name


def v1_field_is_user(field: dict) -> bool:
    return field['fieldOrigin'] == 'CUSTOM' and not field['contentType'] == 'CUSTOM_SCRIPT'
    #return field['contentType'] == 'CUSTOM'


def copy_user_fields(v1_fields: list, v2_client: CloudV2, dry_run: bool):
    global finalreport
    v2_unique_fields = [Fields.v1_to_v2(field[1]) for field in v1_fields]
    v2_fields = [f['name'] for f in v2_client.fields_get()['items']]
    v2_fields_to_create = list()
    for field in v2_unique_fields:
        if field['name'] in v2_fields:
            print(f'SKIPPING FIELD \'{field["name"]}\' because it already exists in org: {field}')
            finalreport += f'\n\tSKIPPING FIELD \'{field["name"]}\' because it already exists in org: {field}'
        else:
            print(f'ADDING FIELD \'{field["name"]}\': {field}')
            finalreport += f'\n\tADDING FIELD \'{field["name"]}\': {field}'
            v2_fields_to_create.append(field)

    if not dry_run and len(v2_fields_to_create) > 0:
        v2_client.fields_create_batch(v2_fields_to_create)

def v2_create_mapping_from_v1_fields(v2_client: CloudV2, v1_sources: object, v1_fields: list, v2_sources: list, dry_run: bool):
    def v2_get_mappings_by_source_id_by_field_name(sources: dict) -> dict:
        # we can't have the same mapping on the same field in CloudV1
        return dict([(sources[source]['v2_id'],
                      dict([(x['field'].lower(), x) for x in
                            v2_client.mappings_get(sources[source]['v2_id'])['common']['rules']]))
                     for source in sources])

    def v2_get_sources_by_name() -> dict:
        v1_sources_by_name = dict([(source['name'].lower(), source) for source in v1_sources['sources']])
        v2_sources_by_name = dict([(source['name'].lower(), source) for source in v2_sources])
        return dict([(v2_source_key,
                      {'v1_id': v1_sources_by_name[v2_source_key]['id'],
                       'v2_id': v2_sources_by_name[v2_source_key]['id']})
                     for v2_source_key in v2_sources_by_name.keys()
                     if v2_source_key in v1_sources_by_name])

    def v2_get_source_used_field(field: dict, common_sources: dict) -> dict:
        # v1 source id -> v1 source name == v2 source name -> v2 source id
        v1_source_id = field['sourceId']
        v1_source_name = v1_sources_by_id[v1_source_id]['name']
        v2_source_id = None
        if v1_source_name.lower() in common_sources:
            v2_source_id = common_sources[v1_source_name.lower()]['v2_id']
        return {'id': v2_source_id, 'name': v1_source_name}

    def v2_create_mapping(field: dict, mappings: dict, source_id: str, source_name: str) -> None:
        global finalreport
        #print (field)
        if (field['contentType']=='SCRIPT'):
          #get content from scriptparams
          scriptcontent=field["metadataName"]
          new_mapping = {'content': [f'{scriptcontent["Content"]}'], 'field': f'{field["name"]}'}
        else:
          new_mapping = {'content': [f'%[{field["metadataName"]}]'], 'field': f'{field["name"]}'}
        new_mapping_exists = new_mapping['field'].lower() in mappings
        if new_mapping_exists:
            print(f'SKIPPING MAPPING {new_mapping} because it\'s already present in source \'{source_name}\'')
            finalreport += f'\n\tSKIPPING MAPPING {new_mapping} because it\'s already present in source \'{source_name}\''
        elif not dry_run:
            print(f'ADD MAPPING: {new_mapping}')
            finalreport += f'\n\tADD MAPPING: {new_mapping}'
            v2_client.mappings_common_add(source_id, False, new_mapping)

    global finalreport
    common_sources = v2_get_sources_by_name()
    if len(common_sources) == 0:
        print(f'No common source names between CloudV1 and CloudV2. Cannot copy mappings.')
        finalreport += f'\n\tNo common source names between CloudV1 and CloudV2. Cannot copy mappings.'
    else:
        print ("Common source names found.")
        #print(f'Common source names ({len(common_sources)}): {json.dumps(common_sources)}')
    mappings_by_source_id = v2_get_mappings_by_source_id_by_field_name(common_sources)
    v1_sources_by_id = dict([(source['id'].lower(), source) for source in v1_sources['sources']])
    for field in v1_fields:
        v2_source = v2_get_source_used_field(field, common_sources)
        v2_source_id = v2_source['id']
        v2_source_name = v2_source['name']
        if v2_source_id is None:
            print(f'SKIPPING MAPPING for \'{field["name"]}\' because source \'{v2_source_name}\' does not exist in CloudV2')
            finalreport += f'\n\tSKIPPING MAPPING for \'{field["name"]}\' because source \'{v2_source_name}\' does not exist in CloudV2'
        else:
            v2_create_mapping(field, mappings_by_source_id[v2_source_id], v2_source_id, v2_source_name)

def addLine():
  return "   --------------------------------------------------\n"
          

def translatetype(mytype):
  fromRepo = { "WEB":"WEB2", "EXCHANGE_ENTERPRISE":"EXCHANGE",
               "JIRA":"JIRA2_HOSTED", "JIRA_CLOUD":"JIRA2", "JIVE":"JIVE_HOSTED", "JIVE_CLOUD":"JIVE", 
               "CONFLUENCE2":"CONFLUENCE2_HOSTED","CONFLUENCE2_CLOUD":"CONFLUENCE2","SHAREPOINT":"SHAREPOINT",
               "GMAIL":"GMAIL_SINGLE_USER",
               "SHAREPOINT_ONLINE":"SHAREPOINT_ONLINE2","TWITTER":"TWITTER2",
               "YAMMER":"BAD","ORACLE_KNOWLEDGE":"BAD","CONFLUENCE":"BAD", 
               "WEBSCRAPER": "MAN",
                #Must be done manual, you need an valid OAUTH token
               "SALESFORCE":"SALESFORCE", "KNOWLEDGEBASE":"SALESFORCE","SALESFORCE_CONTENT":"SALESFORCE", 
               }

  for repo in fromRepo:
    if repo == mytype:
      return fromRepo[repo]
  return mytype

def addAddressPattern(mytype):
    mytype["configuration"]["addressPatterns"]=[]
    mytype["configuration"]["addressPatterns"].append({})
    mytype["configuration"]["addressPatterns"][0]["expression"]="*"
    mytype["configuration"]["addressPatterns"][0]["patterntype"]="Wildcard"
    mytype["configuration"]["addressPatterns"][0]["allowed"]=True

    return mytype

def addSecurityEverybody(mytype):
    mytype["configuration"]["permissions"]=[{"permissionSets": [{"allowedPermissions": [{"identitytype": "Group","securityProvider": "Email Security Provider","identity": "*@*"}],"name": "Shared"}],"name": "Source Specified Permissions"}    ]

    return mytype

def addSecurityUser(mytype,email):
    mytype["configuration"]["permissions"]=[{"permissionSets": [{"allowedPermissions": [{"identitytype": "User","securityProvider": "Email Security Provider","identity": email}],"name": "Private"}],"name": "Source Specified Permissions"}    ]

    return mytype


def addParam(mytype,key,sensitive, value):
    mytype["configuration"]["parameters"][key]={}
    mytype["configuration"]["parameters"][key]["sensitive"]=sensitive
    mytype["configuration"]["parameters"][key]["value"]=value
    return mytype

def getCloudSetting(config, value, default):
  if value in config["cloudSourceConfiguration"]:
    return config["cloudSourceConfiguration"][value]
  else:
    return default

def fix(mytype, config):
  global v1_org_id
  global actionlist
  mytype["MethodToUse"]="SIMPLE"
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="GOOGLE_DRIVE_SINGLE_USER":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.GoogleDriveSingleUser"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    email =  getCloudSetting(config,"name","").replace('Drive - ','')
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"owner","*@*"))
    if email:
      mytype["emailAddress"]=email
      mytype["additionalInfos"]={"emailAddress": email }

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="GMAIL":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    #Must be done manual, you need an valid OAUTH token
    #Must be done using RAW 
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.GmailSingleUser"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"emailAddress","*@*"))
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["emailAddress"]
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["emailAddress"] }
      mytype["configuration"]["startingAddresses"]=["https://www.gmail.com"]

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="EXCHANGE":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Exchange"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"emailAddress","*@*"))
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["emailAddress"]
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["emailAddress"] }
      mytype["configuration"]["startingAddresses"]=[ "https://outlook.office365.com/exchange/"+config["cloudSourceConfiguration"]["emailAddress"] ]
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["emailAddress"],  "password": "UPDATEIT" }}
    mytype["password"]="TOCHANGE"
    #mytype["sourceVisibility"] = "SHARED"

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="DROPBOX":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    email =  getCloudSetting(config,"name","").replace('Dropbox - ','')
    if email:
      mytype["emailAddress"]=email
      mytype["additionalInfos"]={"emailAddress": email }
    mytype["accessToken"]="UPDATEIT"
    
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="TWITTER":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="LITHIUM":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "serverAddress" in config["cloudSourceConfiguration"]:
      mytype["serverAddress"]=config["cloudSourceConfiguration"]["serverAddress"]

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SHAREPOINT":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "url" in config["cloudSourceConfiguration"]:
      mytype["urls"]=[config["cloudSourceConfiguration"]["url"]]
    mytype["crawlScope"]="SiteCollection"

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SHAREPOINT_ONLINE":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tRefresh Token"
    actionlist += "\n\tAdd Tennant name"
    mytype["RefreshToken"]="UPDATEIT"
    mytype["tenantname"]="UPDATEIT"
    mytype["crawlScope"]="SiteCollection"
    if "url" in config["cloudSourceConfiguration"]:
      mytype["urls"]=[config["cloudSourceConfiguration"]["url"]]

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SHAREPOINT_LEGACY":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="YAMMER":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="WEBSCRAPER":
    actionlist += "\n\tAdjust webscraper configuration"
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="GOOGLE_DRIVE_DOMAIN_WIDE":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="RSS":
    if "uri" in config["cloudSourceConfiguration"]:
      mytype["urls"]=[config["cloudSourceConfiguration"]["uri"]]

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="WEB":
    a=0

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="CONFLUENCE":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="CONFLUENCE2":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Confluence2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"IndexComments", False, getCloudSetting(config,"indexComments",True))
    mypersonal = getCloudSetting(config,"indexOnlyPersonalSpaces",False)
    myglobal = getCloudSetting(config, "indexOnlyGlobalSpaces", False)
    #Current/Archived is not present in V1
    mycurrent = getCloudSetting(config,"indexCurrentSpaces",True)
    myarchived = getCloudSetting(config, "indexArchivedSpaces", False)
    if mypersonal and myglobal:
      myglobal = False
      mypersonal = True
    mytype=addParam(mytype,"IndexOnlyPersonalSpaces", False, getCloudSetting(config,"indexOnlyPersonalSpaces",mypersonal))
    mytype=addParam(mytype,"IndexArchivedSpaces", False, getCloudSetting(config, "indexArchivedSpaces", myarchived))
    mytype=addParam(mytype,"IndexOnlyGlobalSpaces", False, getCloudSetting(config, "indexOnlyGlobalSpaces", myglobal))
    mytype=addParam(mytype,"IndexAttachments", False, getCloudSetting(config, "indexAttachments", True))
    mytype=addParam(mytype,"IndexCurrentSpaces", False, getCloudSetting(config, "indexCurrentSpaces", mycurrent))
    mytype=addParam(mytype,"FilterSpaceRegex", False, getCloudSetting(config,"spaceFilter",""))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))

    if "username" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "urls" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= config["cloudSourceConfiguration"]["urls"] 
    mytype["password"]="TOCHANGE"
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="CONFLUENCE2_CLOUD":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Confluence2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"IndexComments", False, getCloudSetting(config,"indexComments",True))
    mypersonal = getCloudSetting(config,"indexOnlyPersonalSpaces",False)
    myglobal = getCloudSetting(config, "indexOnlyGlobalSpaces", False)
    #Current/Archived is not present in V1
    mycurrent = getCloudSetting(config,"indexCurrentSpaces",True)
    myarchived = getCloudSetting(config, "indexArchivedSpaces", False)
    if mypersonal and myglobal:
      myglobal = False
      mypersonal = True
    mytype=addParam(mytype,"IndexOnlyPersonalSpaces", False, getCloudSetting(config,"indexOnlyPersonalSpaces",mypersonal))
    mytype=addParam(mytype,"IndexArchivedSpaces", False, getCloudSetting(config, "indexArchivedSpaces", myarchived))
    mytype=addParam(mytype,"IndexOnlyGlobalSpaces", False, getCloudSetting(config, "indexOnlyGlobalSpaces", myglobal))
    mytype=addParam(mytype,"IndexAttachments", False, getCloudSetting(config, "indexAttachments", True))
    mytype=addParam(mytype,"IndexCurrentSpaces", False, getCloudSetting(config, "indexCurrentSpaces", mycurrent))
    mytype=addParam(mytype,"FilterSpaceRegex", False, getCloudSetting(config,"spaceFilter",""))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))
    if "username" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "urls" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= config["cloudSourceConfiguration"]["urls"] 
    mytype["password"]="TOCHANGE"
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="ORACLE_KNOWLEDGE":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="YOUTUBE":
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SITEMAP":
    actionlist += "\n\tAdjust webscraper configuration"
    if (getCloudSetting(config,"urlReplacementPattern","")):
      actionlist += "\n\tUrl replacement is obsolete, add your extension script to solve it."
    if (getCloudSetting(config,"oAuthProviderType","")):
      actionlist += "\n\toAuthProviderType is obsolete, set form authentication in the source."
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="JIRA":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Jira2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ShallIndexWorkLogs", False, getCloudSetting(config,"indexWorkLogs",True))
    mytype=addParam(mytype,"ShallIndexComments", False, getCloudSetting(config,"indexComments",False))
    mytype=addParam(mytype,"ShallIndexAttachments", False, getCloudSetting(config, "indexAttachments", False))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))
    if "username" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "startingAddress" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= [ config["cloudSourceConfiguration"]["startingAddress"] ]
    mytype["password"]="TOCHANGE"

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="JIRA_CLOUD":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Jira2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ShallIndexWorkLogs", False, getCloudSetting(config,"indexWorkLogs",True))
    mytype=addParam(mytype,"ShallIndexComments", False, getCloudSetting(config,"indexComments",False))
    mytype=addParam(mytype,"ShallIndexAttachments", False, getCloudSetting(config, "indexAttachments", False))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)

    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))
    if "username" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "startingAddress" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= [ config["cloudSourceConfiguration"]["startingAddress"] ]
    mytype["password"]="TOCHANGE"

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="JIVE":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Jive"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"OnlyIndexPublishedContent", False, getCloudSetting(config,"indexOnlyPublishedItems",False))
    mytype=addParam(mytype,"ShallIndexGroups", False, getCloudSetting(config,"indexSocialGroups",True))
    mytype=addParam(mytype,"ShallIndexSystemBlogs", False, getCloudSetting(config, "indexSystemBlogs", True))
    mytype=addParam(mytype,"ShallIndexSpaces", False, getCloudSetting(config,"indexCommunities",True))
    mytype=addParam(mytype,"ShallIndexProjects", False, getCloudSetting(config,"indexProjects",True))
    mytype=addParam(mytype,"ShallIndexPeople", False, getCloudSetting(config, "indexUsers", False))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    mytype["additionalInfos"] = { "JiveInstanceAllowsAnonymousAccess": getCloudSetting(config, "allowsAnonymousAccess", True) }
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))
    if "username" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "url" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= [ config["cloudSourceConfiguration"]["url"] ]
    mytype["password"]="TOCHANGE"
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="JIVE_CLOUD":
    if "publicVisibility" in config["cloudSourceConfiguration"]:
      if not config["cloudSourceConfiguration"]["publicVisibility"]:
        actionlist += "\n\tWARNING: V1 has public Visibility set to false, check security in V2!!!"
    actionlist += "\n\tAdd password"
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["email"]=config["cloudSourceConfiguration"]["emailAddress"]
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Jive"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"OnlyIndexPublishedContent", False, getCloudSetting(config,"indexOnlyPublishedItems",False))
    mytype=addParam(mytype,"ShallIndexGroups", False, getCloudSetting(config,"indexSocialGroups",True))
    mytype=addParam(mytype,"ShallIndexSystemBlogs", False, getCloudSetting(config, "indexSystemBlogs", True))
    mytype=addParam(mytype,"ShallIndexSpaces", False, getCloudSetting(config,"indexCommunities",True))
    mytype=addParam(mytype,"ShallIndexProjects", False, getCloudSetting(config,"indexProjects",True))
    mytype=addParam(mytype,"ShallIndexPeople", False, getCloudSetting(config, "indexUsers", False))
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    mytype["additionalInfos"] = { "JiveInstanceAllowsAnonymousAccess": getCloudSetting(config, "allowsAnonymousAccess", True) }
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
      mytype=addSecurityUser(mytype,getCloudSetting(config,"username","*@*"))
    if "username" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": config["cloudSourceConfiguration"]["username"],  "password": "UPDATEIT" }}
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["username"]
      mytype["additionalInfos"]={"emailAddress": config["cloudSourceConfiguration"]["username"] }
    if "url" in config["cloudSourceConfiguration"]:
      mytype["configuration"]["startingAddresses"]= [ config["cloudSourceConfiguration"]["url"] ]
    mytype["password"]="TOCHANGE"

  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SALESFORCE":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    actionlist += "\n\tImport field configuration"
    #Must be done using RAW 
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Salesforce2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)
    #remove objectsSchema
    mytype["objectsSchema"]=[]

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    mytype=addParam(mytype,"SchemaVersion", False, "LEGACY")
    mytype=addParam(mytype,"IsSandbox", False, getCloudSetting(config,"sandbox", False))
    mytype=addParam(mytype,"UseRefreshToken", False, getCloudSetting(config,"useRefreshToken", True))
    mytype=addParam(mytype,"OAuthRefreshToken", True, "UPDATEIT")
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Merge"
    #Weird token is in password of a useridentity
    mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": "unused",  "password": "UPDATEIT" }}
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["emailAddress"]
      if "username" in config["cloudSourceConfiguration"]:
        mytype["additionalInfos"]={"salesforceOrg": "UPDATEIT", "schemaVersion": "LEGACY",  "salesforceOrgName": "UPDATEIT", "salesforceUser":config["cloudSourceConfiguration"]["username"] }
      mytype["configuration"]["startingAddresses"]=["http://www.salesforce.com"]    
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="KNOWLEDGEBASE":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    actionlist += "\n\tImport field configuration"
    #Must be done using RAW 
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Salesforce2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)
    #remove objectsSchema
    mytype["objectsSchema"]=[]

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    mytype=addParam(mytype,"SchemaVersion", False, "LEGACY")
    mytype=addParam(mytype,"IsSandbox", False, getCloudSetting(config,"sandbox", False))
    mytype=addParam(mytype,"UseRefreshToken", False, getCloudSetting(config,"useRefreshToken", True))
    mytype=addParam(mytype,"OAuthRefreshToken", True, "UPDATEIT")
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Merge"
    #Weird token is in password of a useridentity
    mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": "unused",  "password": "UPDATEIT" }}
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["emailAddress"]
      if "username" in config["cloudSourceConfiguration"]:
        mytype["additionalInfos"]={"salesforceOrg": "UPDATEIT", "schemaVersion": "LEGACY",  "salesforceOrgName": "UPDATEIT", "salesforceUser":config["cloudSourceConfiguration"]["username"] }
      mytype["configuration"]["startingAddresses"]=["http://www.salesforce.com"]    
    a=0
  #-----------------------------------------------------------------------------------------------------------------
  if config["type"]=="SALESFORCE_CONTENT":
    actionlist += "\n\tAdd password"
    actionlist += "\n\tRefresh Token"
    actionlist += "\n\tImport field configuration"
    #Must be done using RAW 
    mytype["MethodToUse"]="RAW"
    mytype["crawlerInstancetype"] = "Connector.Salesforce2"
    mytype["configuration"]={}
    mytype = addAddressPattern(mytype)
    #remove objectsSchema
    mytype["objectsSchema"]=[]

    mytype["configuration"]["parameters"]={}
    mytype=addParam(mytype,"PauseOnError", False, "true")
    mytype=addParam(mytype,"ClientSecret", True, "UPDATEIT")
    mytype=addParam(mytype,"ClientId", False, "UPDATEIT")
    mytype=addParam(mytype,"ClientRefreshToken", True, "UPDATEIT")
    mytype=addParam(mytype,"OrganizationId", False, v1_org_id)
    mytype=addParam(mytype,"SchemaVersion", False, "LEGACY")
    mytype=addParam(mytype,"IsSandbox", False, getCloudSetting(config,"sandbox", False))
    mytype=addParam(mytype,"UseRefreshToken", False, getCloudSetting(config,"useRefreshToken", True))
    mytype=addParam(mytype,"OAuthRefreshToken", True, "UPDATEIT")
    if config["cloudSourceConfiguration"]["publicVisibility"]:
      mytype=addSecurityEverybody(mytype)
      mytype["configuration"]["sourceSecurityOption"] = "Specified"
    else:
      mytype["configuration"]["sourceSecurityOption"] = "Merge"
    #Weird token is in password of a useridentity
    mytype["configuration"]["userIdentities"]= { "UserIdentity": {  "name": "token",  "userName": "unused",  "password": "UPDATEIT" }}
    if "emailAddress" in config["cloudSourceConfiguration"]:
      mytype["emailAddress"]=config["cloudSourceConfiguration"]["emailAddress"]
      if "username" in config["cloudSourceConfiguration"]:
        mytype["additionalInfos"]={"salesforceOrg": "UPDATEIT", "schemaVersion": "LEGACY",  "salesforceOrgName": "UPDATEIT", "salesforceUser":config["cloudSourceConfiguration"]["username"] }
      mytype["configuration"]["startingAddresses"]=["http://www.salesforce.com"]    
    a=0
  return mytype

def translateVisibility(mytype):
  fromRepo = { "PUBLIC":"SHARED","PRIVATE":"SECURED"}
  for repo in fromRepo:
    if repo == mytype:
      return fromRepo[repo]
  return mytype

def transformV1ToV2(myconfig):
  #Transform V1 source to V2 RAW format
  #Check for problems in SFDC configs
  restrictedfields = { "name","notifyOnRebuildCompleted","objectsSchema","owner","publicVisibility","rebuildRequired", "sourceType","sourceVisibility", "titleSelectionSequence","type","urls", "urlFilters"}
  
  report = {}
  #print (myconfig["cloudSourceConfiguration"])
  report["id"]=myconfig["id"]
  report["information"]={}
  report["information"]["sourceId"] = myconfig["id"]
  sourcename=""
  if 'name' in myconfig["cloudSourceConfiguration"]:
      sourcename = myconfig["cloudSourceConfiguration"]["name"]
  else:
      sourcename = myconfig["id"]
  report["information"]["sourceName"] = sourcename
  report["name"] = sourcename
  if 'owner' in myconfig["cloudSourceConfiguration"]:
    report["owner"] = myconfig["cloudSourceConfiguration"]["owner"]
  report["sourceType"] = translatetype(myconfig["type"])
  report["sourceVisibility"] = translateVisibility(myconfig["visibility"])
  if 'urls' in myconfig["cloudSourceConfiguration"]:
    report["urls"] = myconfig["cloudSourceConfiguration"]["urls"]
  if 'urlFilters' in myconfig["cloudSourceConfiguration"]:
    report["urlFilters"] = myconfig["cloudSourceConfiguration"]["urlFilters"]
  
  report["customParameters"] = {}
  for field in myconfig["cloudSourceConfiguration"]:
    if not field in restrictedfields:
      report["customParameters"][field]=myconfig["cloudSourceConfiguration"][field]
      report[field]=myconfig["cloudSourceConfiguration"][field]
  report = fix(report,myconfig)
  return report


def inspectSFDC(myconfig):
  #Inspects SFDC custom settings
  #Check for problems in SFDC configs
  report = ""
  if myconfig['cloudSourceConfiguration']:
    if 'objectsSchema' in myconfig['cloudSourceConfiguration']:
      for objects in myconfig['cloudSourceConfiguration']['objectsSchema']:
        if objects['custom']==True:
          body = ""
          if 'body' in objects:
            body = objects['body']
          report += "\n\tSFDC SCHEMA FOR OBJECT: "+objects['name']+", different body:\n\t"+body+"\n\t==================================================\n"
          for fields in objects['fields']:
            if fields['custom']==True:
              report += "\n\tSFDC SCHEMA FOR OBJECT: "+objects['name']+""
              #facet, fieldName, freeText, label, multi, name, parentObjectName, mytype
              report += "\n\tSFDC SCHEMA FOR FIELD : "+fields["name"]+"\n"+addLine()
              report +=   "\tfieldName             : "+fields["fieldName"]+"\n"+addLine()
              report +=   "\tlabel                 : "+fields["label"]+"\n"+addLine()
              report +=   "\ttype                  : "+fields["type"]+"\n"+addLine()
              report +=   "\tparentObjectName      : "+fields["parentObjectName"]+"\n"+addLine()
              report +=   "\tfacet                 : "+str(fields["facet"])+"\n"+addLine()
              report +=   "\tfreeText              : "+str(fields["freeText"])+"\n"+addLine()
              report +=   "\tmulti facet           : "+str(fields["multi"])+"\n"
              report += "\n\t==================================================\n"

  return report


def removeComments(string):
    string = re.sub(re.compile("/\*.*?\*/",re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL  ) ,"" ,string) # remove all occurance streamed comments (/*COMMENT */) from string
    string = re.sub(re.compile("//.*?\n" ,re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL ) ,"" ,string) # remove all occurance singleline comments (//COMMENT\n ) from string
    return string


def changeComments(string):
    string = re.sub(re.compile("//(.*)[^;]\n" ) ,"// \\1 \n" ,string) # remove all occurance singleline comments (//COMMENT\n ) from string
    string = re.sub(re.compile("/\*([\S\s]*?)\*/",re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL  ) ,"/* \\1 */" ,string) # remove all occurance streamed comments (/*COMMENT */) from string
    #string = re.sub(re.compile("//(.*)\n" ) ,"// \\1\n" ,string) # remove all occurance singleline comments (//COMMENT\n ) from string
    return string

def toPython(string, filename):
  global functionstocall
  global finalreport
  string = changeComments(string)
  #print (string)
  string = jsbeautifier.beautify(string)
  #replace functions
  addWriteOutput=False
  addWriteHTMLOutput=False
  #function (.*)[^\r]{
  #string = re.sub(re.compile("function (.*)[^\r]{",re.DOTALL ) ,"function \\1{" ,string) 
  """ string = re.sub(re.compile("function (.*)[^\r]{",re.DOTALL ) ,"def \\1:" ,string) 
  #var fields
  #var fieldList = {
  string = re.sub(re.compile("var (.*)=[ ]*{([\S\s][^}]*)}[;]*",re.DOTALL ) ,"\\1={\\2}" ,string) 
  #var 
  string = re.sub(re.compile("var ",re.DOTALL ) ,"" ,string) 
  # && 
  string = re.sub(re.compile(" && ",re.DOTALL ) ," and " ,string) 
  # {
  string = re.sub(re.compile("{",re.DOTALL ) ,":" ,string) 
  # }
  string = re.sub(re.compile("}",re.DOTALL ) ,"" ,string) """
  #fix regex
  #var (\w)*[ ]*=[ ]*\/(.*);
  string = re.sub(re.compile("var (\w*)[ ]*=[ ]*\/(.*)/(.*);" ) ,"\\1=r\"\\2\";" ,string)
  #var 
  string = re.sub(re.compile("var (\w*);" ) ,"\\1=None;" ,string) 
  string = re.sub(re.compile("var " ) ,"" ,string) 

  #
  string = re.sub(re.compile("{}" ) ,"{\n//Empty\npass\n}" ,string) 
 
  

  #PostConversion.Trace
  string = re.sub(re.compile("PostConversion\.Trace\((.*),.?0\)"  ) ,"log(\\1, 'Normal')" ,string)
  string = re.sub(re.compile("PostConversion\.Trace\((.*),.?1\)"  ) ,"log(\\1, 'Debug')" ,string)
  string = re.sub(re.compile("PostConversion\.Trace\((.*),.?2\)"  ) ,"log(\\1, 'Error')" ,string)
  string = re.sub(re.compile("PostConversion\.Trace\((.*),.?(\w*)\)"  ) ,"log(\\1, \\2)" ,string)
  string = re.sub(re.compile("PostConversion\.Trace\((.*)\)"  ) ,"log(\\1, 'Normal')" ,string)
  string = re.sub(re.compile("PostConversion\.Trace"  ) ,"log" ,string)
  
  #DocumentInfo.URI
  string = re.sub(re.compile("DocumentInfo\.URI",re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL  ) ,"document.uri" ,string)
  
  #\(function (\w*)\((.*){([\s\S\n]*)\)\(\);
  #print (string)
  while re.search("\(function (\w*)\((.*){([\s\S\n]*)}[\n]*\)\(\);", string ):
    string = re.sub(re.compile("\(function (\w*)\((.*){([\s\S\n]*)}[\n]*\)\(\);"  ) ,"function \\1(\\2{\\3} \\1();" ,string)
  while re.search("\(function\(\) {([\s\S\n]*)}[\n]*\)\(\)", string ):
    string = re.sub(re.compile("\(function\(\) {([\s\S\n]*)}[\n]*\)\(\)"  ) ,"\\1" ,string)
  
  
  #Gather all the functions called which we might need to support
  #\.(\w*)\(
  for match in re.finditer('\.(\w*)\(', string):
    if not match.group(1) in functionstocall:
      functionstocall.append(match.group(1))
      finalreport += "\nFunction call found in JS file: "+(match.group(1)+ "-->"+filename)
  #PostConversion.HTMLOutputToOverride.WriteString
  if "PostConversion.HTMLOutputToOverride.WriteString" in string:
    addWriteHTMLOutput = True
  if "PostConversion.TextToOverride.WriteString" in string:
    addWriteOutput = True
  string = re.sub(re.compile("PostConversion.HTMLOutputToOverride.WriteString",re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL  ) ,"WriteHTMLOutput" ,string)
  string = re.sub(re.compile("PostConversion.TextToOverride.WriteString",re.RegexFlag.MULTILINE|re.RegexFlag.DOTALL  ) ,"WriteOutput" ,string)
  #DocumentInfo.GetFieldValue
  string = re.sub(re.compile("DocumentInfo\.GetFieldValue\((\w*)\);"  ) ,"document.get_meta_data_value(\\1)[0]" ,string)
  string = re.sub(re.compile("DocumentInfo\.(\w*)[ ]*=(.*);"  ) ,"document.add_meta_data({'\\1':\\2})" ,string)
  #DocumentInfo.SetFieldValue --> document.add_meta_data({"mylat2":str(i['Lat'])})
  #;$
  #string = re.sub(re.compile(";$",re.DOTALL ) ,"" ,string) 
  #Switch
  #switch \((\w+):([\S\s\n]*)case ['\"]*(\w+)['\"]:
  #first replace all case, then when nothing left, replace the switch
  #print (string)
  #print ("START")
  while re.search(r"switch \((\w+)\) {([\S\s\n]*)case ['\"]*(\w+)['\"]:([\S\s\n]*?)break;", string ):
    #print ("IN HERE")
    string = re.sub(re.compile(r"switch \((\w+)\) {([\S\s\n]*)case (['\"]*\w+['\"]*):([\S\s\n]*?)break;"  ) ,"switch (\\1) {\\2if (\\1==\\3) {\n\\4\n}" ,string)
  #replace the switch itself
  string = re.sub(re.compile(r"switch \((\w+)\)") ,"a=0;\nif (a==0) " ,string)

 
  string = jsbeautifier.beautify(string)
  #print (string)
  string = jiphy.to.python(string)
  string = re.sub(re.compile("\);") ,")" ,string) 
  string = re.sub(re.compile("\(\:") ,":" ,string) 

  #print (string)
  string = re.sub(re.compile("DocumentInfo\.SetFieldValue\((.*),(.*)\)") ,"document.add_meta_data({\\1:\\2})" ,string)
  #fix for loops
  #for (\w*) = (\w*); (\w+) (\S+) ([\w.]+); ([\w+]+):
  string = re.sub(re.compile("for (\w*) = (\w*); (\w+) (\S+) ([\w.]+); ([\w+]+):") ,"for \\1 in range(\\2,\\5): #for \\1 = \\2;\\3 \\4 \\5; \\6" ,string)
  string = re.sub(re.compile("for (\w*) = ([\w\.\(\)]*) (\w*) (\W*) ([\w\.\(\)]*) (\S*):") ,"for \\1 in range(\\2, \\5): #for \\1 = \\2;\\3 \\4 \\5; \\6" ,string)
  #fix length
  #(\w*).length
  string = re.sub(re.compile("(\w*).length") ,"len(\\1)" ,string)
  #fix lower/uppercase
  string = re.sub(re.compile("toLowerCase\(\)") ,"lower()" ,string)
  string = re.sub(re.compile("toUpperCase\(\)") ,"upper()" ,string)
  #fix replace
  #\.replace\(\/(.*)\/(.*),
  string = re.sub(re.compile("(\w*)\.(.*)\.replace\(\/(.*)\/(.*), (.*)\)") ,"\\1.\\2\r\\1=re.sub('\\3',\\5,\\1) #\\4\n\n" ,string)
  string = re.sub(re.compile("(this)\.replace\(\/(.*)\/(.*), (.*)\)") ,"re.sub('\\2',\\4,\\1) #\\3 FIX the this reference\n" ,string)
  string = re.sub(re.compile("(\w*)\.replace\(\/(.*)\/(.*), (.*)\)") ,"re.sub('\\2',\\4,\\1)  #\\3\n" ,string)
  string = re.sub(re.compile("(\w*)\.replace\((.*), (.*)\)"), "re.sub(\\2,\\3,\\1)  #\\3\n" ,string)
  #ClickableURI
  #DocumentInfo\.ClickableURI
  string = re.sub(re.compile("DocumentInfo\.ClickableURI") ,"document.get_meta_data_value('clickableuri')[0]" ,string)
  string = re.sub(re.compile("DocumentInfo\.Title") ,"document.get_meta_data_value('title')[0]" ,string)
  string = re.sub(re.compile("DocumentInfo\.FileType") ,"document.get_meta_data_value('filetype')[0]" ,string)
  string = re.sub(re.compile("DocumentInfo\.Date") ,"document.get_meta_data_value('date')[0]" ,string)

  string = re.sub(re.compile("PostConversion\.HTMLOutput\.SeekReadPointerInBytes\(\d+\)"), "", string)
  string = re.sub(re.compile("PostConversion\.HTMLOutput\.ReadByteString\(.*"),'document.get_data_stream("body_html", "converter").read().replace("\\\\n", "")',string)

  string = re.sub(re.compile("PostConversion\.Text\.ReadString\(.*"),'document.get_data_stream("body_text", "converter").read().replace("\\\\n", "")',string)
  #search
  #\.search\(
  string = re.sub(re.compile("\.search\(") ,".index(" ,string)
  #print (string)
  #concat
  string = re.sub(re.compile("(\w*) = (\w*)\.concat\((\S*)\)") ,"\\1 += \\3" ,string)
  #shift
  string = re.sub(re.compile("\.shift\(\)") ,".pop(0)" ,string)
  #Round
  string = re.sub(re.compile("Math\.round\((.[^\)]*)\)") ,"round(\\1)" ,string)
  #fix if not
  string = re.sub(re.compile("([\w\.]*) not = (\w*)") ,"not \\1 == \\2" ,string)
  #indexof
  string = re.sub(re.compile(".indexOf\((\w+)\)") ,".find(\\1)" ,string)
  string = re.sub(re.compile(".indexOf\((\w+), (\w+)\)") ,".find(\\1,\\2)" ,string)
  string = re.sub(re.compile("\.indexOf\("),".find(",string)
  #regexp
  string = re.sub(re.compile("new RegExp\((.*[\"]), \"(\w+)\"\)") ,"r\\1 #\\2" ,string)
  string = re.sub(re.compile("new RegExp\((.*), \"(\w+)\"\)") ,"re.compile(\\1) #\\2" ,string)
  string = re.sub(re.compile("new RegExp\((.*[\"])\)") ,"r\\1" ,string)
  string = re.sub(re.compile("new RegExp\((.*)\)") ,"re.compile(\\1)" ,string)
  #match
  string = re.sub(re.compile("(\w+).match\(\/(.*)\/(.*)\):"),"re.search(\"\\2\",\\1):", string)
  string = re.sub(re.compile("(\w+).match\((.*)\)"),"re.search(\\1,\\2)", string)
  #exec
  string = re.sub(re.compile("(\w+).exec\((.*)\)"),"re.search(\\1,\\2)", string)
  #join
  string = re.sub(re.compile("(\w+)\.join\((.*?)\)"),"\\2.join(\\1)", string)
  #lastindexof
  string = re.sub(re.compile("(\w+)\.lastIndexOf\((.*)\)"),"\\1.rindex(\\2)", string)
  #substring
  string = re.sub(re.compile("(\w+)\.substring\((.*),(.*)\)"),"\\1[\\2:\\3]", string)
  string = re.sub(re.compile("(\w+)\.substring\((.*)\)"),"\\1[\\2:]", string)
  #toString
  string = re.sub(re.compile("(\w*)\.toString\(\)"),"str(\\1)", string)
  #typeof
  string = re.sub(re.compile("typeof (.*) (is|==) ([not ]*)'(\w+)'"),"\\3 instance(\\1,\\4)", string)
  #long text
  string = re.sub(re.compile("' \+\n( *)'"),"\\\\n\"\n\\1\"", string)
  string = re.sub(re.compile("'(.*\")\n([\S\s\n]*?)'"),"(\"\\1\n\\2\")", string)
  #string = re.sub(re.compile("\"(.*?)\"(.*?)\"(.*)\n"),"\"\\1\\\"\\2\\\"\\3\n", string)
  string = re.sub(re.compile("=\"(.*?)\""),"=\\\"\\1\\\"", string)
  string = re.sub(re.compile("= r \""),"= r\"", string)
  string = re.sub(re.compile("RegExp.\$(\d)"),"CHANGETHIS.group(\\1)", string)
    #or
  string = re.sub(re.compile("\|\|[ ]*\n" ) ,"  or " ,string) 
  string = re.sub(re.compile("//(.*)[^;]\n" ) ,"# \\1 \n" ,string) # remove all occurance singleline comments (//COMMENT\n ) from string
  string = re.sub(re.compile(" is not None:"), ":", string)
  addcode = "import re\n\n"
  #add scripts
  if addWriteOutput:
    addcode += ("def WriteOutput(text):\n# Get the Body Text holder\n"
               "  bodytext = document.DataStream('body_text')\n"
               "  # Write to the bodytext holder\n"
               "  bodytext.write(text)\n"
               "  # Add the datastream back in\n"
               "  document.add_data_stream(bodytext)\n")
  if addWriteHTMLOutput:
    addcode += ("def WriteHTMLOutput(text):\n# Get the Body HTML holder\n"
               "  bodytext = document.DataStream('body_html')\n"
               "  # Write to the bodytext holder\n"
               "  bodytext.write(text)\n"
               "  # Add the datastream back in\n"
               "  document.add_data_stream(bodytext)\n")
  string = addcode + "\n\n"+string

  #print (string)
  return string

def checkScriptFields(myconfig,filename, sourcename):
  #Checks existing fields, any custom scripts will be outputted
  global actionlist
  report = ""
  #print (myconfig)
  for field in myconfig:
    values = myconfig[field]
    #print (fieldcontent)
    #for values in fieldcontent:
    #print (values)
    if values['contentType']=="CUSTOM_SCRIPT":
      report += "\n\tCUSTOM SCRIPT: "+values['name']+", in: "+filename+"_"+values['name']+".js\n"
      report += "\n\tCUSTOM SCRIPT: "+values['name']+", in: "+filename+"_"+values['name']+".py\n"
      #report += values['customScriptContent']
      #report += "\n==================================================\n"
      current = values['customScriptContent']
      mytype=""
      #Check for big problems
      if 'Mutex.AcquireLock' in current:
       mytype = "AQLOCK_"+mytype
      if 'GetGlobalVariable' in current:
       mytype = "GLOBAL_"+mytype
      if 'ActiveXObject' in current:
       mytype = "ACTIVEX_"+mytype
      file = open("output/"+filename+"_"+values['name']+".js","w" )
      file.write(values['customScriptContent'])
      file.close()
      file = open("output/"+mytype+filename+"_"+values['name']+".py","w" )
      file.writelines(toPython(current, mytype+filename+"_"+values['name']+".py"))
      file.close()
      actionlist += "\n\n\tMigrate/validate python script: "+mytype+filename+"_"+values['name']+".py"
      actionlist += "\n\tAdd it as IPE to your Cloud V2 Organization"
      actionlist += "\n\tAssign it to source: "+sourcename+"\n"
      #Now create the python translation
      #Python translation
  return report

def yes_or_no(question):
    reply = str(input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return yes_or_no("Uhhhh... please enter ")

def createSource(client, myconfig):
  sourceid=""
  response = client.source_create(myconfig)
  if 'id' in response:
    sourceid = response["id"]
  else:
    sourceid = "ERROR: "+response["message"]
  return sourceid

if __name__ == '__main__':

    import doctest
    if doctest.testmod().failed > 0:
        exit(-1)
    finalreport=""
    actionlist=""

    parser = argparse.ArgumentParser(description='Migrate fields configuration from CloudV1 to CloudV2')
    parser.add_argument('--env', required=True, type=Environment, choices=list(Environment))
    parser.add_argument('--v1_org_id', required=True)
    #parser.add_argument('--v1_source_name', required=False)
    parser.add_argument('--v1_access_token', required=True)
    parser.add_argument('--v2_org_id', required=True)
    #parser.add_argument('--v2_source_id', required=True)
    parser.add_argument('--v2_access_token', required=True)
    parser.add_argument('--delete_fields', action='store_true')
    opts = parser.parse_args()
    functionstocall = []
    # args
    env = opts.env
    v1_org_id = opts.v1_org_id
    #v1_source_name = opts.v1_source_name
    v1_access_token = opts.v1_access_token
    v2_org_id = opts.v2_org_id
    #v2_source_id = opts.v2_source_id
    v2_access_token = opts.v2_access_token
    delete_fields = opts.delete_fields

    v1_client = CloudV1(env, v1_org_id, v1_access_token)
    v2_client = CloudV2(env, v2_org_id, v2_access_token)

    v1_sources = v1_client.sources_get()
    if "message" in v1_sources:
      print ("Bad stuff is happening in V1: "+json.dumps(v1_sources))
      exit
    v2_sources = v2_client.sources_get()
    if "message" in v2_sources:
      print ("Bad stuff is happening in V2: "+json.dumps(v2_sources))
      exit



    #remove sources from v2
    print("Removing V2 sources.")
    if yes_or_no("Delete V2 sources first?"):
      for source in v2_sources:
        result = json.dumps(v2_client.sources_delete(source["id"]))
        if 'sourceType' in result:
          print("Removing: "+source["id"]+", DONE")
        else:
          print("Removing: "+source["id"]+", ERROR: "+result)
      input("Press Enter to continue... (wait a bit so all sources in v2 are removed")

    finalreport+="Migration of:\n"
    finalreport+="Organization: "+v1_org_id+" (V1) --> "+v2_org_id+" (V2)\n"
    actionlist = finalreport


    #Report sources found
    for source in v1_sources['sources']:
      sourcename=""
      if 'name' in source:
        sourcename = source['name']
      else:
        sourcename = source["id"]
      #input("Press Enter to continue... Creating source: "+sourcename)
      actionlist += "\n\nSource: "+sourcename
      finalreport+="\n\n====================================================================================\nSource name : "+sourcename+"\n"
      print (f'\n=================================================\nSource name: {sourcename}')
      print (f'Source id: {source["id"]}')
      print (f'V1 config:')
      raw = v1_client.source_get(source["id"])
      v1_fields = v1_get_fields_by_name(v1_client.fields_get_for_source(source["id"]))
      #print(f'Fields present in CloudV1 ({len(v1_fields)}): {v1_fields}')
      adddisable="_DISABLED_"      
      disabled = False
      if raw["platformStatus"] =="DISABLED":
        print (f'Skipping, disabled')
        finalreport+= "\tSOURCE DISABLED, SKIPPING"
        actionlist += "\n\tDisabled, not migrated"
        filename = re.sub('[^A-Za-z0-9_]+', ' ',v1_org_id+"_"+sourcename+adddisable)
        disabled = True
      else:
        filename = re.sub('[^A-Za-z0-9_]+', ' ',v1_org_id+"_"+sourcename)
      file = open("output/"+filename+".json","w" )
      file.write(json.dumps(raw, indent=4, sort_keys=True))
      file.close()
      if not disabled:
        #print (f'=========================================================================================')
        #print (f'V2 config:')
        v2source = transformV1ToV2(raw)
        report=""
        addfile=""
        addSource=True
        if v2source["sourceType"]=="BAD":
          addfile +="_NO_LONGER_SUPPORTED_"
          report += "\tSource: "+sourcename+" NO LONGER SUPPORTED!!!\n\n"
          actionlist += "\n\tNO LONGER SUPPORTED, contact PS"
          addSource=False
          #finalreport+="   Remark      : "+addfile+"\n"
        if v2source["sourceType"]=="MAN":
          addfile+="_CANNOT BE CREATED DO IT MANUAL_"
          report += "\tSource: "+sourcename+" CANNOT BE CREATED, DO IT MANUAL!!!\n\n"
          actionlist += "\n\tCannot be automatically converted, must be manually created"
          addSource=False
          #finalreport+="   Remark      : "+addfile+"\n"
        if raw["editable"]==False:
          addfile+="_BACKEND CHANGES CONTACT OPS_"
          report += "\tSource: "+sourcename+" HAS BACKEND CHANGES, CONTACT OPS!!!\n\n"
          actionlist += "\n\tHas backend changes, must be manually configured, contact OPS for changes."
          addSource=False
          #finalreport+="   Remark      : "+addfile+"\n"
        file = open("output/"+filename+addfile+"_V2.json","w" )
        file.write(json.dumps(v2source, indent=4, sort_keys=True))
        file.close()

        SFDCChanges = inspectSFDC(raw)
        if SFDCChanges:
          finalreport+= "\tSalesforce source contains custom settings, see REMARKS file.\n"
          actionlist += "\n\t(Salesforce) contains custom settings, see REMARKS file, adjust your configuration."

        report += checkScriptFields(v1_fields,filename, sourcename)
        finalreport+= report
        if report:
          file = open("output/"+filename+"_REMARKS.txt","wb" )
          file.write(report.encode('utf-8'))
          file.close()
        #Create source in v2
        #Get source id
        if addSource:
          v2_source_id = createSource(v2_client, v2source)
          if "ERROR" in v2_source_id:
            finalreport+= "\tERROR AT CREATING SOURCE IN V2: "+v2_source_id
            print (f'Error: {v2_source_id}')
            actionlist += "\n\tCould not be created, create it manually."
          else:
            finalreport+= "\tNew source id in V2: "+v2_source_id
            print (f'New ID: {v2_source_id}')
            #Transfer fields from v1 to v2
            print("Adding fields to V2")
            v2_mappings = v2_get_mappings_fieldname(v2_client.mappings_get(v2_source_id))
            common_fields = [v2_mapping for v2_mapping in v2_mappings if v2_mapping in v1_fields.keys()]
            #print(f'Common field names between v1 and v2 ({len(common_fields)}): {common_fields}')
            v2_fields_by_name = v2_get_fields_in_use(v2_client.fields_get(), v2_mappings)
            #print(f'Fields to compare in v2 ({len(v2_fields_by_name)}): {v2_fields_by_name}')
            fields_difference_to_apply = get_fields_differences(v1_fields, v2_fields_by_name)
            #print(f'Found {len(fields_difference_to_apply)} fields to update: {fields_difference_to_apply}')

            v2_fields_updated = v2_get_updated_fields(fields_difference_to_apply)
            if v2_fields_updated:
                #print(f'CloudV2 fields to update ({len(v2_fields_updated)}): {v2_fields_updated}')
                finalreport += "\n\tFields updated: "+json.dumps(v2_fields_updated)
                result = v2_client.fields_update(v2_fields_updated)
                if result==None:
                  finalreport += "\n\tFields succesfully added"
                else:
                  finalreport += "\n\tError: " + json.dumps(result)
                  actionlist += "\n\tField creation failed, check logs."
            else:
                print('No fields to update.')
            #------------------------------------------------------------------------
            #Get Schedules and create them
            #First get the just created schedule and remove it
            v2_schedules = v2_client.schedule_get(v2_source_id)
            for schedule in v2_schedules:
              print ("Removing schedule: "+schedule['id'])
              v2_client.schedule_delete(v2_source_id, schedule['id'])
            #Removed, get the v1 schedules
            v1_schedules = v1_client.schedules_get(source["id"])
            for schedule in v1_schedules:
              schedule["scheduleType"]="SOURCE"
              schedule["refreshType"]=schedule["type"]
              schedule["type"]=""
              #set enabled to false
              schedule["enabled"]=False
              schedule["id"]=""
              #print (json.dumps(schedule))
              addedschedule= v2_client.schedule_create(v2_source_id, schedule)
              if 'id' in addedschedule:
                finalreport += "\n\tNew schedule added: "+addedschedule['id']
                actionlist += "\n\tEnable schedule with id: "+addedschedule['id']
              else:
                finalreport += "\n\tError in adding schedule: "+schedule['name']
                actionlist += "\n\tSchedule creation failed, check logs."

      #Create custom fields in v2
      #print (f'=========================================================================================')

    #Add custom fields
    finalreport+="\n====================================================================================\n"
    dry_run=False
    if yes_or_no("Continue with fields and pipelines?"):
      v1_user_fields = [field for field in v1_client.fields_get() if v1_field_is_user(field)]
      v1_user_fields_unique = v1_get_unique_fields(v1_user_fields)
      print (v1_user_fields_unique)
      copy_user_fields(v1_user_fields_unique, v2_client, dry_run)
      print('All users fields copied.')

      v1_fields_mapping = list(itertools.chain.from_iterable([field_list[1]['mappings'] for field_list in v1_user_fields_unique]))
      v2_create_mapping_from_v1_fields(v2_client, v1_client.sources_get(), v1_fields_mapping, v2_client.sources_get(), dry_run)
      finalreport+= "\n\nUser Fields updated: "+json.dumps(v1_fields_mapping).replace('{"name":','\n{"name":')
      print('All mappings created.')

      

      #Pipelines -----------------------------------------------------------------------------------------------
      #{'id': 'b1bf1ba5-0d6d-4c0b-923c-df388e4b0f87', 'name': 'Copy of besttechCommunityTuned (1)', 'isDefault': False, 
      #  'description': 'Pipeline for the besttech community with Reveal', 'filter': None, 'splitTestName': None, 
      # 'splitTestTarget': None, 'splitTestRatio': None, 'splitTestEnabled': False, 'condition': None, 'position': 27, 
      # 'last_modified_by': None, 'created_by': None}

      actionlist += "\n====================================================================="
      actionlist += "\nQuery Pipelines\n"
      print('Pipelines.')    
      print ('Deleting V2 pipelines')
      defaultpipelineid=""
      v2_pipelines = v2_client.pipelines_get()
      #if yes_or_no("Delete V2 pipelines first?"):
      for pipeline in v2_pipelines:
          #print (pipeline)
          if (pipeline["isDefault"]):
            defaultpipelineid=pipeline["id"]
          v2_client.pipeline_delete(pipeline["id"])

      #default pipeline is normally already completely empty so we do not have to do anything

      print ("Create condition statements")
      v2_statements = v2_client.statements_get()
      for statement in v2_statements["statements"]:
        #print (statement)
        print ("Deleting condition statement "+statement["id"])
        v2_client.statement_delete(statement["id"])

      v1_statements = v1_client.statements_get()
      for statement in v1_statements["statements"]:
        #print (statement)
        print ("Creating condition statement "+statement["id"])
        response = v2_client.statement_create(statement)
        if 'id' in response:
          finalreport += "Created condition statement: "+statement["id"]+" in V2 with ID: "+response["id"]
        else:
          pipelineid = "ERROR: "+response["message"]
          print (pipelineid)
          finalreport += "\nERROR in creating condition statement: "+statement["id"]+", error: "+response["message"]
          actionlist += "\nERROR in creating condition statement: "+statement["id"]+", CHECK LOGS"

          
      v1_pipelines = v1_client.pipelines_get()
      for pipeline in v1_pipelines:
        #Create pipeline in V2
        #pipeline["id"]=""
        print ("Creating pipeline "+pipeline["name"])
        #A/B Tests targets are not supported
        if pipeline["splitTestTarget"]:
          pipeline["splitTestTarget"] = None
          pipeline["splitTestName"] = None
          pipeline["splitTestRatio"] = None
          pipeline["splitTestEnabled"] = False
          actionlist += "\n\tWARNING: A/B tests are defined in pipeline: "+pipeline["name"]+", create them manually!!!"
          finalreport += "\n\tWARNING: A/B tests are defined in pipeline: "+pipeline["name"]+", create them manually!!!"
          #print (json.dumps(pipeline))
        pipelineid=""
        if pipeline["name"]=="default":
          pipelineid=defaultpipelineid
        else:
          response = v2_client.pipeline_create(pipeline)
          if 'id' in response:
            pipelineid = response["id"]
        if 'id' in response or pipeline["name"]=="default":
          #pipelineid = response["id"]
          finalreport += "\nCreated pipeline: "+pipeline["name"]+" in V2 with ID: "+pipelineid
          #get all statements
          v1_statements = v1_client.pipeline_statements_get(pipeline['id'])
          for statement in v1_statements['statements']:
            # {'id': 'c8d1b77f-a2b3-475d-9b85-ff5d144e47d9', 'description': '', 'feature': 'top', 
            # 'definition': 'when $query contains `enable netflix` then top `@sysurihash="YShRcUQrh1TvHQ3E"`', 
            # 'parent': {'id': '4c9a2e17-f04a-4fbb-a99c-a71813d05b80', 'description': '', 'definition': 'when $searchHub is "AgentPanel"', 
            # 'detailed': {'condition': {'operator': 'is', 'left': {'object': 'searchHub'}, 'right': 'AgentPanel'}}, 'childrenCount': 0, 
            # 'feature': 'when', 'parent': None, 'condition': None, 'position': 0, 'ready': True},
            #  'condition': {'id': '4c9a2e17-f04a-4fbb-a99c-a71813d05b80', 'description': '', 'definition': 'when $searchHub is "AgentPanel"', 
            # 'detailed': {'condition': {'operator': 'is', 'left': {'object': 'searchHub'}, 'right': 'AgentPanel'}}, 
            # 'childrenCount': 0, 'feature': 'when', 'parent': None, 'condition': None, 'position': 0, 'ready': True}, 
            # 'position': 14, 'ready': False, 'detailed': {'condition': {'operator': 'contains', 'left': {'object': 'query'}, 'right': 'enable netflix'}, 
            # 'statement': {'expressions': ['@sysurihash="YShRcUQrh1TvHQ3E"']}}, 'childrenCount': 0}
            #Create statement in V2
            #print (statement)
            #Get The details
            statement = (v1_client.pipeline_statement_details_get(pipeline["id"], statement["id"]))
            if "parent" in statement:
              if statement["parent"]:
                if "id" in statement["parent"]:
                  statement["parent"]=statement["parent"]["id"]
            print ("Creating pipeline - statement "+pipeline["name"]+"("+pipelineid+"), "+statement["id"])
            #statement["id"]=""
            #print (json.dumps(statement))
            response = v2_client.pipeline_statement_create(pipelineid, statement)
            if 'id' in response:
              statementid = response["id"]
              finalreport += "\nCreated statement: "+pipeline["name"]+" in V2 with ID: "+statementid
            else:
              statementid = "ERROR: "+response["message"]
              print (statementid)
              finalreport += "\nERROR in creating query pipeline - STATEMENT: "+pipeline["name"]+" ("+pipeline["id"]+"), error: "+response["message"]
              actionlist += "\nERROR in creating query pipeline - STATEMENT: "+pipeline["name"]+" ("+pipeline["id"]+"), CHECK LOGS"


        else:
          pipelineid = "ERROR: "+response["message"]
          print (pipelineid)
          finalreport += "\nERROR in creating query pipeline: "+pipeline["name"]+", error: "+response["message"]
          actionlist += "\nERROR in creating query pipeline: "+pipeline["name"]+", CHECK LOGS"



    finalreport+="\n====================================================================================\n"
    finalreport+="\nDimensions\n"
    print ('Migrate dimensions')
    v1_dimensions = v1_client.dimensions_get()
    for dimension in v1_dimensions:
      #print (json.dumps(dimension))
      # {    "type": "TEXT",    
      # "displayName": "Facet Value",    
      # "apiNames": [      "CUSTOM_EVENTS.C_FACETVALUE"    ],    
      # "returnName": "custom_events.c_facetvalue",    
      # "custom": true,    
      # "availableInVisit": true,    
      # "eventTypes": [      "custom_events"    ],    
      # "status": "AVAILABLE"  },    

      #{
      #   "type": "TEXT",
      #   "displayName": "string"
      # }
      if dimension["custom"]:
        name = dimension["returnName"]
        events = dimension["eventTypes"]
        myevent = ""
        for event in events:
          #Create Dimension
          myevent+="&event="+event
        mydimension={}
        mydimension["type"] = dimension["type"]
        mydimension["displayName"] = dimension["displayName"]
        if '.' in name:
          name = name.split('.')[1]
        #print (name)
        
        result = v2_client.dimension_create(name,myevent,mydimension)
        if 'type' in result:
          finalreport += '\nDimension '+dimension["displayName"]+', created'
        else:
          finalreport += '\nERROR in creating Dimension '+dimension["displayName"]+', '+result["message"]
          print ('\nERROR in creating Dimension '+dimension["displayName"]+', '+result["message"])
          actionlist += '\nERROR in creating Dimension '+dimension["displayName"]+', CHECK LOGS'



    print('Migration completed.')    
    finalreport+="\n====================================================================================\n"
    finalreport += "Actions needed:\n"
    finalreport += actionlist
    finalreport+="\n====================================================================================\n"
    file = open("output/"+v1_org_id+"_FINALREPORT.txt","wb" )
    file.write(finalreport.encode('utf-8'))
    file.close()
    file = open("output/"+v1_org_id+"_ACTIONLIST.txt","wb" )
    file.write(actionlist.encode('utf-8'))
    file.close()
    print ("Ready...")
    print("Functions to call:")
    for function in functionstocall:
      print (function)
"""
    v1_source_id = v1_get_source_id(v1_sources['sources'], v1_source_name)

    v2_mappings = v2_get_mappings_fieldname(v2_client.mappings_get(v2_source_id))
    print(f'Mapping present in CloudV2 ({len(v2_mappings)}): {v2_mappings}')

    common_fields = [v2_mapping for v2_mapping in v2_mappings if v2_mapping in v1_fields.keys()]
    print(f'Common field names between v1 and v2 ({len(common_fields)}): {common_fields}')

    v2_fields_by_name = v2_get_fields_in_use(v2_client.fields_get(), v2_mappings)
    print(f'Fields to compare in v2 ({len(v2_fields_by_name)}): {v2_fields_by_name}')

    fields_difference_to_apply = get_fields_differences(v1_fields, v2_fields_by_name)
    print(f'Found {len(fields_difference_to_apply)} fields to update: {fields_difference_to_apply}')

    v2_fields_updated = v2_get_updated_fields(fields_difference_to_apply)
    if v2_fields_updated:
        print(f'CloudV2 fields to update ({len(v2_fields_updated)}): {v2_fields_updated}')
        v2_client.fields_update(v2_fields_updated)
    else:
        print('No fields to update.')
    print('Migration completed.')    

    #Deleting unused fields
    if delete_fields:
        unused_fields = get_unused_fields(v2_client.fields_get_with_mappings())
        print('Deleting fields ' + unused_fields)
        v2_client.fields_delete(unused_fields)
        print('Field deletion completed.')"""