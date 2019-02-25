# coveo-cloud-v2-migration-tools
Coveo Cloud V2 Migration Tools

## Full Migration
Copy Sources, fields, mappings, schedules, conditions, query pipelines, custom dimensions from a CloudV1 to a CloudV2 organization
After specifying the proper parameters the script will first get all sources from Cloud V1, and from Cloud V2.


Then for every source found in V1:
- In the output\ directory you will find:
  - ORG_SOURCENAME.json (the json we got from Cloud V1)
  - ORG_SOURCENAME_V2.json (the json we are pushing into Cloud V2)
- Check status of V1 source
  - If Disabled: will be skipped
  - If Edited (in the back-end): will be skipped
- Create a proper JSON for V2
- Create a new source in V2
- Check if there are custom fields defined for Salesforce, if so report them
- Check if there are custom script fields (with JScript) defined
  - Output them to OUTPUT\ORG_SOURCE_Scriptname.js
  - Translate them to python in OUTPUT\ORG_SOURCE_Scriptname.py (Remark: this is an attempt, never 100% accurate!!!)
- Get all custom fields from V1
  - Apply them to V2
- Get all schedules from V1
  - Apply them to V2 and put them on ‘Disabled’

When done:
- Get all user defined fields from V1
  - Apply them to V2
- Get all mappings from V1
  - Apply them to V2
- Get all condition statements from V1
  - Apply them to V2
- Get all query pipelines from V1
  - If the pipeline contains splittestnames, remove them
  - Apply pipeline to V2
  - Get all statements for the pipeline from V1
    - Apply them to V2
- Get all Custom Dimensions (Analytics) from V1
  - Apply them to V2
- Any exceptions/errors are logged into the OUTPUT\ORG_FinalReport.txt file
- An actionlist is created with actions to perform in OUTPUT\ORG_ActionList.txt file

### Installation
```python
pip install jiphy
pip install jsbeautifier
```

### Execution
* Create a new V2 Org: EXACT NAME (See above: Organization Name), If the name is not the same, analytics of Cloud V1 cannot be used!!!!
* Execute the following script:
`migrate_v1_to_v2.py --env {DEV,QA,PROD} --v1_org_id V1_ORG_ID --v1_access_token V1_ACCESS_TOKEN --v2_org_id 
V2_ORG_ID --v2_access_token V2_ACCESS_TOKEN `
* REMARK: --env is lowercase!! (dev, qa, prod)
* Look into output\ORG_FinalReport.txt for errors
* Look into output\ORG_ActionList.txt for next steps

## Partial Migration

### Migrate the settings of fields used in a CloudV1 source to CloudV2

`migrate_fields_config.py --env {DEV,QA,PROD} --v1_org_id V1_ORG_ID --v1_source_name V1_SOURCE_NAME 
--v1_access_token V1_ACCESS_TOKEN --v2_org_id V2_ORG_ID --v2_source_id V2_SOURCE_ID --v2_access_token V2_ACCESS_TOKEN
[--delete_fields]`

### Copy user fields from a CloudV1 to a CloudV2 organization

`copy_user_fields.py --env {DEV,QA,PROD} --v1_org_id V1_ORG_ID --v1_access_token V1_ACCESS_TOKEN --v2_org_id 
V2_ORG_ID --v2_access_token V2_ACCESS_TOKEN [--dry-run]`

