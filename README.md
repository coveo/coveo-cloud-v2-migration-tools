# coveo-cloud-v2-migration-tools
Coveo Cloud V2 Migration Tools

Migrate the settings of fields used in a CloudV1 source to CloudV2

 `migrate_fields_config.py --env {DEV,QA,PROD} --v1_org_id V1_ORG_ID
                                --v1_source_name V1_SOURCE_NAME
                                --v1_access_token V1_ACCESS_TOKEN --v2_org_id
                                V2_ORG_ID --v2_source_id V2_SOURCE_ID
                                --v2_access_token V2_ACCESS_TOKEN                                --delete_fields [OPTIONAL_PARAMETER_TO_DELETE_UNUSED_FIELDS]`

Copy user fields from a CloudV1 to a CloudV2 organization
`copy_user_fields.py --env {DEV,QA,PROD} --v1_org_id V1_ORG_ID --v1_access_token V1_ACCESS_TOKEN --v2_org_id 
V2_ORG_ID --v2_access_token V2_ACCESS_TOKEN`
                                