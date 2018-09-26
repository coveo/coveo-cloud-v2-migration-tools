

class Fields:
    @staticmethod
    def v1_to_v2(v1_field: dict):
        return {'facet': v1_field['facet'],
                'sort': v1_field['sort'],
                'includeInQuery': v1_field['fieldQueries'],
                'includeInResults': v1_field['displayField'],
                'mergeWithLexicon': v1_field['freeTextQueries'],
                'multiValueFacet': v1_field['multivalueFacet'],
                'name': v1_field['name'].lower(),
                'system': False,
                'type': v1_field['fieldType'],
                'description': 'migrationFromCloudV1'}
