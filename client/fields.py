

class Fields:
    @staticmethod
    def v1_to_v2(v1_field: dict):
        #fix problem with multivalueFacet and facet
        myfacet = v1_field['facet']
        mymultiFacet = v1_field['multivalueFacet']
        if myfacet and mymultiFacet:
          myfacet = False
        #fix date, if date, sorted must be true
        mysort = v1_field['sort']
        if v1_field['fieldType']=='DATE' or v1_field['fieldType']=='INTEGER' or v1_field['fieldType']=='DOUBLE' or v1_field['fieldType']=='LONG_64':
          mysort = True
        myfieldtype = v1_field['fieldType']
        #fix field types
        if myfieldtype=='INTEGER':
          myfieldtype='LONG'
        
        return {'facet': myfacet,
                'sort': mysort,
                'includeInQuery': v1_field['fieldQueries'],
                'includeInResults': v1_field['displayField'],
                'mergeWithLexicon': v1_field['freeTextQueries'],
                'multiValueFacet': mymultiFacet,
                'name': v1_field['name'].lower(),
                'system': False,
                'multiValueFacetTokenizers':';',
                'type': myfieldtype,
                'description': 'migrationFromCloudV1'}
