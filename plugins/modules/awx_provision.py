#!/usr/bin/python

# Copyright: (c) 2020, Maxim Generalov <maxim.generalov@netdevopsx.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: awx_provision

short_description: Provision AWX configuration

version_added: "2.5"

description:
    - "Provision configuration of AWX based on inventory"

options:
    config - configuration of AWX

author:
    - Maxim Generalov (@generalovmaksim)
'''

EXAMPLES = '''
# provision AWX
- name: AWX Provision
  awx_provision:
    config: "{{ ansible_tower }}"


'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The output message that the test module generates
    type: str
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types
from ansible.errors import AnsibleFilterError

import json,re,jmespath,os
import requests,time

class Tower_rest:

    def __init__(self, host_url, rest_user, rest_password):

        # Retrieve the parameters passed in
        self.host_url      = host_url
        self.rest_user     = rest_user
        self.rest_password = rest_password

    def get(self,api_uri,dict_key = ''):

        # Initialize the output list to empty
        rest_output = []

        while api_uri != None:
            r = requests.get(
                '{0}{1}'.format(self.host_url, api_uri),
                auth=(self.rest_user, self.rest_password),
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                verify=False
                )

            # Fetch the next URI returned by the REST call
            # TODO: better error handling when REST service returns non-200 OK
            api_uri = r.json().get('next',None)

            # Merge the results json to the output list of items
            if dict_key in r.json():
                rest_output = rest_output + r.json().get(dict_key)
            else:
                rest_output = r.json()
        
        return(rest_output)

    def update(self, url_path: str, method: str, body: dict):

        rjson  = dict()
        url    = '{0}{1}'.format(self.host_url, url_path)
        data   = json.dumps(body)

        if (not body and method in ('POST','PATCH')) and body != {} :
            raise Warning("Body of the object is empty, path: {0}".format(url))

        if method=='PATCH':
            r = requests.patch(
                url=url,
                auth=(self.rest_user, self.rest_password),
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                verify=False
                )
            rjson = r.json()

        elif method=='DELETE':
            r = requests.delete(
                url=url,
                auth=(self.rest_user, self.rest_password),
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                verify=False
                )
            rjson = r.json() if r.text else dict()

        elif method=='POST':
            r = requests.post(
                url=url,
                auth=(self.rest_user, self.rest_password),
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                verify=False
                )
            rjson = r.json() if r.text else dict()
        
        if not r.ok:
            raise Warning(f'Method: {method}: {url} {r.json} {data} {r.text}')
        else:
            return rjson

class Tower_provison:
    
    def __init__(self, tower_configuration):

        self.input_configuration = tower_configuration
        self.tower_connect = Tower_rest(tower_configuration['url'], tower_configuration['admin_username'], tower_configuration['admin_password'])
        self.config_desired = {}
        self.config_current = {}
        self.results = list()
        self.tower_settings = {
            'LOG_AGGREGATOR_HOST'       : { 'default': None },
            'LOG_AGGREGATOR_PASSWORD'   : { 'default': '' },
            'AUTH_LDAP_START_TLS'       : { 'default': False },
            'AUTH_LDAP_SERVER_URI'      : { 'default': '' },
            'AUTH_LDAP_BIND_DN'         : { 'default': '' },
            'AUTH_LDAP_BIND_PASSWORD'   : { 'default': '' },
            'AUTH_LDAP_GROUP_TYPE'      : { 'default': 'MemberDNGroupType' },
            'AUTH_LDAP_REQUIRE_GROUP'   : { 'default': '' },
            'AUTH_LDAP_USER_SEARCH'     : { 'default': [] },
            'AUTH_LDAP_USER_ATTR_MAP'   : { 'default': {} },
            'AUTH_LDAP_GROUP_SEARCH'    : { 'default': [] },
            'AUTH_LDAP_GROUP_TYPE_PARAMS'   : { 'default': {
                "name_attr": "cn",
                "member_attr": "member"
                }
            },
            'AUTH_LDAP_USER_FLAGS_BY_GROUP' : { 'default': {} },
            'AUTH_LDAP_ORGANIZATION_MAP'    : { 'default': {} },
            'AUTH_LDAP_TEAM_MAP'            : { 'default': {} },
            'AWX_TASK_ENV'                  : { 'default': '' },
            'AWX_PROOT_SHOW_PATHS'          : { 'default': [] }
            }
        self.sync_order = (
            'organizations',
            'teams',
            'inventories',
            'credential_types',
            'credentials',
            'projects',
            'inventory_sources',
            'job_templates',
            'workflow_job_templates',
            'workflow_job_template_nodes'
        )
        self.objects_structure = {
            'organizations': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' }
                }
            },
            'inventories': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' }
                },
                "links": {
                    'organization'            : { 'target': 'organizations' }
                },
                "object_roles" : { 
                    "Admin": {},
                    "Update": {},
                    "Ad Hoc": {},
                    "Use": {},
                    "Read": {}
                 }
            },
            'teams': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' }
                },
                "links": {
                    'organization'            : { 'target': 'organizations' }
                }
            },
            'credential_types': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                    'kind'                    : { 'default': 'cloud' },
                    'managed_by_tower'        : { 'default': False },
                    'inputs'                  : { 'default': {} },
                    'injectors'               : { 'default': {} }
                }
            },
            'credentials': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                    'inputs'                  : { 'default': {} },
                },
                "links": {
                    'credential_type'         : { 'target': 'credential_types' },
                    'organization'            : { 'target': 'organizations' }
                },
                "object_roles" : { 
                    "Admin": {},
                    "Use": {},
                    "Read": {}
                 }
            },
            'projects': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                    'custom_virtualenv'       : { 'default': None },
                    'scm_branch'              : { 'default': 'master' },
                    'scm_type'                : { 'default': 'git' },
                    'scm_url'                 : { 'default': '' }, 
                    'scm_update_on_launch'    : { 'default': False }, 
                    'scm_delete_on_update'    : { 'default': False }, 
                    'scm_update_cache_timeout': { 'default': 0 }, 
                    'timeout'                 : { 'default': 0 } 
                },
                "links": {
                    'credential'              : { 'target': 'credentials' },
                    'organization'            : { 'target': 'organizations' }
                },
                "object_roles" : { 
                    "Admin": {},
                    "Use": {},
                    "Update": {},
                    "Read": {}
                 }
            },
            'inventory_sources': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                    'source'                  : { 'default': 'scm' },
                    'source_path'             : { 'default': '' },
                    'overwrite'               : { 'default': True },
                    'update_on_launch'        : { 'default': False },
                    'update_cache_timeout'    : { 'default': 0 },
                    'update_on_project_update': { 'default': 0 },
                    'custom_virtualenv'       : { 'default': False }
                },
                "links": {
                    'source_project'          : { 'target': 'projects' },
                    'inventory'               : { 'target': 'inventories' },
                    'credential'              : { 'target': 'credentials' }
                },
                "schedules": {
                    'name'                    : { 'default': '' },
                    'enabled'                 : { 'default': False },
                    'rrule'                   : { 'default': '' }
                }
            },
            'job_templates': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                    'job_type'                : { 'default': 'run' },
                    'custom_virtualenv'       : { 'default': None },
                    'allow_simultaneous'      : { 'default': False },
                    'ask_variables_on_launch' : { 'default': False },
                    'use_fact_cache'          : { 'default': False },
                    'forks'                   : { 'default': 0 },
                    'survey_enabled'          : { 'default': False },
                    'playbook'                : { 'default': '' }
                },
                "links": {
                    'inventory'               : { 'target': 'inventories' },
                    'project'                 : { 'target': 'projects' }
                },
                'surveys' : {
                    'question_name'           : { 'default': '' },
                    'question_description'    : { 'default': '' },
                    'required'                : { 'default': True },
                    'type'                    : { 'default': '' },
                    'variable'                : { 'default': '' },
                    'min'                     : { 'default': 0  },
                    'max'                     : { 'default': 1024 },
                    'default'                 : { 'default': '' },
                    'choices'                 : { 'default': '' },
                    'new_question'            : { 'default': True }
                },
                "schedules": {
                    'name'                    : { 'default': '' },
                    'enabled'                 : { 'default': False },
                    'rrule'                   : { 'default': '' }
                },
                "credentials"                 : { 'default': list() },
                "object_roles" : { 
                    "Admin": {},
                    "Execute": {},
                    "Read": {}
                 }
            },
            'workflow_job_templates': {
                'key' : 'name',
                'id': '',
                "leafs": {
                    'name'                    : { 'default': '' },
                    'description'             : { 'default': '' },
                },
                "links": {
                    'organization'            : { 'target': 'organizations' }
                },
                "schedules": {
                    'name'                    : { 'default': '' },
                    'enabled'                 : { 'default': False },
                    'rrule'                   : { 'default': '' }
                }
            },
            'workflow_job_template_nodes': {
                'key' : 'identifier',
                'id': '',
                "leafs": {
                    'identifier'              : { 'default': '' },
                    'extra_data'              : { 'default': '' }
                },
                "links": {
                    'workflow_job_template'   : { 'target': 'workflow_job_templates' },
                    'unified_job_template'    : { 'target': 'job_templates' }
                }
            }
        }

    def tower_settings_update(self):

        current_settings = self.tower_connect.get('/api/v2/settings/all/')
        for key, value in self.tower_settings.items():
            value_desired = self.input_configuration['settings'].get(key, value['default'])
            value_current = current_settings[key]
            if value_desired != value_current:
                change = ('/api/v2/settings/all/', "PATCH", {key: value_desired})
                self.tower_connect.update(*change)  
                self.results.append('Updated: Settings ID: {0}'.format(key))


    def read_objects_from_tower(self, object_type: str):

        # Clean up all objects of proper type from config_current
        # since it will be overwritten
        self.config_current[object_type] = list()

        tower_objects = self.tower_connect.get('/api/v2/{0}/'.format(object_type),'results')
        
        for tower_object in tower_objects:

            filtered_object = dict()
            
            # ID
            if tower_object.get('id'):
                filtered_object['id'] = tower_object.get('id')

            # Leafs
            for leaf in self.objects_structure[object_type].get('leafs',{}):
                filtered_object[leaf] = tower_object.get(leaf)
            
            # Links
            for link in self.objects_structure[object_type].get('links',{}):
                filtered_object[link] = tower_object.get(link)

            # Schedules
            if self.objects_structure[object_type].get('schedules'):
                
                filtered_schedules = list()
                for schedule in self.tower_connect.get('/api/v2/{0}/{1}/schedules/'.format(object_type,tower_object['id']),'results'):
                    schedule_item = dict()
                    for schedule_var in self.objects_structure[object_type].get('schedules'):
                        schedule_item[schedule_var] = schedule[schedule_var]
                    filtered_schedules.append(schedule_item)

                filtered_object['schedules'] = filtered_schedules

            # Surveys
            if self.objects_structure[object_type].get('surveys'):
                
                filtered_surveys = list()
                for survey in self.tower_connect.get('/api/v2/{0}/{1}/survey_spec/'.format(object_type,tower_object['id']),'spec'):
                    survey_item = dict()
                    for survey_var, value in self.objects_structure[object_type].get('surveys').items():
                        survey_item[survey_var] = survey.get(survey_var,value.get('default'))
                    filtered_surveys.append(survey_item)

                filtered_object['surveys'] = filtered_surveys

            # Credentials
            if self.objects_structure[object_type].get('credentials'):

                filtered_credentials = list()
                for credential in self.tower_connect.get('/api/v2/{0}/{1}/credentials/'.format(object_type,tower_object['id']),'results'):
                    credential_item = dict()
                    for credential_var in ('id','name'):
                        credential_item[credential_var] = credential[credential_var]
                    filtered_credentials.append(credential_item)

                filtered_object['credentials'] = sorted(filtered_credentials, key=lambda k: k['id'])
            
            # Object_roles
            if self.objects_structure[object_type].get('object_roles'):
                j_query = r"[].{id: id, name: name}"
                filtered_object_roles = dict()
                for object_role_v in tower_object['summary_fields']['object_roles'].values():
                    filtered_object_roles[object_role_v['name']] = {
                        "id" : object_role_v['id'],
                        "teams": jmespath.search(j_query, sorted(self.tower_connect.get('/api/v2/roles/{0}/teams/'.format(object_role_v['id']),'results'), key=lambda k: k['id']))
                    }
                filtered_object['object_roles'] = filtered_object_roles

            self.config_current[object_type].append(filtered_object)


    def read_objects_from_config(self, object_type: str):

        # Clean up all objects of proper type from config_desired
        # since it will be overwritten
        self.config_desired[object_type] = list()

        config_objects = self.input_configuration[object_type]

        for config_object in config_objects:
            
            filtered_object = dict()

            # Leafs
            for leaf in self.objects_structure[object_type].get('leafs',{}):
                filtered_object[leaf] = config_object.get(leaf, self.objects_structure[object_type]['leafs'][leaf]['default'])
            
            # Links
            for link in self.objects_structure[object_type].get('links',{}):
                if not config_object.get(link):
                    filtered_object[link] = None
                    continue
                target = self.objects_structure[object_type]['links'][link]['target']
                j_query = "[?name=='{0}'].id|[0]".format(config_object[link])
                filtered_object[link] = jmespath.search(j_query, self.config_current[target])

            # Schedules
            if self.objects_structure[object_type].get('schedules'):
                
                filtered_schedules = list()
                for schedule in config_object.get('schedules',{}):
                    schedule_item = dict()
                    for schedule_var in self.objects_structure[object_type].get('schedules'):
                        schedule_item[schedule_var] = schedule[schedule_var]
                    filtered_schedules.append(schedule_item)

                filtered_object['schedules'] = filtered_schedules

            # Surveys
            if self.objects_structure[object_type].get('surveys'):

                filtered_surveys = list()
                for survey in config_object.get('survey_spec',{}):
                    survey_item = dict()
                    for survey_var in self.objects_structure[object_type].get('surveys'):
                        default_var = self.objects_structure[object_type]['surveys'][survey_var]['default']
                        survey_item[survey_var] = survey.get(survey_var,default_var)
                    filtered_surveys.append(survey_item)

                filtered_object['surveys'] = filtered_surveys

            # Credentials
            if self.objects_structure[object_type].get('credentials'):
                filtered_credential = list()
                for credential in config_object.get('credential',[]):
                    j_query = "[?name=='{0}'].id|[0]".format(credential)
                    credential_item = dict()
                    credential_item['id'] = jmespath.search(j_query, self.config_current['credentials'])
                    credential_item['name'] = credential
                    filtered_credential.append(credential_item)

                filtered_object['credentials'] = sorted(filtered_credential, key=lambda k: k['id'])

            # object_roles
            if self.objects_structure[object_type].get('object_roles'):
                
                filtered_object_roles = dict()
                permissions_name = config_object.get('permissions',None)

                for object_role in self.objects_structure[object_type]['object_roles'].keys():
                    j_query = "[?name=='{0}'].object_roles.\"{1}\".id|[0]".format(config_object['name'],object_role)
                    object_role_id = jmespath.search(j_query, self.config_current[object_type])
                    
                    try:
                        teams_list = self.input_configuration['permissions'][object_type][permissions_name][object_role]['teams']
                    except:
                        teams_list = list()
                    
                    teams = []
                    for team in teams_list:
                        j_query_teams = "[?name=='{0}'].id|[0]".format(team)
                        teams.append({
                            "id": jmespath.search(j_query_teams, self.config_current['teams']),
                            "name": team
                        })
                    
                    filtered_object_roles[object_role] = {
                        "id": object_role_id,
                        "teams": sorted(teams, key=lambda k: k['id'])
                    }

                filtered_object['object_roles'] = filtered_object_roles

            self.config_desired[object_type].append(filtered_object)


    def update_objects(self, object_type: str):

        current_objects  = self.config_current[object_type]
        desired_objects = self.config_desired[object_type]
        key = self.objects_structure[object_type]['key']

        j_query = f"[].{key}"
        object_names = set(jmespath.search(j_query, current_objects + desired_objects))

        for object_name in object_names:
            j_query = f"[?{key}=='{object_name}']|[0]"
            current_object_search = jmespath.search(j_query, current_objects)
            desired_object_search = jmespath.search(j_query, desired_objects)

            current_object = dict(current_object_search) if current_object_search else None
            desired_object = dict(desired_object_search) if desired_object_search else None

            try:
                object_id = current_object.pop('id',None)
            except:
                object_id = None
            
            # Create
            if not current_object:
                self.object_create(object_type,desired_object)

            # Update
            elif not current_object or (current_object != desired_object and desired_object):
                self.object_update(object_type,desired_object,object_id, current_object)

            # Delete
            elif not desired_object:
                self.object_delete(object_type,current_object,object_id)


    def object_create(self, object_type: str, object_to_create: dict):

        bodies = self.create_bodies(object_type, object_to_create)
        object_key = self.objects_structure[object_type]['key']
        
        # Main
        change = ('/api/v2/{0}/'.format(object_type), "POST", bodies['main'] )
        main_object = self.tower_connect.update(*change)
        object_id = main_object.get('id')
        self.results.append('New: object type: {0} ID: {1} Name: {2}'.format(object_type, object_id, object_to_create.get(object_key) ))
        
        # Update config_current on the fly
        object_to_create['id'] = object_id
        self.config_current[object_type].append(object_to_create)

        # Survey
        if self.objects_structure[object_type].get('surveys') and object_to_create.get('surveys'):
            change = ('/api/v2/{0}/{1}/survey_spec/'.format(object_type,object_id), "POST", bodies['survey'])
            self.tower_connect.update(*change)
            self.results.append('New: object type: {0} ID: {1} Name: {2} Survey'.format(object_type, object_id, object_to_create.get('name') ))

        # Schedule
        if self.objects_structure[object_type].get('schedules') and object_to_create.get('schedules'):
            for schedule in bodies.get('schedules',[]):
                change = ('/api/v2/{0}/{1}/schedules/'.format(object_type,object_id), "POST", schedule)
                self.tower_connect.update(*change)
                self.results.append('New: object type: {0} ID: {1} Name: {2} Schedule'.format(object_type, object_id, object_to_create.get('name')))

        # Credentials
        if self.objects_structure[object_type].get('credentials') and object_to_create.get('credentials'):
            # Create all new credentials
            for credential in object_to_create['credentials']:
                credential_body = { 
                    'id': credential['id'],
                    'associate': True
                }
                change = ('/api/v2/{0}/{1}/credentials/'.format(object_type,object_id), "POST", credential_body)
                self.tower_connect.update(*change)
            
            self.results.append('New: object type: {0} ID: {1} Name: {2} Credentials'.format(object_type, object_id, object_to_create.get('name')))

        # Object_roles
        if self.objects_structure[object_type].get('object_roles') and object_to_create.get('object_roles'):
            # Create all old object_roles
            for object_role_item in self.objects_structure[object_type]['object_roles'].keys():
                j_query_role_item = r"*|[?name=='{0}'].id|[0]".format(object_role_item)
                object_role_id = jmespath.search(j_query_role_item, main_object['summary_fields']['object_roles'])
                for item in object_to_create['object_roles'][object_role_item]['teams']:
                    object_role_body = { 
                        'id': item['id'],
                        'associate': True
                    }
                    change = ('/api/v2/roles/{0}/teams/'.format(object_role_id), "POST", object_role_body)
                    self.tower_connect.update(*change)            

            self.results.append('New: object type: {0} ID: {1} Name: {2} Object roles'.format(object_type, object_id, object_to_create.get('name')))

    def object_update(self, object_type: str, desired_object: dict ,object_id: int, current_object: dict) :

        bodies = self.create_bodies(object_type, desired_object)

        # Main
        change = ('/api/v2/{0}/{1}/'.format(object_type,object_id), "PATCH", bodies['main'] )
        self.tower_connect.update(*change)
        self.results.append('Updated: object type: {0} ID: {1} Name: {2}'.format(object_type, object_id, desired_object.get('name') ))

        # Survey
        if self.objects_structure[object_type].get('surveys') and desired_object['surveys'] != current_object['surveys']:
            if not desired_object.get('surveys'):
                change = ('/api/v2/{0}/{1}/survey_spec/'.format(object_type,object_id), "DELETE", dict())
                self.tower_connect.update(*change)
                self.results.append('Deleted: object type: {0} ID: {1} Name: {2} Survey'.format(object_type, object_id, desired_object.get('name') ))

            elif desired_object.get('surveys'):
                change = ('/api/v2/{0}/{1}/survey_spec/'.format(object_type,object_id), "POST", bodies['survey'])
                self.tower_connect.update(*change)
                self.results.append('Updated: object type: {0} ID: {1} Name: {2} Survey'.format(object_type, object_id, desired_object.get('name') ))

        # Schedule
        # Delete all existed schedules
        if self.objects_structure[object_type].get('schedules') and desired_object['schedules'] != current_object['schedules']:
            schedules_current = self.tower_connect.get('/api/v2/{0}/{1}/schedules/'.format(object_type,object_id),'results')
            for schedule_current in schedules_current:
                self.tower_connect.update(schedule_current['url'], "DELETE", dict())
            # Create all schedules
            for schedule in bodies['schedules']:
                change = ('/api/v2/{0}/{1}/schedules/'.format(object_type,object_id), "POST", schedule)
                self.tower_connect.update(*change)
                self.results.append('Updated: object type: {0} ID: {1} Name: {2} Schedule'.format(object_type, object_id, desired_object.get('name')))
            if len(schedules_current) != 0 and len(bodies['schedules']) == 0 :
                self.results.append('Deleted: object type: {0} ID: {1} Name: {2} Schedule'.format(object_type, object_id, desired_object.get('name')))

        # Credentials
        if self.objects_structure[object_type].get('credentials') and desired_object['credentials'] != current_object['credentials']:
            # Remove all old credentials
            for credential in current_object['credentials']:
                credential_body = { 
                    'id': credential['id'],
                    'disassociate': True
                }
                change = ('/api/v2/{0}/{1}/credentials/'.format(object_type,object_id), "POST", credential_body)
                self.tower_connect.update(*change)

            # Create all new credentials
            for credential in desired_object['credentials']:
                credential_body = { 
                    'id': credential['id'],
                    'associate': True
                }
                change = ('/api/v2/{0}/{1}/credentials/'.format(object_type,object_id), "POST", credential_body)
                self.tower_connect.update(*change)
            
            self.results.append('Updated: object type: {0} ID: {1} Name: {2} Credentials'.format(object_type, object_id, desired_object.get('name')))

        # Object_roles
        if self.objects_structure[object_type].get('object_roles') and desired_object['object_roles'] != current_object['object_roles']:
            for object_role_item in self.objects_structure[object_type]['object_roles'].keys():
                if current_object['object_roles'][object_role_item] != desired_object['object_roles'][object_role_item]:
                    object_role_id = current_object['object_roles'][object_role_item]['id']
                    # Remove all old object_roles
                    for item in current_object['object_roles'][object_role_item]['teams']:
                        object_role_body = { 
                            'id': item['id'],
                            'disassociate': True
                        }
                        change = ('/api/v2/roles/{0}/teams/'.format(object_role_id), "POST", object_role_body)
                        self.tower_connect.update(*change)            
                    # Create all new object_roles
                    for item in desired_object['object_roles'][object_role_item]['teams']:
                        object_role_body = { 
                            'id': item['id'],
                            'associate': True
                        }
                        change = ('/api/v2/roles/{0}/teams/'.format(object_role_id), "POST", object_role_body)
                        self.tower_connect.update(*change)            

            self.results.append('Updated: object type: {0} ID: {1} Name: {2} Object roles'.format(object_type, object_id, desired_object.get('name')))



    def object_delete(self, object_type: str, object_to_delete: dict ,object_id: int):

        if object_type == 'credential_types' and object_to_delete['managed_by_tower']:
            return

        self.tower_connect.update('/api/v2/{0}/{1}/'.format(object_type,object_id), "DELETE", dict())
        self.results.append('Deleted: object type: {0} ID: {1} Name: {2}'.format(object_type, object_id, object_to_delete.get('name') ))

    
    def create_bodies(self, object_type: str, my_object: dict):

        body = {
            'main': dict(),
            'survey': None,
            'schedules': []
            }

        # Leafs
        for item in self.objects_structure[object_type].get('leafs', {}):
            body['main'][item] = my_object[item]

        # Links
        for item in self.objects_structure[object_type].get('links', {}):
            body['main'][item] = my_object[item]

        # Survey
        if self.objects_structure[object_type].get('surveys') and my_object['surveys'] != []:
            body['survey'] = {
                "description": "",
                "name": "",
                "spec": my_object['surveys']
                }

        # Schedule
        if self.objects_structure[object_type].get('schedules') and my_object['schedules'] != []:
            body['schedules'] = my_object['schedules']

        return body

    def sync_objects(self, object_type: str):

        self.read_objects_from_tower(object_type)
        self.read_objects_from_config(object_type)
        self.update_objects(object_type)
        
        # Refresh the pending projects
        if object_type == 'projects':
            j_query = r'[?status != `successful`].{id: id, name: name, current_update_id: summary_fields.current_update.id}'
            attempts = 3
            current_project_updates = self.tower_connect.get('/api/v2/projects/','results')
            current_project_updates_failed = jmespath.search(j_query, current_project_updates)
            if len(current_project_updates_failed):
                while(True):
                    time.sleep(10)
                    current_project_updates = self.tower_connect.get('/api/v2/projects/','results')
                    current_project_updates_failed = jmespath.search(j_query, current_project_updates)
                    if len(current_project_updates_failed):
                        for current_project_update_failed in current_project_updates_failed:
                            if self.tower_connect.get('/api/v2/project_updates/{0}/cancel/'.format(current_project_update_failed['current_update_id'])).get('can_cancel'):
                                # Cancel project_update
                                change = ('/api/v2/project_updates/{0}/cancel/'.format(current_project_update_failed['current_update_id']),'POST', {})
                                self.tower_connect.update(*change)
                                time.sleep(5)
                                # Delete project_update
                                change = ('/api/v2/project_updates/{0}/'.format(current_project_update_failed['current_update_id']),'DELETE', {})
                                time.sleep(5)
                                self.tower_connect.update(*change)
                            change = ('/api/v2/projects/{0}/update/'.format(current_project_update_failed['id']), "POST", {})
                            self.tower_connect.update(*change)
                            self.tower_connect.update(*change)
                            self.results.append('Refreshed: object type: {0} ID: {1} Name: {2}'.format(object_type, current_project_update_failed['id'], current_project_update_failed['name'] ))
                            attempts -= 1
                    else:
                        break
                    if attempts == 0:
                        raise Warning ("Impossible to successfully pull all projects")

        # Refresh Inventory sources if they are `never updated`
        if object_type == 'inventory_sources':
            j_query = r'[?status == `never updated`].{id: id, name: name}'
            current_inventory_sources = self.tower_connect.get('/api/v2/inventory_sources/','results')
            current_inventory_sources_failed = jmespath.search(j_query, current_inventory_sources)
            for current_inventory_source_failed in current_inventory_sources_failed:
                change = ('/api/v2/inventory_sources/{0}/update/'.format(current_inventory_source_failed['id']),'POST', {})
                self.tower_connect.update(*change)
                self.results.append('Refreshed: object type: {0} ID: {1} Name: {2}'.format(object_type, current_inventory_source_failed['id'], current_inventory_source_failed['name'] ))

        # Refresh the always_nodes, 
        if object_type == 'workflow_job_template_nodes':
            self.sync_workflow_job_template_nodes_relationship()

    def sync_workflow_job_template_nodes_relationship(self):

        # Pull always_nodes, failure_nodes and success_nodes
        tower_objects = self.tower_connect.get('/api/v2/workflow_job_template_nodes/','results')
        
        for tower_object in tower_objects:
            object_id = tower_object['id']
            identifier = tower_object['identifier']
            current = {
                'always_nodes': tower_object['always_nodes'],
                'failure_nodes': tower_object['failure_nodes'],
                'success_nodes': tower_object['success_nodes'],
            }

            j_query = f"[?identifier=='{identifier}']|[0]"
            desired_object = jmespath.search(j_query, self.input_configuration['workflow_job_template_nodes'])
            desired = {
                'always_nodes': desired_object.get('always_nodes',[]),
                'failure_nodes': desired_object.get('failure_nodes',[]),
                'success_nodes': desired_object.get('success_nodes',[]),
            }
            for case_type in ['always_nodes','failure_nodes','success_nodes']:
                for case_item in desired[case_type]:
                    j_query = f"[?identifier=='{case_item}'].id|[0]"
                    case_item_id = jmespath.search(j_query, tower_objects)
                    if not case_item_id:
                        raise Warning(f'Can not find workflow_job_template_nodes: {case_item}')
                    desired[case_type].append(case_item_id)
                    desired[case_type].remove(case_item)

                for case_item in list(set(desired[case_type])-set(current[case_type])):
                    associate_body = { 
                        'id': case_item,
                        'associate': True
                    }
                    change = (f'/api/v2/workflow_job_template_nodes/{object_id}/always_nodes/','POST', associate_body )
                    self.tower_connect.update(*change)
                    self.results.append(f'New: object type: workflow_job_template_nodes ID: {object_id} Name: {identifier} {case_type} {identifier} Case_item: {case_item}')

                for case_item in list(set(current[case_type])-set(desired[case_type])):
                    disassociate_body = { 
                        'id': case_item,
                        'disassociate': True
                    }
                    change = (f'/api/v2/workflow_job_template_nodes/{object_id}/always_nodes/','POST', disassociate_body )
                    self.tower_connect.update(*change)
                    self.results.append(f'Deleted: object type: workflow_job_template_nodes ID: {object_id} Name: {identifier} {case_type} {identifier} Case_item: {case_item}')


    def provision(self):

        self.tower_settings_update()
        for object_type in self.sync_order:

            self.sync_objects(object_type)

        return self.results


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        configuration=dict(type='dict', required=True)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )
    
    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    
    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    tower_provison = Tower_provison(dict(module.params['configuration']))
    result['message'] = tower_provison.provision()

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['original_message'] = 'original_message'

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    if result['message']:
        result['changed'] = True
    else:
        result['changed'] = False

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
