


#Library function to work on the Canary side 
# Author : murari.bhattacharyya@hpe.com
import boto3
import os
import json
import urllib3
from botocore.exceptions import ClientError
import base64
import logging
import time 
import json
import datetime
import hpe_ccs_automation_lib
from hpe_ccs_automation_lib.session.ui.uisession import *
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ClusterDict:
    
    _urldict = None 
    urldict = None 
    _payloaddict = None 
    _cluster = None 
    
    def api_endpoint(self, operation_name):
        if operation_name in self.urldict.keys():
            return self.urldict[operation_name]
        else:
            raise CCSCanaryException("The Url Endpoint for the {} not found".format(operation_name))
    
    def api_payload(self ,operation_name): 
        if operation_name in self._payloaddict.keys(): 
            return self._payloaddict[operation_name]
        else:
            raise CCSCanaryException("The operation payload for operation  is not present in cluster ")
    
    def _load_cluster_data(self , clustername): 
        
        try: 
            with open('devicedata.json') as f: 
                _jsondata = json.load(f)
                self._urldict = _jsondata['url'][clustername]
                print("Self_urldic")
                print(type(self._urldict))
                print(self._urldict)
                #Modify all the url to append the cluster name 
                getcalls = ['device_assign_get' ,'device_unassign_get']
                
                #self.urldict = {k: 'https://' + self._cluster + v  for k,v in self._urldict.items() if k not in getcalls }
                for k,v in self._urldict.items(): 
                    if k not in getcalls:
                       self.urldict[k] = 'https://' + self._cluster + v 
                    else:
                       self.urldict[k] = v 
                   
                if clustername in _jsondata['clusters'].keys():
                     self._payloaddict = _jsondata['clusters'][clustername]
                else:
                    raise CCSCanaryException("Please load the cluster data in the corresponding function")
            
                logger.debug(self.urldict)
                
                logger.debug(self._payloaddict)
        except ValueError as error: 
            logger.error("Problem with loading json data ,make sure json is in correct format %s" %error)
        except IOError as error:
            logger.error("Problem with reading the file")
        except Exception as error:
            logger.error(error)

    def __init__(self ,**kwargs):
        if 'cluster' not in kwargs.keys():
            raise CCSCanaryException("Need to provide the cluster name in the cluster dictionary") 
        else:
            self._cluster = kwargs['cluster']
            self.urldict =dict()
            self._load_cluster_data(self._cluster)
            
'''
Class CCSClusterUIAPIOps
Description : This is the function for the different API 
'''
class CCSClusterUIAPIOps:
    
    #Pass the cluster dictionary object in the pointer 
    _myclusterdict = None 
    #Pass the UI Session object in the pointer 
    _myuisession = None
    errorcount = 0 
    _myretdict = dict()
    apilist = None 
    def __init__(self , clusterdict:ClusterDict ,uisession:UISession):
        self._myclusterdict = clusterdict 
        self._myuisession = uisession 
        self.apilist = list() 
        myheaders = {"Content-Type" : "application/json"}
        self._myuisession.session.headers.update(myheaders)
        self.errorcount = 0 
        self._myretdict = dict()
        self._myretdict['status'] = False 
        self._myretdict['apilist'] = dict()
        self._myretdict['errorstring'] = 'None!'
        self._myretdict['state'] = "UNKNOWN"
    '''
    Definition : Internal function to reset the dictionary 
    '''
    def reset_return_dict(self):
        self._myretdict = dict()
        self._myretdict['status'] = False 
        self._myretdict['apilist'] = dict() # { url : time } 
        self._myretdict['errorstring'] = 'None!'
        self._myretdict['state'] = "UNKNOWN"
    
    '''
    Definition : This is for the app role UI doorway calls 
    Author: abhinav.singh@hpe.com
    '''
    def app_role_ui_calls(self, **kwargs): 
       
         
        logger.debug("We are trying the  APP Role UI doorway calls") 
        if 'ops' in kwargs.keys(): 
            ops = kwargs['ops']
        else: 
            raise CCSCanaryException("Need to provide an OPS for the APP Role UI Create/Delete/Get  ")
        if 'cookies' in kwargs.keys(): 
            cookies = kwargs['cookies']
            logger.debug("We have passed the cookie as follows %s" %cookies )
        else:
            raise CCSCanaryException("Need to pass cookie to call license code for the call")
        if 'username' in kwargs.keys(): 
            username = kwargs['username']
        else:
            raise CCSCanaryException("Need to pass username for constructing the object ")
        
        if 'pcid' in kwargs.keys():
            pcid = kwargs['pcid']
        else:
            raise CCSCanaryException("Need to pass PCID for the Roles")
        if 'application_id' in kwargs.keys():
            application_id = kwargs['application_id']
        else:
            logger.debug("Probably we are not using application id for the case of %s" %ops)
        
        if 'slug' in kwargs.keys():
            myslug = kwargs['slug']
        else:
            logger.debug("Probably we are not using slug for the call of %s" %ops)
            
        if ops.upper() =="CREATERRP": 
            self.reset_return_dict()
            logger.debug("We are trying to create the resource restriction policy ")
            if 'application_cid' not in kwargs.keys() and 'application_instance_id' not in kwargs.keys():
                raise CCSCanaryException("Not able to find application_cid in kwargs , need to provide as key for RRP creation")
            
            else:
                shortpayload = [{"name":"allgroups",
                            "slug":"/aruba-central/group/*",
                            "description":"allgroups",
                            "matcher":"/aruba-central/group/*",
                            "scope_type_name":"Group Scope",
                            "scope_type_slug":"/aruba-central/group",
                            "type":"/aruba-central/group",
                            "application_cid": kwargs['application_cid'],
                            "application_instance_id": kwargs['application_instance_id']
                          }]
                          
                #Get the API endpoint and the 
                _url =  self._myclusterdict.api_endpoint("rrp_create")
                _url += application_id +"/resource_restriction"
                _payload = self._myclusterdict.api_payload("rrp_create")
                _payload[scope_resource_instances] = shortpayload
                logger.debug("We are going to fire this URL {} for the creation of the RRP...with payload {}".format(_url,_payload))
                
        elif ops.upper() =="CHECKAPPROLEASSIGNMENT":
            self.reset_return_dict()
            logger.debug("We are trying to get the role assignment and trying to find if a corresponding role is assigned to the pcid")
            _url = self._myclusterdict.api_endpoint("app_role_assignment_get")
            _url += pcid + "/users/" + username + "/role_assignments"
            _payload = self._myclusterdict.api_payload("app_role_assignment_get")
            rolename = _payload['name']
            logger.debug('We are going to fire URL {} '.format(_url))
            try: 
                res = requests.get(_url,headers=self._myuisession.session.headers, cookies=cookies )
                if res.status_code in [ 200, 201, 204]:
                    logger.info("We got a successful status code for the requests URL %s" %res.status_code)
                    myresponse = res.json()
                    logger.debug("The elapsed time of calling the API is %s" %res.elapsed)
                    self._myretdict['apilist'][_url]  = res.elapsed
                    found = False 
                    _roles = myresponse['roles'] 
                    if not _roles:
                        logger.debug("There is no associated roles with the user %s" %username)
                        self._myretdict['status'] = False 
                        self._myretdict['rolesarray'] = None
                        self._myretdict['errorcode'] = "User " + username + " has no role associated with it"
                    else:
                        for i in _roles: 
                            if i['role_name'] == rolename:
                                found = True
                                _myrole = i 
                                break 
                        if found: 
                            self._myretdict['status'] = True
                            self._myretdict['rolesarray'] =i
         
          
                else:
                    logger.error("We did not get a successful status code for the requests URL %s" %res.status_code)
                    self._myretdict['status'] = False
                    self._myretdict['errorcode'] = "Did not find the successful return code for get " + _url + " Status code:" + str(res.status_code)
                    
                    self._myretdict['apilist'][_url]  = res.elapsed
            except Exception as error: 
                logger.error("Did get an exception while calling the app role assignment get %s" %error)
                self._myretdict['status'] = False
                self._myretdict['errorcode'] = str(error)
                self._myretdict['apilist'][_url]  = -1
            
        elif ops.upper() =="GETRRP":
            self.reset_return_dict()
            logger.debug("We are trying to get the resource restriction policy ")
            #Hardcoding the limit and offset for now 
            limit = 10 
            offset = 0 
            #Get the API for the resource restriction policy .
            _url =  self._myclusterdict.api_endpoint("rrp_get")
            _payload = self._myclusterdict.api_payload("rrp_get")
            if "rrpname" in kwargs.keys():
                mykey = kwargs['rrpname']
            else:
                mykey = _payload['name']
            logger.debug("We are trying to get this RRP Customer Id and other details ")
            params = {'limit': limit , 'offset': offset } 
            logger.debug("We are going to fire the following API {}".format(_url))
            try: 
                res = requests.get(_url,headers=self._myuisession.session.headers, params=params, cookies=cookies)
                logger.debug(res.json())
                logger.debug("The elapsed time of calling the API is %s" %res.elapsed)
                self._myretdict['apilist'][_url]  = res.elapsed
                if res.status_code in [ 200, 201, 204 ]:
                    logger.debug("Get RRP session worked correctly ...")
                    
                    #Get the RRP and 
                    policies = res.json()['policies']
                    def get_data_policy(p):
                        found = False 
                        for i in p:
                            if i['name'] == mykey: 
                                found = True
                                _concernedvalue = i 
                                break 
                        if found == True: 
                            return _concernedvalue , True 
                        else:
                            return None , False 
                    concernedvalue ,retcode= get_data_policy(policies)
                    if retcode:
                        self._myretdict['platform_cid'] = concernedvalue['platform_cid']
                        self._myretdict['status'] = True 
                        self._myretdict['application_id'] = concernedvalue['application_id']
                        self._myretdict['resource_restriction_policy_id'] = concernedvalue['resource_restriction_policy_id']
                    else: 
                        logger.error("Did not find the concerned Default  Resource restriction policy  ")
                        self._myretdict['platform_cid'] = None
                        self._myretdict['status'] = False
                        self._myretdict['application_id'] = None
                        self._myretdict['resource_restriction_policy_id'] = None
                        self._myretdict['errorcode'] = "Did not find the default resource restriction policy"
                else:
                    logger.error("The get RRP API call did not work correctly ..")
                    self._myretdict['status'] = False 
                    self._myretdict['errorcode'] = "Get RRP called returned " + str(res.status_code) 
            except Exception as error:
                logger.error("We got an exception while calling the Resource Restriction policy get %s" %error)
                
        elif ops.upper() == "DELETERRP":
            self.reset_return_dict()
            logger.debug("We are tryung to delete the resource restriction policy ")
        elif ops.upper() == "ASSIGN":
            self.reset_return_dict()
            logger.debug("We are trying to assign the role,with RRPS")
            _payload = self._myclusterdict.api_payload("app_role_assign")
            _url = self._myclusterdict.api_endpoint("app_role_assign")
            _url += username +'/roles'
            if 'rrp' not in kwargs.keys():
                raise CCSCanaryException("Need to pass the RRP array for testing out the cluster properly")
            else:
                rrp = kwargs['rrp']
            slugdict = {"add":[{"role": {"slug": myslug , "application_id": application_id ,"resource_restriction_policies":rrp} }]} 
            
            
            #Replace the slug and application_id from the get call 
            logger.debug("We are going to fire URL {} with payload {}".format(_url,slugdict))
            try:
                res = requests.put(_url,headers=self._myuisession.session.headers, data=json.dumps(slugdict), cookies=cookies)
                logger.debug(res.json())
                
                if res.status_code in [ 200,201,204]: 
                    logger.info("Successfully assigned the APP role")
                    self._myretdict['status'] = True
                    logger.debug("The elapsed time of calling the API is %s" %res.elapsed)
                    self._myretdict['apilist'][_url]  = res.elapsed
                else:
                    logger.error("Could not successfully assign the APP role ")
                    self._myretdict['status'] = False
                    self._myretdict['errorcode'] = "Got an error code of " + str(res.status_code) + " while APP role assignment "
                    self._myretdict['apilist'][_url]  = -1
            except Exception as error:
                logger.error("Exception caught while trying to assign the App role %s" %error)
                self._myretdict['status'] = False
                self._myretdict['errorcode'] = str(error)
                self._myretdict['apilist'][_url]  = -1
                
        elif ops.upper() == "UNASSIGN":
            self.reset_return_dict()
            logger.debug("We are trying to unassign the role, without RRS")
            _payload = self._myclusterdict.api_payload("app_role_unassign")
            _url = self._myclusterdict.api_endpoint("app_role_unassign")
            _url += username + '/roles'
            slugdict = {"delete":[{"slug":myslug,"application_id":application_id}]}
            logger.debug("We are going to fire URL {} with payload {}".format(_url,slugdict))
            try: 
                res = requests.put(_url,headers=self._myuisession.session.headers, data=json.dumps(slugdict), cookies=cookies)
                logger.debug(res.json())
                if res.status_code in [ 200,201,204]: 
                    logger.info("Successfully unassigned the APP role")
                    self._myretdict['status'] = True
                    logger.debug("The elapsed time of calling the API is %s" %res.elapsed)
                    self._myretdict['apilist'][_url]  = res.elapsed
                else:
                    logger.error("Could not successfully unassign the APP role ")
                    self._myretdict['status'] = False
                    self._myretdict['errorcode'] = "Got an error code of " + str(res.status_code) + " while APP role unassignment "
                    self._myretdict['apilist'][_url]  = -1
            except Exception as error:
                logger.error("Exception caught while trying to unassign the App role %s" %error)
                self._myretdict['status'] = False
                self._myretdict['errorcode'] = str(error)
                self._myretdict['apilist'][_url]  = -1
                
        elif ops.upper() == "CREATE": 
            self.reset_return_dict()
            logger.debug("We are going to create the role for the APP Role creation ")
            #https://gemini-default-user-api.ccs.arubathena.com/authorization/ui/v1/customers/eb207f2611ee11edab674e7e80cd07fc/applications/07a6aa3b-5202-4d95-bfdb-e23217edc62b/roles 
            _payload = self._myclusterdict.api_payload("app_role_create")
            
            _url = self._myclusterdict.api_endpoint("app_role_create")
            application_id = self._myclusterdict.api_payload("app_role_get")['application_id']
            _url += pcid + '/applications/' + application_id +'/roles'
            logger.debug("We are going to fire the API endpoint as follows : %s " %_url)
            try: 
                res = requests.post(_url, headers=self._myuisession.session.headers, data=json.dumps(_payload), cookies=cookies)
                logger.debug("The status code that is returned is %s" %res.status_code)
                logger.debug("The content that is returned ins %s" %res.content)
                
               
                if res.status_code in [ 200, 201, 204 ]: 
                   logger.debug("We have successfully created the  app role ")
                   self._myretdict['apilist'][_url]  = res.elapsed
                   logger.debug("The app role creation time taken is %s" %self._myretdict['apilist'][_url])
                   self._myretdict['status'] = True 
                   logger.debug("The status code for the app role creation is %s" %res.status_code)
                   myretval = res.json()
                   logger.debug("The return value is %s" %myretval)
                   self._myretdict['slug'] = myretval['slug']
                else:
                   logger.error("We could not successfully create role ")
                   logger.error("The status code is %s" %res.status_code)
                   self._myretdict['errorcode']  += "\n We could not successfully assign the role \n , Status code is :" + str(res.status_code)
                   self._myretdict['apilist'][_url]  = -1
                   self._myretdict['status'] = False 
            except Exception as error:
                logger.error("Exception caught while firing the API: %s " %error)
                self._myretdict['status'] = False
                self._myretdict['errorcode'] = str(error)
                self._myretdict['apilist'][_url]  = -1
            
        elif ops.upper() == "DELETE": 
            self.reset_return_dict()
            logger.debug("We are going to delete the role for the APP role ")
            _payload = self._myclusterdict.api_payload("app_role_delete")
            _url = self._myclusterdict.api_endpoint("app_role_delete")
            if 'slug' not in kwargs.keys():
                raise CCSCanaryException("Need to pass the application slug for the delete role ")
           
            _url += pcid + '/applications/' + application_id + '/roles/' + myslug
            logger.debug("We are going to fire {} ,with payload {} ".format(_url, _payload))
            try: 
                res = requests.delete(_url, headers=self._myuisession.session.headers,  cookies=cookies)
                logger.debug("The status code that is returned is %s" %res.status_code)
                logger.debug("The content that is returned ins %s" %res.content)
                
               
                if res.status_code in [ 200,201, 204 ]: 
                   logger.debug("We have successfully deleted the  app role ")
                   self._myretdict['apilist'][_url]  = res.elapsed
                   logger.debug("The app role deletion time taken is %s" %self._myretdict['apilist'][_url])
                   self._myretdict['status'] = True 
                   logger.debug("The status code for the app role deletion is %s" %res.status_code)
                else:
                   logger.error("We could not successfully delete role  ")
                   logger.error("The status code is %s" %res.status_code)
                   self._myretdict['errorcode']  += "\n We could not successfully delete the role \n , Status code is :" + str(res.status_code)
                   self._myretdict['apilist'][_url]  = -1
                   self._myretdict['status'] = False 
            except Exception as error:
                logger.error("Exception caught while firing the API %s " %error)
                self._myretdict['status'] = False
                self._myretdict['errorcode'] = str(error)
                self._myretdict['apilist'][_url]  = -1
                
        elif ops.upper() == "GET": 
            self.reset_return_dict()
            def verify_roles(**kwargs):
  
                if 'name' in kwargs.keys():
                    _rolename  = kwargs['name']
                else:
                    raise CCSCanaryException("Need to provide the rolename for verification")
                if 'resultdict' in kwargs.keys():
                    _roledict = kwargs['resultdict']['roles']
                else:
                    raise CCSCanaryException("Need to pass the result from the get calls")
                found = False
                for i in _roledict:
                    if i['name'] == _rolename:
                        _mydata = i
                        #logger.debug(_mydata)
                        found = True
                        break
                if found == True:
                    return _mydata , True
                else:
                    return None , False
                    
            logger.debug("We are calling the get call for the pcid %s" %pcid)
            _payload = self._myclusterdict.api_payload("app_role_get")
            name = _payload['name']
            _url = self._myclusterdict.api_endpoint("app_role_get")
            _url = _url + pcid + "/roles"
            try: 
                res = requests.get(_url,headers=self._myuisession.session.headers ,cookies=cookies)
                if res.status_code in [ 200,201,204]:
                    #logger.debug("The content for the get call is %s" %res.content)
                    myretval = res.json()
                    mydictionary = {'name' : name , 'resultdict' : myretval } 
                    mydata , retval = verify_roles(**mydictionary) 
            
                    if retval == True :
                        logger.info("We have got the role being present in the existing APP role ")
                        self._myretdict['status'] = True
                        self._myretdict['slug'] =  mydata['slug']
                        self._myretdict['application_id'] =mydata['application_id']
                        self._myretdict['apilist'][_url] = res.elapsed
                    else: 
                        logger.error("We did not find the role being present in the existing APP role ")
                        self._myretdict['status'] = False 
                        self._myretdict['slug'] = None 
                        self._myretdict['application_id'] = None 
                        self._myretdict['apilist'][_url] = res.elapsed
                else:
                    logger.error("We got a wrong status code executing the get call :" %res.status_code)
                    self._myretdict['status'] = False 
                    self._myretdict['slug'] = None 
                    self._myretdict['application_id'] = None 
                    self._myretdict['errorcode'] = "Got status code " + str(res.status_code) + " in the get app role call"
            except Exception as error:
                logger.error("Exception caught while executing the get API call %s" %error)
                self._myretdict['status'] = False 
                self._myretdict['slug'] = None 
                self._myretdict['application_id'] = None 
                self._myretdict['errorcode'] = str(error)
                
            
        else:
            
            raise CCSCanaryException("We are trying an wrong ops in case of app_role_assign")
            
        return self._myretdict
            
    def role_ui_calls(self, **kwargs): 
        
        logger.debug("We are trying the Role UI doorway calls") 
        if 'ops' in kwargs.keys(): 
            ops = kwargs['ops']
        else: 
            raise CCSCanaryException("Need to provide an OPS for the Role UI Assign/ Unassign  ")
        if 'cookies' in kwargs.keys(): 
            cookies = kwargs['cookies']
            logger.debug("We have passed the cookie as follows %s" %cookies )
        else:
            raise CCSCanaryException("Need to pass cookie to call license code for the call")
        if 'username' in kwargs.keys(): 
            username = kwargs['username']
        else:
            raise CCSCanaryException("Need to pass username for constructing the object ")
        
        if 'pcid' in kwargs.keys():
            pcid = kwargs['pcid']
        else:
            raise CCSCanaryException("Need to pass PCID for the Roles")
        if ops.upper() == "ASSIGN":
           
        
           self.reset_return_dict()
           _payload = self._myclusterdict.api_payload("role_assign")
           _url = self._myclusterdict.api_endpoint("role_assign")
           _url = _url + username + "/roles"
           self._myretdict['apilist'][_url] = -1
           logger.debug("We are going to fire {} with the payload {} for role assignment ".format(_url,_payload))
           try: 
               logger.debug("The headers what we are posting is %s: "%self._myuisession.session.headers)
               res = requests.put(_url, headers=self._myuisession.session.headers, data=json.dumps(_payload), cookies=cookies)
               logger.debug("The status code that is returned is %s" %res.status_code)
               logger.debug("The content that is returned ins %s" %res.content)
               #res = requests.post(_url, headers= self._myuisession.session.headers , data = json.dumps(_payload))
               #res = self._myuisession.post(_url  ,data=json.dumps(_payload))
               if res.status_code in [ 200, 204 ]: 
                   logger.debug("We have successfully assigned the role ")
                   self._myretdict['apilist'][_url]  = res.elapsed
                   logger.debug("The role assignment time taken is %s" %self._myretdict['apilist'][_url])
                   self._myretdict['status'] = True 
                   logger.debug("The status code for the role assignment is %s" %res.status_code)
               else:
                   logger.error("We could not successfully assigned the role ")
                   logger.error("The status code is %s" %res.status_code)
                   self._myretdict['errorcode']  += "\n We could not successfully assign the role \n , Status code is :" + str(res.status_code)
                 
                   self._myretdict['status'] = False 
              
               
           except Exception as error:
                logger.error("Exception caught while trying for role operations %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" +str(error) + "\n"
                self._myretdict['status'] = False 
        elif ops.upper() == "GET": 
            self.reset_return_dict()
            _payload = self._myclusterdict.api_payload("role_get")
            _url = self._myclusterdict.api_endpoint("role_get")
            _url = _url + pcid + "/users/" + username + "/role_assignments"
            
            res = requests.get(_url,headers=self._myuisession.session.headers ,cookies=cookies)
            logger.debug("The content for the get call is ")
            logger.debug(res.content)
            _my_res = res.json()
            logger.debug("The username we are getting in response is %s" %_my_res['user_name'])
            logger.debug("The length of roles we are getting in response is %s" %len(_my_res['roles']))
            logger.debug("The username is %s" %username)
            if res.status_code in [ 200, 204 ] and _my_res['user_name'] == username : 
                
                logger.debug("We have successfully did a get role operations")
                logger.debug("We got a role get  status code as %s" %res.status_code)
                self._myretdict['apilist'][_url]  = res.elapsed.total_seconds()
                logger.debug("The time taken for the API is %s" %res.elapsed)
                self._myretdict['status'] = True 
            else:
                logger.error("We could not successfully get the roles")
                logger.debug("We have got a status code as %s" %res.status_code)
                self._myretdict['apilist'][_url] = -1 
                self._myretdict['status'] = False 
                self._myretdict['errorcode'] = "\n We could not successfully get the roles. \n The status code returned is :" + str(res.status_code)
                
        elif ops.upper() == "UNASSIGN": 
           self.reset_return_dict()
           _payload = self._myclusterdict.api_payload("role_unassign")
           _url = self._myclusterdict.api_endpoint("role_unassign")
           _url = _url + username + "/roles"
           logger.debug("We are going to fire {} with the payload {} for role unassignment ".format(_url,_payload))
           try: 
               res = requests.put(_url, headers=self._myuisession.session.headers , data=json.dumps(_payload),cookies=cookies)
               #res = self._myuisession.delete(_url  ,data=json.dumps(_payload))
               if res.status_code in [ 200, 204 ]: 
                   logger.debug("We have successfully unassigned the role operations")
                   logger.debug("We got a role unassignment status code as %s" %res.status_code)
                   self._myretdict['apilist'][_url]  = res.elapsed.total_seconds() 
                   self._myretdict['status'] = True 
               else:
                   logger.error("We could not successfully unassign the roles")
                   logger.debug("We have got a status code as %s" %res.status_code)
                   self._myretdict['apilist'][_url] = -1 
                   self._myretdict['status'] = False 
                   self._myretdict['errorcode'] = "\n We could not successfully get the roles. \n The status code returned is :" + str(res.status_code)
               
           except Exception as error:
                logger.error("Exception caught while trying for unassign roles %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" + error + "\n"
                self._myretdict['status'] = False 
        else :
            raise CCSCanaryException("Unsupported operation for license UI calls ")
        return self._myretdict
        
    '''
    Definition : This is the license UI call to be made 
    '''
    def license_ui_calls(self ,**kwargs):
       
        logger.debug("We are trying the License UI doorway calls") 
        if 'ops' in kwargs.keys(): 
            ops = kwargs['ops']
        else: 
            raise CCSCanaryException("Need to provide an OPS for the device ASSIGN/UNASSIGN ")
        if 'cookies' in kwargs.keys(): 
            cookies = kwargs['cookies']
            logger.debug("We have passed the cookie as follows %s" %cookies )
        else:
            raise CCSCanaryException("Need to pass cookie to call license code for the call")
        if ops.upper() == "ASSIGN":
           
           
           self.reset_return_dict()
           _payload = self._myclusterdict.api_payload("license_assign")
           _url = self._myclusterdict.api_endpoint("license_assign")
           self._myretdict['apilist'][_url] = -1
           logger.debug("We are going to fire {} with the payload {} for license assignment ".format(_url,_payload))
           try: 
               logger.debug("The headers what we are posting is %s: "%self._myuisession.session.headers)
               res = requests.post(_url, headers=self._myuisession.session.headers, data=json.dumps(_payload), cookies=cookies)
               #res = requests.post(_url, headers= self._myuisession.session.headers , data = json.dumps(_payload))
               #res = self._myuisession.post(_url  ,data=json.dumps(_payload))
               if res.status_code in [ 200, 204 ]: 
                   logger.debug("We have successfully assigned the license ")
                   self._myretdict['apilist'][_url]  = res.elapsed.total_seconds() 
                   self._myretdict['status'] = True 
                   logger.debug("The status code for the license assignment is %s" %res.status_code)
               else:
                   logger.error("We could not successfully assign the license")
                   print(res.status_code)
                 
                   self._myretdict['status'] = False 
               time.sleep(3)
               
           except Exception as error:
                logger.error("Exception caught while trying for post operations %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" +str(error) + "\n"
                self._myretdict['status'] = False 
        elif ops.upper() == "UNASSIGN": 
           self.reset_return_dict()
           _payload = self._myclusterdict.api_payload("license_unassign")
           _url = self._myclusterdict.api_endpoint("license_unassign")
           logger.debug("We are going to fire {} with the payload {} for license unassignment ".format(_url,_payload))
           try: 
               res = requests.delete(_url, headers=self._myuisession.session.headers , data=json.dumps(_payload),cookies=cookies)
               #res = self._myuisession.delete(_url  ,data=json.dumps(_payload))
               if res.status_code in [ 200, 204 ]: 
                   logger.debug("We have successfully deleted the license")
                   logger.debug("We got a delete license status code as %s" %res.status_code)
                   self._myretdict['apilist'][_url]  = res.elapsed.total_seconds() 
                   self._myretdict['status'] = True 
               else:
                   logger.error("We could not successfully delete the license")
                   logger.debug("We have got a status code as %s" %res.status_code)
                   self._myretdict['apilist'][_url] = -1 
                   self._myretdict['status'] = False 
               
               
           except Exception as error:
                logger.error("Exception caught while trying for post operations for license %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" + error + "\n"
                self._myretdict['status'] = False 
        else :
            raise CCSCanaryException("Unsupported operation for license UI calls ")
        return self._myretdict
        
    def device_ui_calls(self , **kwargs):
        self.reset_return_dict()
        if 'ops' in kwargs.keys():
               ops = kwargs['ops']
        else:
            raise CCSCanaryException("Need to provide an OPS for the device , ASSIGN/ UNASSIGN/ GET")
        if 'cookies' in kwargs.keys():  
            cookies = kwargs['cookies']
            logger.debug("We have passed the cookie as follows %s" %cookies )
        else:
            raise CCSCanaryException("Need to pass cookie to call license code for the call")
        if ops.upper() == "ASSIGN": 
            self.reset_return_dict()
            logger.debug("Performing device assignment calls")
            _payload = self._myclusterdict.api_payload("device_assign")
            _url = self._myclusterdict.api_endpoint("device_assign")
            self._myretdict['apilist'][_url] = -1
            logger.debug("We are firing {} with payload {}".format(_url,_payload))
            try: 
               res = requests.post(_url, headers= self._myuisession.session.headers , data = json.dumps(_payload) ,cookies=cookies)
               #res = self._myuisession.post(_url  ,data=json.dumps(_payload))
               if res.status_code in [ 200, 204 ]: 
                   logger.debug("We have successfully assigned the device ")
                   self._myretdict['apilist'][_url]  = res.elapsed.total_seconds() 
                   self._myretdict['status'] = True 
               else:
                   logger.error("We could not successfully assign the device")
                   self._myretdict['status'] = False 
               time.sleep(3)
               
            except Exception as error:
                logger.error("Exception caught while trying for post operations %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" + error + "\n"
                self._myretdict['status'] = False 
    
            
        elif ops.upper() == "UNASSIGN":
            self.reset_return_dict()
            _payload = self._myclusterdict.api_payload("device_unassign")
            _url = self._myclusterdict.api_endpoint("device_unassign")
            logger.debug("Performing device unassignment calls")
            logger.debug("We are firing {} with payload {}".format(_url,_payload))
            try:
                res = requests.delete(_url, headers= self._myuisession.session.headers , data = json.dumps(_payload),cookies=cookies)
                
                if res.status_code in [ 200, 204]:
                    logger.debug("We have got a successful delete of the endpoint ")
                    logger.debug("The return code for device delete is %s" %res.status_code)
                    self._myretdict['status'] = True 
                    self._myretdict['apilist'][_url]  = res.elapsed.total_seconds() 
                   
                else:
                    logger.debug("Device unassignment call failed ")
                    self._myretdict['status'] = False
                time.sleep(3)
                
            except Exception as error:
                logger.error("Exception caught while trying for post operations %s" %error)
                self.errorcount += 1 
                self._myretdict['errorstring'] += "\n" + error + "\n"
                self._myretdict['status'] = False 
            
        elif ops.upper() == "GET":
            self.reset_return_dict()
            url = self._myclusterdict.api_endpoint("device_get")
            state_payload = self._myclusterdict.api_payload("device_get")
            myurl = self._myclusterdict.api_endpoint("device_unassign_get")
            logger.debug("We are verifying {} with verification {}".format(url,state_payload)) 
            logger.debug("Performing device get calls ")
            logger.debug(self._myuisession.session.headers)
            print(self._myuisession.session.headers)
            self._myretdict['apilist'][url] = -1 
            res = requests.get(url , headers=self._myuisession.session.headers )
           # print(res.text)
            logger.debug(res.status_code)
            print(res.elapsed)
            logger.debug(res.elapsed)
            res = self._myuisession.get(myurl)
            self._myretdict['payload'] = res
            self._myretdict['status'] = True
            
            _device_list = res['devices']
            #TO DO :Check if it is None 
            found = False
            
            for i in _device_list: 
                if i['serial_number'] == state_payload['serial_number']: 
                    logger.debug("We get the corresponding device we are looking for : %s" %i)
                    _mydataconcern = i 
                    
                    found = True 
                    break 
            if found: 
                self._myretdict['status'] = True 
                if _mydataconcern['application_customer_id'] == '' and _mydataconcern['application_id'] == '': 
                    logger.debug("The Device is not assigned")
                    _state = "UNASSIGNED"
                    self._myretdict['state'] = "UNASSIGNED"
                else:
                    logger.debug("The Device is assigned")
                    self._myretdict['state'] = "ASSIGNED"
            else:
                logger.error("We did not get the specific device we are looking for")
                self._myretdict['status'] = False
                self.__myretdict['errorstring'] += "We did not find the corresponding device with serial number " + state_payload['serial_number']
                
            
    
            
        else:
            raise CCSCanaryException("Need to do either assign/ unassign and get")
        return self._myretdict




class CCSUTCTimeStamp: 
    def generatetimestamp(self):
        myd = datetime.datetime.utcnow()
        #print(myd.strftime("%Y-%m-%dT%H:%M:%S.%f"))
        return str(myd.strftime("%Y-%m-%dT%H:%M:%S.%f"))
        
'''
Description : Lambda class 
'''
class CCSLambdaInvoker(): 
    
    lambdaarn = None 
    lambdaclient = None 
    def __init__(self , **kwargs):
        if 'lambdaarn' in kwargs.keys(): 
            self.lambdaarn = kwargs['lambdaarn']
            logger.debug("The Lambda ARN is coming as %s" %self.lambdaarn)
        else:
            raise CCSCanaryException("Please provide the lambda ARN in the Initiator")
        try: 
            self.lambdaclient = boto3.client('lambda')
            log.debug("Successfully initialized lambda client")
        except Exception as error: 
            logger.debug("Exception caught while initializing the lambda client %s" %error)
    
    #This function will insert it in the DynamoDB 
    def insert_dynamodb(self, **data): 
        try: 
             logger.debug("************")
             logger.debug(data)
             response = self.lambdaclient.invoke(
               FunctionName=self.lambdaarn,
               InvocationType='RequestResponse',
               Payload=json.dumps(data),
               )
             
             logger.debug("The response is coming as %s"  %response)
             return True , response 
             
        except Exception as error: 
            logger.debug("Exception caught while putting the data lambda client %s" %error)      
            return False , None 
            
    def create_pagerduty(self, **data): 
        try: 
             logger.debug("************")
             logger.debug(data)
             response = self.lambdaclient.invoke(
             FunctionName=self.lambdaarn,
             InvocationType='RequestResponse',
             Payload=json.dumps(data),
             )
             logger.debug("The response is coming as %s"  %response)
             
        except Exception as error: 
            logger.debug("Exception caught while putting the data lambda client %s" %error)      
    def put_to_websocket(self, **data): 
        try: 
             logger.debug("************")
             logger.debug(data)
             response = self.lambdaclient.invoke(
             FunctionName=self.lambdaarn,
             InvocationType='RequestResponse',
             Payload=json.dumps(data),
             )
             logger.debug("The response is coming as %s"  %response)
             
        except Exception as error: 
            logger.debug("Exception caught while putting the data lambda client %s" %error)
        
        
'''
    Description: CCSCanaryExceptionClass
    Usage: Used to catch the common Selenium exceptions and raise the exceptions
'''

class CCSCanaryException(Exception):

      def __init__(self,  message="Default CCS Canary exception raised"):
           self.message = message
           super().__init__(self.message)
           
class CCSCanaryInfra():
       _alarmname = None
       def __init__(self, alarmname):
           try:
               self.alarmclient = boto3.client('cloudwatch')
           except Exception as error:
               logger.error("The alarm client cannot be created")
           self._alarmname = alarmname
       
       def set_alarm(self, reason="Canary is disturbed"):
            response = self.alarmclient.set_alarm_state(
                  AlarmName=self._alarmname,
                  StateValue='ALARM' , StateReason=reason)
       def defuse_alarm(self,reason="Canary is disturbed"):
             response = self.alarmclient.set_alarm_state(
                  AlarmName=self._alarmname,
                  StateValue='OK' , StateReason=reason)


'''
This class is for the Slack Formatting 
Author: murari.bhattacharyya@hpe.com

'''
class CCSSlackFormatter(): 
    _internal_dict =None 
    _slack_webhook = None
    http = None
    def __init__(self , slack_webhook = '/hpe/ccs/productionmonitoringslackhook'):
        logger.debug("Using the Slack formatter engine for parsing the data")
        _slack = CCSSlackParameter(slack_webhook)
        self._slack_webhook = _slack.get_slack_weblink()
        logger.debug(self._slack_webhook)
        self._get_list_of_users_notified()
        self.http = urllib3.PoolManager()
        
    def _get_list_of_users_notified(self):
        with open("slackuser.json") as j: 
            mydict =json.load(j)
            logger.debug(mydict)
            self._internal_dict = mydict
    #Function definition : To paste in the proper slack channel ....
    def paste_in_slack_channel(self,message): 
        logger.debug("Message is %s" %message)
       # message ="The report for *ccs_apps_aquila*\\n\\n The *ERROR* reported is : _Nothing to report, probably no failures _ \\nHi ,<@UEEHX782C> , <@UFE7PBU9Z> , <@U0287A5NXMX> , <@U01LMTPP4UA> , \\n Can you please look at Error reported above? Ignore if there is no error\\n\\n*AWS Region * : eu-west-3\n* AWS Log Group  * :/aws/lambda/lambdaslack\\n*AWS Log File *: 2022/05/31/[$LATEST]343404e3a0b2453aba780e06de39e75a\\n"
        payload = {'text' : message }
        r = self.http.request("POST", 
                         self._slack_webhook,        
                         body = json.dumps(payload),
                         headers = {"Content-Type" : "application/json"})
    
        #This function is to format the userlist , based on the canary 
    
    def format_the_userlist(self,**kwargs):
        if 'lambda_handler' in kwargs.keys(): 
            _canary_name = kwargs['lambda_handler']
        elif 'canary_name' in kwargs.keys(): 
            _canary_name = kwargs['canary_name']
        else:
            logger.error("We are not publishing the canary name")
        if 'harerrordict' in kwargs.keys(): 
            self._harerrordict = kwargs['harerrordict']
            #Process the HAR dictionary
        elif 'errorcode' in kwargs.keys(): 
            self._errorstring = kwargs['errorcode']
        else:
            self._errorstring = "None!"
        
        #Add the log location if someone wants to have a look ...
        if 'context' in kwargs.keys(): 
            _contextstring = "*AWS Region * : " + os.environ['AWS_REGION'] + "\n"
            _contextstring += "*AWS Log Group  * :" + kwargs['context'].log_group_name + "\n"
            _contextstring += "*AWS Log File *: " + kwargs['context'].log_stream_name + "\n"
        fancycanarynamedict = dict()
        fancycanarynamedict['testEST'] = "EST Provisioning API canary"
        fancycanarynamedict['testvinaya'] = "IAP/Switch Device connection API Canary"
        fancycanarynamedict['ccs_aquila_device_api_check'] = "CCS Aquila Device API Canary"
        fancycanarynamedict['ccs_pavo_device_api_check'] = "CCS Aquila Device API Canary"
        fancycanarynamedict['ccs_aquila_license_api_check'] = "CCS Aquila License API Canary"
        fancycanarynamedict['ccs_pavo_license_api_check'] = "CCS Aquila License API Canary"
        fancycanarynamedict['ccs_lilo_api_gemini'] = "CCS Login Load Account Gemini API Canary"
        fancycanarynamedict['ccs_gemini_device_api_check'] = 'CCS Gemini Device Assignment Canary'
        fancycanarynamedict['ccs_gemini_license_api_check'] = 'CCS Gemini License Assignment Canary'
        fancycanarynamedict['ccs_gemini_role_api_check'] = 'CCS Gemini Role Assign API Canary'
        fancycanarynamedict['ccs_aquila_role_api_check'] = 'CCS Aquila Role Assign API Canary'
        fancycanarynamedict['ccs_aquila_app_role_create_delete'] = 'CCS Aquila App Role Create Delete API Canary'
        fancycanarynamedict['ccs_gemini_app_role_create_delete'] = 'CCS Gemini App Role Create Delete API Canary'
        fancycanarynamedict['ccs_aquila_app_role_assign_unassign'] = 'CCS Aquila App Role Assign Unassign API Canary'
        fancycanarynamedict['ccs_gemini_app_role_assign_unassign'] = 'CCS Gemini App Role Assign Unassign API Canary'
        
        if _canary_name in fancycanarynamedict.keys(): 
            _printed_canary_name = fancycanarynamedict[_canary_name]
        else:
            _printed_canary_name = _canary_name 
        mystring = "The report for *" + _printed_canary_name + "*\n"
        if self._errorstring == "None!":
           mystring += "\n No incident reported !!! \n\n"
        else:
           mystring += "\n The *ERROR* reported is : " + str(self._errorstring) + "_ \n"
        #Attach the responsible persons from the error list from slack user json 
        _firstlevelusers = self._internal_dict[_canary_name]
        if self._errorstring == 'None!':
            logger.debug("We are not printing the userlist")
        else:
            _format_string ="Hi ,"
            for i in _firstlevelusers: 
                _format_string += "<@" + i + "> , "
            if self._errorstring == "None!" :
                _format_string += "\n No Error! Chill for now !"
            else:
                _format_string += "\n Can you please look at Error reported above?\n\n"
                mystring += _format_string
    
        if 'context' in kwargs.keys(): 
            mystring += _contextstring
        #Check for the API list which are fired as a part of the API canary ... 
        if 'apilist' in kwargs.keys(): 
            apistring = "\n *The API List tested in Canary * : \n"
            for i in kwargs['apilist'] : 
                apistring += "\n " + i 
            mystring += apistring 
        return mystring
               
    #This function is to format the userlist , based on the canary 
    
    def format_the_userlist_older(self,**kwargs):
        if 'lambda_handler' in kwargs.keys(): 
            _canary_name = kwargs['lambda_handler']
        elif 'canary_name' in kwargs.keys(): 
            _canary_name = kwargs['canary_name']
        else:
            logger.error("We are not publishing the canary name")
        if 'harerrordict' in kwargs.keys(): 
            self._harerrordict = kwargs['harerrordict']
            #Process the HAR dictionary
        elif 'errorcode' in kwargs.keys(): 
            self._errorstring = kwargs['errorcode']
        else:
            self._errorstring = "None!"
        
        #Add the log location if someone wants to have a look ...
        if 'context' in kwargs.keys(): 
            _contextstring = "*AWS Region * : " + os.environ['AWS_REGION'] + "\n"
            _contextstring += "*AWS Log Group  * :" + kwargs['context'].log_group_name + "\n"
            _contextstring += "*AWS Log File *: " + kwargs['context'].log_stream_name + "\n"
        fancycanarynamedict = dict()
        fancycanarynamedict['testEST'] = "EST Provisioning API canary"
        fancycanarynamedict['testvinaya'] = "IAP/Switch Device connection API Canary"
        fancycanarynamedict['ccs_aquila_device_api_check'] = "CCS Aquila Device API Canary"
        fancycanarynamedict['ccs_pavo_device_api_check'] = "CCS Aquila Device API Canary"
        fancycanarynamedict['ccs_aquila_license_api_check'] = "CCS Aquila License API Canary"
        fancycanarynamedict['ccs_pavo_license_api_check'] = "CCS Aquila License API Canary"
        fancycanarynamedict['ccs_gemini_role_api_check'] = "CCS Gemini CCS Role Assignment API Canary"
        fancycanarynamedict['ccs_aquila_role_api_check'] = "CCS Aquila CCS Role Assignment API Canary"
        
        if _canary_name in fancycanarynamedict.keys(): 
            _printed_canary_name = fancycanarynamedict[_canary_name]
        else:
            _printed_canary_name = _canary_name 
        mystring = "The report for *" + _printed_canary_name + "*\n"
        mystring += "\n The *ERROR* reported is : _" + self._errorstring + "_ \n"
        #Attach the responsible persons from the error list from slack user json 
        _firstlevelusers = self._internal_dict[_canary_name]
        _format_string ="Hi ,"
        for i in _firstlevelusers: 
            _format_string += "<@" + i + "> , "
        if self._errorstring == "None!" :
            _format_string += "\n No Error! Chill for now !"
        else:
            _format_string += "\n Can you please look at Error reported above?\n\n"
        mystring += _format_string
        if 'context' in kwargs.keys(): 
            mystring += _contextstring
        #Check for the API list which are fired as a part of the API canary ... 
        if 'apilist' in kwargs.keys(): 
            apistring = "\n *The API List tested in Canary * : \n"
            for i in kwargs['apilist'] : 
                apistring += "\n " + i 
            mystring += apistring 
        return mystring
            
            
'''.    
This is the class of getting the secret links from the Parameter Store only for Slack Parameter
Author: murari.bhattacharyya@hpe.com
Parameter: name_of_secret : The secret which is stored in AWS Systems Manager and retrieved 
'''
class CCSSlackParameter():
      _generalslackweblink = None 
      def __init__(self, name_of_secret):
          logger.debug("Trying to decode the key value %s" %name_of_secret)
          myclient =boto3.client('ssm')
          parameter = myclient.get_parameter(Name=name_of_secret, WithDecryption=True)
          
          logger.info("The decoded value is %s" %parameter['Parameter']['Value'])
          self._generalslackweblink = parameter['Parameter']["Value"]
      def get_slack_weblink(self): 

          return self._generalslackweblink 
'''
Class CCS Parameter Store 
This is to get the parameter 

This class is needed for CCS Parameter store 
Author : murari.bhattacharyya@hpe.com
'''

class CCSParameterStore():
      _secret = None 
      def __init__(self, name_of_secret):
          logger.debug("Trying to decode the key value %s" %name_of_secret)
          myclient =boto3.client('ssm')
          parameter = myclient.get_parameter(Name=name_of_secret, WithDecryption=True)
          
          logger.info("The decoded value is %s" %parameter['Parameter']['Value'])
          self._secret = parameter['Parameter']["Value"]
      def get_secret(self): 
          return self._secret
          


