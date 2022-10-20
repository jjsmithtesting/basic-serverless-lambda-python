#Lambda function 
#Purpose : To test the APP roles ....... 
import json
import importlib

import os 

import hpe_ccs_automation_lib
from hpe_ccs_automation_lib.session.ui.uisession import *
try:
    import simplejson as json
except ImportError:
    import json
import time
import pprint
import logging
import requests
import urllib.parse as urlparse
from CCSBotolibs import CCSCanaryException , CCSSlackFormatter ,CCSCanaryInfra ,CCSParameterStore ,CCSSlackParameter,CCSLambdaInvoker,CCSClusterUIAPIOps,CCSUTCTimeStamp,ClusterDict

from functools import wraps
from requests.exceptions import HTTPError, Timeout
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


'''
Function to login into the account and load the PCID  from the data
'''
def operation_login(**kwargs): 
    errcount = 0 
    if 'uiobject' in kwargs.keys(): 
        myuiobj = kwargs['uiobject']
        
    else:
        raise CCSCanaryException("Login requires an UI object")
    if 'pcid' in kwargs.keys(): 
        _pcid = kwargs['pcid']
    else:
        raise CCSCanaryException("Please provide an Login Username")
    try: 
        res = myuiobj.login() 
        if res == None : 
             logger.info("Successfully logged in to the account ")
        
        else:
             logger.error("Could not perform the login operation")
             errcount += 1 
    # except SessionException as error: 
    #     logger.error('Could not log in with session exception %s' %error)
    #     errcount += 1 
    except Exception as error: 
        logger.error('Could not log in with general exception %s' %error)
        errcount += 1 
    try: 
        res = myuiobj.load_account(_pcid)
        if res['status'] == "success":  
            logger.info("Successfully logged in to the account ")
        else: 
            logger.error("Not able to load the account %s" %_pcid)
            errcount += 1
    except Exception as error: 
        logger.error('Could not log in with general exception %s' %error)
        errcount += 1 
    if errcount > 0: 
        return  myuiobj ,False 
    logger.debug(myuiobj.session.cookies)
    
    return myuiobj ,True 

    
def lambda_handler(event, context):
    
    myslackapproledict = dict()
   
    myslackapproledict['apilist'] = list()
    myslackcreatedeleteroledict = dict()
    myslackcreatedeleteroledict['apilist'] = list()
    
    mytimestamp = CCSUTCTimeStamp()
    mytime = str(mytimestamp.generatetimestamp())
    
    mydata = {'lambdaarn': 'arn:aws:lambda:eu-west-3:112136210529:function:CCSWebSocketBroadcast'}
    mywebsockethook = CCSLambdaInvoker(**mydata)
    mydata = {'lambdaarn': 'arn:aws:lambda:eu-west-3:112136210529:function:CCSRaisePagerDutyIncident'}
    myPagerDutyIncident = CCSLambdaInvoker(**mydata)
    myregiondict = { 'eu-west-3' : 'Paris' ,'ap-southeast-1' : 'Singapore' , 'ap-south-1' :"Mumbai" ,'us-west-1': 'NCalifornia'}
    #Get the slack webhook , one for dev another for Gemini tests 
    myslackparameter = CCSSlackParameter('/hpe/ccs/productionmonitoringslackhook')
    myslackformatter = CCSSlackFormatter()
    myqaslackformatter = CCSSlackFormatter('/hpe/ccs/productionmonitoringslackhookqa')
    #Inserting into the DynamoDB
    mydata = {'lambdaarn': 'arn:aws:lambda:eu-west-3:112136210529:function:ccsInsertDynamoDB'}
    myDynamoDBInsert = CCSLambdaInvoker(**mydata)
    region = os.environ['AWS_REGION']
    print("This canary is running in %s in time %s" %(region, mytime))
    logger.info("This Canary is running in %s" %region)
    if 'cluster' in event.keys(): 
        logger.debug("We are testing the API in cluster %s" %event['cluster'])
        _cluster = event['cluster']
        
        myslackapproledict['canary_name'] = "ccs_" + _cluster +"_app_role_assign_unassign"
        myslackcreatedeleteroledict['canary_name'] = "ccs_" + _cluster + "_app_role_create_delete"
        
        logger.debug("The following  canaries {} would be covered : ".format(myslackapproledict['canary_name']))
        _securestring= '/hpe/ccs/uidoorway/'+ _cluster + '/'
        _usernamestr = _securestring + 'username'
        c1 = CCSParameterStore(_usernamestr)
        username = c1.get_secret()
        _passwordstr= _securestring + 'password'
        c2 = CCSParameterStore(_passwordstr)
        password = c2.get_secret()
        _pcidstr= _securestring + 'pcid'
        c3 = CCSParameterStore(_pcidstr)
        pcid = c3.get_secret()
        _hoststr = _securestring + 'host'
        c4 = CCSParameterStore(_hoststr)
        host = c4.get_secret()
        logger.debug("Trying to login with username {} in host {}".format(username,host))
        #Get the operations which are being performed for the cluster 
        _clusteropslist = event['operation']
        _clusterops = list()
        print(_clusteropslist)
        for i in _clusteropslist: 
            _clusterops.append(i.keys())
        logging.debug("We are doing the following cluster operations %s" %_clusterops)
    else:
        raise CCSCanaryException("Please pass the cluster API")
    
    
   
    try:
        myUISession = UISession(host=host, username=username, password=password)
    except Exception as e:
      print(e)
    mylogindict = {
        'uiobject' :myUISession , 'pcid' :pcid
    }
    myuisess ,retval =operation_login(**mylogindict)
    if retval:
         logger.debug("Successfully logged in") 
    else: 
        logger.error("Could not log in to the system ,raising Aquila UI Login failed alarm")
        return {
        'statusCode': 500,
        'body': json.dumps('Could not log in to the system via UI Login')
    }
    myclusterdict = { 'cluster' : _cluster } 
    myclusterptr = ClusterDict(**myclusterdict)
    cookies = myuisess.session.cookies
    myclusterops = CCSClusterUIAPIOps(myclusterptr,myuisess)
    #This is a variable to store the devices error 
    appassignunassignerror = 0 
    approlecreatedeleteerror = 0 
    #Hardcoded for now , but will change it to something soft ...
    secondusername = "ccsqa2021@gmail.com"
    logger.debug("Checking the get call to check the role being there or not ")
    mydict = {}
    rrpcreationflag = False 
    logger.debug("Entering the App Role Creation and Deletion section....")
    mydict = {'ops' : 'GET','cookies': cookies ,'username' : username , 'pcid': pcid } 
    myretdict  = myclusterops.app_role_ui_calls(**mydict)
    if myretdict['status'] == True: 
       logger.info("The App role already exists , so trying check whether the role is assigned  role ")
       myslug = myretdict['slug']
       logger.debug("The slug is coming as %s" %myslug)
       myapplicationid = myretdict['application_id']
       logger.debug("The application id is coming as %s " %myapplicationid) 
       logger.debug("Trying to get the default Resource restriction policy ")
       mydict = {'ops' : 'GETRRP' ,'cookies': cookies ,'username' : username , 'pcid': pcid }
       myretdict = myclusterops.app_role_ui_calls(**mydict)
       if myretdict['status'] == True: 
           logger.debug("The Get RRP call returns RRPID as {} and PCID as {} and application id as {}".format(myretdict['resource_restriction_policy_id'],myretdict['platform_cid'] ,myretdict['application_id']))
           myrrpid = myretdict['resource_restriction_policy_id']
           myplatformcid = myretdict['platform_cid']
           myverificationappid = myretdict['application_id']
           # Trying to create an custom RRP for use ...
           
           #Get the Slug to assign the role properly ... as the earlier call went through we are not verifying too much in that 
           mydict = {'ops' : 'GET','cookies': cookies ,'username' : secondusername , 'pcid': pcid } 
           myretdict  = myclusterops.app_role_ui_calls(**mydict)
           myslug = myretdict['slug']
           myapplicationid = myretdict['application_id']
           rrparray = [ myrrpid ]
           #Check that whether the role is already assigned , for error path 
           logger.debug("Trying to check if the role is already assigned ")
           mydict = {'ops' : 'CHECKAPPROLEASSIGNMENT','cookies': cookies ,'username' : secondusername , 'pcid': pcid  }
           myretdict = myclusterops.app_role_ui_calls(**mydict)
           if myretdict['status'] == True: 
                logger.debug("The role is correctly assigned to the user, trying to unassign ")
                mydict = {'ops' : 'UNASSIGN','cookies': cookies ,'username' : secondusername , 'pcid': pcid  ,'slug' : myslug,'application_id': myapplicationid}
                myretdict = myclusterops.app_role_ui_calls(**mydict)
                #Get the status 
                if myretdict['status'] == True:
                    logger.info("We have successfully unassigned the role")
                    logger.info("Now we are trying to delete the role ")
                           
                else:
                    logger.error("We could not successfully unassign the role, trying delete the role directly  ")
                    appassignunassignerror += 1
                    myslackcreatedeleteroledict['errorcode'] = myretdict['errorcode']
                    
           else:
               logger.debug("This is the recovery path , so no testing and deleting ")
           
          
       else: 
           logger.error("The get RRP call did not get the corresponding RRP ID")
           
           #Add the failure message as per the things .
           
       logger.info("Trying to delete the APP role after the test ")
       mydict = {'ops' : 'DELETE','cookies': cookies ,'username' : secondusername , 'pcid': pcid  ,'slug' : myslug ,'application_id': myapplicationid}
       myretdict = myclusterops.app_role_ui_calls(**mydict)
       for i in myretdict['apilist']:
           myslackcreatedeleteroledict['apilist'].append(i)
       if myretdict['status'] == True: 
           logger.info("The App role is successfully deleted")
       else:
           logger.error("The app role is not successfully deleted")
           approlecreatedeleteerror += 1
           myslackcreatedeleteroledict['errorcode'] = myretdict['errorcode']
                    
    else:
        logger.info("The App role does not exist , so trying not to create the role  ")
        mydict = {'ops' : 'CREATE','cookies': cookies ,'username' : secondusername , 'pcid': pcid  }
        myretdict = myclusterops.app_role_ui_calls(**mydict)
        for i in myretdict['apilist']:
           myslackcreatedeleteroledict['apilist'].append(i)
        if myretdict['status'] == True: 
            logger.info("Successfully created the app role ")
            myslug = myretdict['slug']
            time.sleep(3)
            logger.info("Trying to get the slug of the created role ")
            mydict = {'ops' : 'GET','cookies': cookies ,'username' : secondusername , 'pcid': pcid } 
            myretdict  = myclusterops.app_role_ui_calls(**mydict)
            for i in myretdict['apilist']:
                myslackapproledict['apilist'].append(i)
            if myretdict['status'] == True: 
                logger.debug("Trying to get the resource restriction policy to taatch with the APP role assign call")
                mydict = {'ops' : 'GETRRP' ,'cookies': cookies ,'username' : secondusername , 'pcid': pcid }
                myretdict = myclusterops.app_role_ui_calls(**mydict)
                if myretdict['status'] == True: 
                   logger.debug("The Get RRP call returns RRPID as {} and PCID as {} and application id as {}".format(myretdict['resource_restriction_policy_id'],myretdict['platform_cid'] ,myretdict['application_id']))
                   myrrpid = myretdict['resource_restriction_policy_id']
                   myplatformcid = myretdict['platform_cid']
                   myverificationappid = myretdict['application_id']
                   #Get the Slug to assign the role properly ... as the earlier call went through we are not verifying too much in that 
                   mydict = {'ops' : 'GET','cookies': cookies ,'username' : secondusername , 'pcid': pcid } 
                   myretdict  = myclusterops.app_role_ui_calls(**mydict)
                   for i in myretdict['apilist']:
                       myslackapproledict['apilist'].append(i)
                   myslug = myretdict['slug']
                   myapplicationid = myretdict['application_id']
                   rrparray = [ myrrpid ]
                   logger.debug("Trying to assign the role with default RRP")
                   mydict = {'ops' : 'ASSIGN','cookies': cookies ,'username' : secondusername , 'pcid': pcid  ,'slug' : myslug,'application_id': myapplicationid,'rrp': rrparray}
                   myretdict = myclusterops.app_role_ui_calls(**mydict)
                   for i in myretdict['apilist']:
                       myslackapproledict['apilist'].append(i)
                   if myretdict['status'] == True: 
                       logger.info("We have successfully assigned the role , checking with role assignment call")
                       mydict = {'ops' : 'CHECKAPPROLEASSIGNMENT','cookies': cookies ,'username' : secondusername , 'pcid': pcid  }
                       myretdict = myclusterops.app_role_ui_calls(**mydict)
                       for i in myretdict['apilist']:
                           myslackapproledict['apilist'].append(i)
                       if myretdict['status'] == True: 
                           logger.debug("The role is correctly assigned to the user")
                       else:
                           logger.error("The role is not correctly assigned to the user")
                           appassignunassignerror += 1 
                       #TO DO: How to find if the role is assigned 
                       logger.debug("Trying to unassign the role ....")
                       mydict = {'ops' : 'UNASSIGN','cookies': cookies ,'username' : secondusername , 'pcid': pcid  ,'slug' : myslug,'application_id': myapplicationid}
                       myretdict = myclusterops.app_role_ui_calls(**mydict)
                       for i in myretdict['apilist']:
                           myslackapproledict['apilist'].append(i)
                       if myretdict['status'] == True:
                           logger.info("We have successfully unassigned the role")
                           logger.info("Now we are trying to delete the role ")
                           
                       else:
                           logger.error("We could not successfully unassign the role ")
                           logger.error("Trying to delete the role ")
                           appassignunassignerror += 1
                else: 
                   logger.error("The get RRP call did not get the corresponding RRP ID")
           #Add the failure message as per the things .
                #Now trying to delete the role 
                
                mydict = {'ops' : 'GET','cookies': cookies ,'username' : secondusername , 'pcid': pcid } 
                myretdict  = myclusterops.app_role_ui_calls(**mydict)
                for i in myretdict['apilist']:
                    myslackapproledict['apilist'].append(i)
                myslug = myretdict['slug']
                myapplicationid = myretdict['application_id']
                logger.info("Now trying to delete the role ")
                mydict = {'ops' : 'DELETE','cookies': cookies ,'username' : secondusername , 'pcid': pcid  ,'slug' : myslug,'application_id': myapplicationid}
                myretdict = myclusterops.app_role_ui_calls(**mydict)
                for i in myretdict['apilist']:
                     myslackcreatedeleteroledict['apilist'].append(i)
        
                if myretdict['status'] == True: 
                  logger.info("The App role is successfully deleted")
                else:
                  logger.error("The app role is not successfully deleted")
                  approlecreatedeleteerror += 1
                  myslackcreatedeleteroledict['errorcode'] = myretdict['errorcode']
                    
     
            else: 
                logger.error("We are not able to delete the role ")
                approlecreatedeleteerror += 1
                myslackcreatedeleteroledict['errorcode'] = myretdict['errorcode']
                    
        else:
            logger.error("Could not successfully create the app role ")
            approlecreatedeleteerror += 1
            myslackcreatedeleteroledict['errorcode'] = myretdict['errorcode']
    
    _canary_name = myslackapproledict['canary_name']
    if appassignunassignerror > 0:
        _status = False 
    else:
        _status = True
    mydynamodblambdadata = {
        "event_type": "insert",
        "tablename": "CCSProductionMonitoringResults",
        "data": {
            "cluster": _cluster.upper(),
            "incident_id" : None, 
            "canary_name": _canary_name,
                "primary": True ,
                "status": _status ,
                "region_name": os.environ['AWS_REGION'],
                "url" : myslackapproledict['apilist']
            }
        }
    try: 
        retval = myDynamoDBInsert.insert_dynamodb(**mydynamodblambdadata)
        if retval :
            logger.info("DynamoDB insertion done correctly for %s " %myslackapproledict['canary_name'])
        else:
            logger.error("DynamoDB insertion did not go well %s" %myslackapproledict['canary_name'])
    except Exception as error: 
        logger.error(error)                
    if appassignunassignerror > 0: 
        logger.error("Notifying the webhook and the slack channel ")
        myslackcreatedeleteroledict['context'] = context
        if _cluster.upper() == "GEMINI": 
            logger.error("Posting for Gemini for the failed run in QA channel")
            _header = _cluster + " : CCS  APP Role Assign Unassign Get API calls"
            mystring = myqaslackformatter.format_the_userlist(**myslackapproledict)
            logger.debug("We are getting the slack message to be reported as %s" %mystring)
            myqaslackformatter.paste_in_slack_channel(mystring)
        elif _cluster.upper() == 'AQUILA':
            
            mypagerdutyincident = { 'canary_name' : myslackcreatedeleteroledict['canary_name'] , "cluster" : _cluster.upper() , "region" : myregiondict[region]  } 
            myPagerDutyIncident.create_pagerduty(**mypagerdutyincident)
            logger.error("Notifying the webhook and the slack channel ")
            myslackcreatedeleteroledict['context'] = context
            _header = _cluster + " : CCS  APP Role Assign Unassign Get API calls"
            mystring = myslackformatter.format_the_userlist(**myslackapproledict)
            logger.debug(mystring)
            myslackformatter.paste_in_slack_channel(mystring)
        _header = _cluster + " : CCS  APP Role Assign Unassign Get API calls"
        mywebsocketdata ={ "type": "error", "timestamp": mytime,
            "data": {"status": "red", "header": _header, "details": "Failed "}
        }
        mywebsockethook.put_to_websocket(**mywebsocketdata)
    else: 
        logger.info("Notifying the Websocket and Slack production QA channel")
        if _cluster.upper() == "GEMINI": 
            
            logger.info("Posting for Gemini for the passed run in QA channel")
            _header = _cluster + " : CCS APP Role Assign Unassign Get API calls"
            myqastring = myqaslackformatter.format_the_userlist(**myslackapproledict)
            logger.debug(myqastring)
            ##Enabled to paste pass run in Alternate channel.
            myqaslackformatter.paste_in_slack_channel(myqastring)

        elif _cluster.upper() == "AQUILA":
            logger.info("Posting for Aquila for the failed run in QA channel")
            _header = _cluster + " : CCS APP Role Assign Unassign Get API calls"
            mystring = myqaslackformatter.format_the_userlist(**myslackapproledict)
            logger.debug(mystring)
            #myslackformatter.paste_in_slack_channel(mystring)
            
        else:
            raise CCSCanaryException("Cluster not supported !")
            
        _header = _cluster + " : CCS  APP Role Assign Unassign Get API calls"
        mywebsocketdata ={ "type": "notification", "timestamp": mytime,
             "data": {"status": "green", "header": _header, "details": "Passed "}
            }
        mywebsockethook.put_to_websocket(**mywebsocketdata)
        
    _canary_name = myslackcreatedeleteroledict['canary_name']
    
    if approlecreatedeleteerror > 0:
        _status = False 
    else:
        _status = True
    mydynamodblambdadata = {
        "event_type": "insert",
        "tablename": "CCSProductionMonitoringResults",
        "data": {
            "cluster": _cluster.upper(),
            "incident_id" : None, 
            "canary_name": _canary_name,
                "primary": True ,
                "status": _status ,
                "region_name": os.environ['AWS_REGION'],
                "url" : myslackcreatedeleteroledict['apilist']
            }
        }
    try: 
        retval = myDynamoDBInsert.insert_dynamodb(**mydynamodblambdadata)
        if retval :
            logger.info("DynamoDB insertion done correctly for %s " %myslackcreatedeleteroledict['canary_name'])
        else:
            logger.error("DynamoDB insertion did not go well %s" %myslackcreatedeleteroledict['canary_name'])
    except Exception as error: 
        logger.error(error) 
        
    if approlecreatedeleteerror > 0: 
        logger.error("Notifying the webhook and the slack channel ")
        myslackcreatedeleteroledict['context'] = context
        if _cluster.upper() == "GEMINI": 
            logger.error("Posting for Gemini for the failed run in QA channel")
            _header = _cluster + " : CCS  APP Role Creation Deletion API calls"
            mystring = myqaslackformatter.format_the_userlist(**myslackcreatedeleteroledict)
            logger.debug("We are getting the slack message to be reported as %s" %s)
            myqaslackformatter.paste_in_slack_channel(mystring)
        elif _cluster.upper() == 'AQUILA':
            
            mypagerdutyincident = { 'canary_name' : myslackroledict['canary_name'] , "cluster" : _cluster.upper() , "region" : myregiondict[region]  } 
            myPagerDutyIncident.create_pagerduty(**mypagerdutyincident)
            logger.error("Notifying the webhook and the slack channel ")
            myslackcreatedeleteroledict['context'] = context
            _header = _cluster + " : CCS  App Role Creation / Deletion  API calls"
            mystring = myslackformatter.format_the_userlist(**myslackcreatedeleteroledict)
            logger.debug(mystring)
            myslackformatter.paste_in_slack_channel(mystring)
        _header = _cluster + " : CCS  App Role Creation / Deletion  API calls"
        mywebsocketdata ={ "type": "error", "timestamp": mytime,
            "data": {"status": "red", "header": _header, "details": "Failed "}
        }
        mywebsockethook.put_to_websocket(**mywebsocketdata)
    else: 
        logger.info("Notifying the Websocket and Slack production QA channel")
        if _cluster.upper() == "GEMINI": 
            
            logger.info("Posting for Gemini for the passed run in QA channel")
            _header = _cluster + " : CCS  App Role Creation / Deletion  API calls"
            myqastring = myqaslackformatter.format_the_userlist(**myslackcreatedeleteroledict)
            logger.debug(myqastring)
            ##Enabled to paste pass run in Alternate channel.
            myqaslackformatter.paste_in_slack_channel(myqastring)

        elif _cluster.upper() == "AQUILA":
            logger.info("Posting for Aquila for the failed run in QA channel")
            _header = _cluster + " : CCS  App Role Creation / Deletion  API calls"
            mystring = myqaslackformatter.format_the_userlist(**myslackcreatedeleteroledict)
            logger.debug(mystring)
            #myslackformatter.paste_in_slack_channel(mystring)
            
            
        _header = _cluster + " : CCS  App Role Creation / Deletion  API calls"
        mywebsocketdata ={ "type": "notification", "timestamp": mytime,
             "data": {"status": "green", "header": _header, "details": "Passed "}
            }
        mywebsockethook.put_to_websocket(**mywebsocketdata)
            
    myUISession.logout()
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from test UI Doorway APP Role Creation and deletion  ')
    }

