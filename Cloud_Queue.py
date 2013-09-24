#!/usr/bin/python
# -*- coding: utf-8 -*-
#Copyright 2013 Aaron Smith

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

"""
CREATING QUEUE
$ curl -i -X PUT https://ord.queues.api.rackspacecloud.com/v1/queues/test_queue -d'{"TestName": "My Test Queue Desctiption"}' \
                            -H"Content-type: application/json" -H"X-Auth-Token: AUTHTOKENGOESHERE" \
                            -H "Accept: application/json"

RETURN VALUE=====>>>
HTTP/1.1 201 CreatedContent-Length: 0
Location: /v1/queues/test_queueu


CONFIG FILE ---> you need to create a configuration file in named /etc/Cloud_Queue.conf.  The template is as follows:
#cat /etc/Cloud_Queue.conf
[rackspace_cloud]
username = YOURUSERNAME
api_key = YOURAPIKEY

[database_credentials]
db_syslog_user = 'XXXXXXX'
db_sylog_user_password = 'XXXXXX'
target_host = 'XXXXXX'
Syslog_database = 'XXXXXX'

#chmod 400 /etc/Cloud_Queue.conf
"""

#Need to use this url to get logging working...need console output for diagnostics while writing code
#--->  http://docs.python.org/dev/howto/logging.html

import pycurl
#import pyrax
import getpass
import cStringIO
import subprocess
import logging
import re
import os
import json
import subprocess
import sys
import pwd      # <---import 'the password database' to get access to user/group id info
import ConfigParser    # <----use to parse config file containing cloud credentials
import MySQLdb as mysqldb
try:
    import daemon
except:
    print "Please install python-daemon!.  \npip install python-daemon   \nOR   \neasy_install python-daemon"
try:
  import cPickle as pickle  # <---for dev purposes...saving objects for offline dev work
except:
  import pickle
import pprint   # <---also temp as of now for dev purposes

#========================================================================================
#SET UP GLOBAL VARIABLES
#========================================================================================
#RESPONSE = ''     #<----this will be used to capture pycurl buffer responses. we will reuse as necessary.
CONFIG_FILE = "/etc/Cloud_Queue.conf"
CREDS_FILE = "~/.rackspace_cloud_credentials"
LOG_FILE = '/var/log/Cloud_Queue.log'    # <--application log file
FIRST_RUN = True  # <--Must execute as root when first run so that it can create proper log files.  Assuming 'first-run' before check is done
F2BDB = 'f2b'
#========================================================================================
#SET UP LOGGING
#========================================================================================

#Checking for the existence of the Cloud_Queue log file and our conf file.  If they do not exist then leaving FIRST_RUN as True.
if os.path.exists(LOG_FILE) and os.path.exists(CONFIG_FILE):
  FIRST_RUN = False        # <---is log file and conf file exists then this is not first run

#Verifying that we can open and write to log file
f_log = ''    #<---initialze the file handle for our log file
conf_file = '' #<---initialize the conf file variable

try:
  f_log = open(LOG_FILE, "aw")
  conf_file = open(CONFIG_FILE, "aw")  
except IOError:
  if FIRST_RUN:
    print "This appears to be the first time you have executed this script.  You must execute with 'sudo' on first run!"
    print ""
    #could also check for root with 'if os.getuid() != 0:'
    sys.exit(1)
  if not f_log:
    print "Unable to open log file, '%s'.  Please check file permissions/ownership" % LOG_FILE
  if not conf_file:
    print "Unable to open configuration file, %s.  Please check file permissions/ovnership.  Also check the top of this script for config format" % CONFIG_FILE
  sys.exit(1)
finally:
  if f_log:
    f_log.close()
    #I have to do extra work to get uid/gid because when we sudo this script on first run the uid is 0.
    #We don't want to set the ownership of our log to 0 (or root) so we need to know 'who' executed the script
    my_uid = pwd.getpwnam(os.getlogin()).pw_uid   #<--get the UID of the user logged into this machine
    my_gid = pwd.getpwnam(os.getlogin()).pw_gid   #<--get the GID of the user logged into this machine
    os.chown(LOG_FILE, my_uid, my_gid)
  if conf_file:
    conf_file.close()

#Set up logging to file--->  remove the filemode ('w') to make the logs append to file rather than overwrite
logging.basicConfig(level=logging.DEBUG,
            format='%(name)-12s:%(levelname)-8s:%(asctime)s %(message)s',
            datefmt='%m-%d %H:%M',
            filename=LOG_FILE,
            filemode='w')

# define a 'console' Handler which writes to the console instead of a log file
console = logging.StreamHandler()
# set console handler logging level to DEBUG for console output
console.setLevel(logging.DEBUG)
# set a format for the console output
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
# tell the console handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)  # <-----We can create multiple handlers and attach to logger

# Now we can begin logging.  First we will log a message to the root logger
logging.info('This is my root logger - info.')

# create a name for a logger.  If we omitted this then the %(name) variable would be 'root', hence 'root' logger.
qlogger = logging.getLogger('CloudQueue')  #<---create as many as we want

# Now we will log a message to the 'qlogger' named logger.
qlogger.info('This is my named qlogger - debug')

###========================================================================================
### CAPTURE CLOUD USERNAME AND API KEY  --if we run from command line will need this
###========================================================================================
##
####Getting credentials needed to interact with Rackspace Cloud account
##qlogger.info("getting username and password..")
##cloud_username = raw_input('Enter Rackspace Cloud Username: ')
##cloud_api_key = raw_input('Enter Rackspace Cloud API key: ')
##qlogger.info("Done!")
##qlogger.info("Username entered: %s" % cloud_username)
##qlogger.info("API_Key entered: %s" % cloud_api_key)



#========================================================================================
# READ CONFIGURATION FILE AND PARSE CREDENTIALS   -need to set up config file with cloud creds and db creds
#========================================================================================
qlogger.info("Read and process local credential configuration file '%s'..." % CONFIG_FILE)
my_config = ConfigParser.ConfigParser()
my_config.read(os.path.expanduser(CONFIG_FILE))
my_sections = my_config.sections()
cred_dict = {}
for section in my_sections:
  options = my_config.options(section)
  for option in options:
    try:
      cred_dict[option] = my_config.get(section, option)
    except Exception as e:
      qlogger.error(e)
qlogger.info('Done reading file, setting creds...')
cloud_username = cred_dict['username'].strip("'")
cloud_api_key = cred_dict['api_key'].strip("'")
syslog_db_user = cred_dict['db_syslog_user'].strip("'")
syslog_db_user_pwd = cred_dict['db_sylog_user_password'].strip("'")
syslog_db_name = cred_dict['syslog_database'].strip("'")
syslog_db_host = cred_dict['target_host'].strip("'")
qlogger.info('Done!')
qlogger.info('Username: %s' % cloud_username)
qlogger.info('API Key: %s' % cloud_api_key)
qlogger.info('Syslog DB Name: %s' % syslog_db_name)
qlogger.info('Syslog DB Username: %s' % syslog_db_user)
qlogger.info("Syslog DB User Password: %s" % syslog_db_user_pwd )
qlogger.info('Syslog DB host: %s' % syslog_db_host)
if syslog_db_user_pwd:
  qlogger.info('Syslog DB password set correctly!')
else:
  qlogger.error('Syslog DB password might not be set correctly')
qlogger.info("Done processing local config file!")

#========================================================================================
# Authenticate to Rackspace cloud and retrieve API token:
#curl -D - -H"X-Auth-User: MY_CLOUD_USERNAME" -H"X-Auth-Key:MY_CLOUD_API__KEY" https://auth.api.rackspacecloud.com/v1.0
#========================================================================================
qlogger.info("Authenticating to Rackspace Cloud and retrieving API token")
auth_url = 'https://auth.api.rackspacecloud.com/v1.0'
content_type_header = "Content-type: application/json"
accept_header = "Accept: application/json"

c = pycurl.Curl()
body = cStringIO.StringIO()
hdr = cStringIO.StringIO()   #when we authenticate the information we require is returned in the header
c.setopt(c.WRITEFUNCTION, body.write)
c.setopt(c.HEADERFUNCTION, hdr.write)
c.setopt(c.URL, auth_url)
c.setopt(c.HTTPHEADER, ["X-Auth-User: %s" % cloud_username, "X-Auth-Key: %s" % cloud_api_key])
c.setopt(c.CONNECTTIMEOUT, 5)
c.setopt(c.TIMEOUT, 8)
c.setopt(c.VERBOSE, False)
c.setopt(c.SSL_VERIFYPEER, False)
c.setopt(c.FAILONERROR, True)
c.perform()
return_code = c.getinfo(pycurl.HTTP_CODE)
hdr_response = hdr.getvalue()
body_response = body.getvalue()

#print response
#print "status code: %s" % c.getinfo(pycurl.HTTP_CODE)
#print "effective URL: %s" % c.getinfo(pycurl.EFFECTIVE_URL)
token_line = hdr_response.splitlines()[8]  #<--This line contains the api token
cloud_api_token = token_line.split(":")[1].strip()
qlogger.info("Retrieved API Token: %s" % cloud_api_token)
#print cloud_api_token
c.close()

#========================================================================================
# SET UP CLASSES
#========================================================================================

q_url = 'https://ord.queues.api.rackspacecloud.com/v1/queues/'

class Cloud_Queue():
  """Rackspace Cloud Queue"""
  def __init__(self):
    self.q_url = q_url
    self.auth_url = auth_url
    self.username = cloud_username
    self.api_key = cloud_api_key
    self.api_token = cloud_api_token
    #self.queue_name = queue_name

  def Auth(self):
    """
    curl -D - -H"X-Auth-User: MYUSERNAME" -H"X-Auth-Key:MYAUTHKEY" https://auth.api.rackspacecloud.com/v1.0
    This method works but it will not save the buffer output for parsing.  Prob variable scope issue....?/
    
    TESTED THIS METHOD SUCCESSFULLY!
    """
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()     # when we authenticate the information we require is returned in the header
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, self.auth_url)
    c.setopt(c.HTTPHEADER, ["X-Auth-User:%s" % self.username, "X-Auth-Key:%s" % self.api_key])
    c.setopt(c.CONNECTTIMEOUT, 5)
    c.setopt(c.TIMEOUT, 8)
    c.setopt(c.VERBOSE, False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.FAILONERROR, True)
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    #print "status code: %s" % c.getinfo(pycurl.HTTP_CODE)
    #print "effective URL: %s" % c.getinfo(pycurl.EFFECTIVE_URL)
    token_line = hdr_response.splitlines()[8]  #<--This line contains the api token
    cloud_api_token = token_line.split(":")[1].strip()
    qlogger.info("Retrieved API Token: %s" % cloud_api_token)
    return cloud_api_token
    c.close()
    hdr.close()
    body.close()

  def createQueue(self, qname):
    """Create a Cloud Queue.  We will be using a pub/sub model for our queue as opposed to a producer/consumer model
    $ curl -i -X PUT https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUENAME \
    -d'{"TEST": "My Test Queue"}' \
    -H"Content-type: application/json" \
    -H"X-Auth-Token: MYAUTHTOKEN" \
    -H "Accept: application/json"
    
    HTTP/1.1 201 Created
    Content-Length: 0
    Location: /v1/queues/NEWQUEUENAME
    """
    content_type_header = "Content-type: application/json"
    accept_header = "Accept: application/json"
    auth_token_header = "X-Auth-Token: %s" % self.api_token
    payload_TTL = 300    # <--5 minutes
    payload_BODY = "{'Creating Queue -> Name': %s}" % qname
    payload = "['ttl': %d, 'body': '%s']" % (payload_TTL, payload_BODY)
    useragent = "KidRack"
    
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()     # when we authenticate the information we require is returned in the header
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, (self.q_url + qname))
    c.setopt(pycurl.PUT, 1)
    c.setopt(c.HTTPHEADER, [auth_token_header, accept_header, content_type_header])
    c.setopt(c.USERAGENT, useragent)
    c.setopt(c.CONNECTTIMEOUT, 5)
    c.setopt(c.TIMEOUT, 8)
    c.setopt(c.VERBOSE, False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.FAILONERROR, True)
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    #body_response = body.getvalue()  # <-- no body returned on queue creation
    
    #we expect to get a 204 no content return header
    if return_code == 201:
      qlogger.info("Queue named '%s' successfully created" % qname)
    else:
      qlogger.error("Unable to create queue!")
      sys.exit(1)
    return "Successfully created queue '%s'" % qname
    body.close()
    hdr.close()
    c.close()

  def checkQueue(self, qname):
    """Use this to check for a queue's existence.  Good sanity check during script initialization to make sure our queue is visible before pumping
    messages to it.
    
    $ curl -i -X GET https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUNAME\
    -H "X-Auth-Token: MYAUTHTOKEN"
    
    HTTP/1.1 204 No Content
    Content-Location: /v1/queues/NEWQUEUNAME
    
    THIS METHOD SUCCESSFULLY TESTED
    """
    auth_token_header = ["X-Auth-Token: %s" % self.api_token]
    useragent = "KidRack"
    
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, (self.q_url + qname))
    c.setopt(c.VERBOSE,False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.USERAGENT, useragent)
    c.setopt(c.HTTPHEADER, auth_token_header)
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    if return_code == 204:
      qlogger.info("Queue Named '%s' DOES exist!" % qname)
    
    body.close()
    hdr.close()
    c.close()


  def listQueues(self):
    """
    Return a list of queueus currently available on this account.
    $ curl -i -X GET https://ord.queues.api.rackspacecloud.com/v1/queues -H "X-Auth-Token: MyAPITOKEN"
    HTTP/1.1 200 OK
    Content-Length: 146
    Content-Type: application/json; charset=utf-8
    Content-Location: /v1/queues
    
    {"queues": [{"href": "/v1/queues/NEWQUEUNAME", "name": "NEWQUEUNAME"}], "links": [{"href": "/v1/queues?marker=NEWQUEUNAME", "rel": "next"}]}
    
    TESTED THIS METHOD AND IT WORKS
    """
    auth_token_header = ["X-Auth-Token: %s" % self.api_token]
    useragent = "KidRack"
    
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, q_url)
    c.setopt(c.VERBOSE, False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.USERAGENT, useragent)
    c.setopt(c.HTTPHEADER, auth_token_header)
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    if return_code != 200:
      qlogger.warning('Possible error.  HTTP response code on API all is NOT 200!')
    print "the HEADER:"
    print hdr_response
    print "BODY:"
    print body_response
    
    body.close()
    hdr.close()
    c.close()


  def sendMessage(self, qname, message):
    """$ curl -i -X POST https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUNAME/messages \
    -d '[{ "ttl": 300, "body": {"event": "First message sent"}}, {"ttl": 60, "body": {"event2": "This is my 2nd message"}}]' \
    -H "Content-type: application/json" \
    -H "Client-ID: QClient" \
    -H "X-Auth-Token: MYAUTHTOKEN" \
    -H "Accept: application/json"
    
    HTTP/1.1 201 Created
    Content-Length: 157
    Content-Type: application/json; charset=utf-8
    Location: /v1/queues/NEWQUEUNAME/messages?ids=5228aa514513ce5976532dbb,5228aa514513ce5976532dbc      #<----Notice the 2 id's…FIFO--message 1 is id 1, etc

    {"partial": false, "resources": ["/v1/queues/NEWQUEUNAME/messages/5228aa514513ce5976532dbb", "/v1/queues/NEWQUEUNAME/messages/5228aa514513ce5976532dbc"]}
    
    qname ::  This is the name of our queue where we are sending messages
    method ::  This is the portion of the URL endpoint just after the queue name.  Possible values ['messages', 'stats', 'claims'] but always
              'messages' for this function
    message :: This is the message we want to broadcast on the queue.  We are just supplying an IP address as the message
    """
    qclient_header = "Client-ID: QClient"
    content_type_header = "Content-type: application/json"
    accept_header = "Accept: application/json"
    auth_token_header = "X-Auth-Token: %s" % cloud_api_token
    #q_url = "https://ord.queues.api.rackspacecloud.com/v1/queues/"
    payload_TTL = 60    # <--5 minutes
    #for test lests set a banned IP and try a message
    #banned_ip = message   # <---temporary...this will provided by calling function as part of the 'message' parameter
    #syslog_id = '34534534'   # <--- this will provided by calling function as part of the 'message' parameter
    #message = """{"Banned IP": "%s", "SyslogID": "%s"}""" % (banned_ip, syslog_id)  #this is returned from SyslogDB.fidnBan
    payload = """[{"ttl": %d, "body": "%s"}]""" % (payload_TTL, message)    # <--we can extend this payload with multiple messages
    useragent = "KidRack"
    #myurl = q_url
    myurl = 'https://ord.queues.api.rackspacecloud.com/v1/queues/%s/messages' % qname
    print "this is the payload i would try to use:"
    print payload
    print ""
    print "payload done:"
    print ""
    cmd = """(curl -i -X POST %s \
    -d '%s' \
    -H "Content-type: application/json" \
    -H "Client-ID: QClient" \
    -H "X-Auth-Token: %s" \
    -H "Accept: application/json")
    """ % (myurl, payload, cloud_api_token)
    #% (send_message_url, payload, content_type_header, qclient_header, auth_token_header, accept_header)
    subprocess.call(cmd, shell=True)




 
  def claimMessage(self, qname, method='claims'):
    """Claim messages from {qname}
    
    $ curl -i -X POST https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUNAME/claims \
    -d'{"ttl": 300, "grace": 300}' \
    -H "Content-Type: application/json" \
    -H "Client-ID: QClient" \
    -H "X-Auth-Token: MYAUTHTOKEN" \
    -H "Accept: application/json"
    
    HTTP/1.1 201 Created
    Content-Length: 344
    Content-Type: application/json; charset=utf-8
    Location: /v1/queues/NEWQUEUNAME/claims/5228aa856f1ecd56dc002ef6
    
    [{"body": {"event": "First message sent"}, "age": 52, "href": "/v1/queues/NEWQUEUNAME/messages/5228aa514513ce5976532dbb?claim_id=5228aa856f1ecd56dc002ef6", "ttl": 300}, {"body": {"event2": "This is my 2nd message"}, "age": 52, "href": "/v1/queues/NEWQUEUNAME/messages/5228aa514513ce5976532dbc?claim_id=5228aa856f1ecd56dc002ef6", "ttl": 60}]
    """
    qclient_header = "Client-ID: QClient"
    content_type_header = "Content-type: application/json"
    accept_header = "Accept: application/json"
    auth_token_header = "X-Auth-Token: %s" % self.api_token
    #q_url = "https://ord.queues.api.rackspacecloud.com/v1/queues/"
    payload_TTL = 300    # <--5 minutes
    payload_GRACE = 300
    payload_BODY = "{'grace': %d}" % payload_GRACE
    payload = "['ttl': %d, 'body': '%s']" % (payload_TTL, payload_BODY)    # <--we can extend this payload with multiple messages
    useragent = "KidRack"
    
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, (self.q_url + qname + '/' + method))
    c.setopt(c.VERBOSE, False)
    c.setopt(pycurl.POST, 1)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.USERAGENT, useragent)
    c.setopt(c.HTTPHEADER, qclient_header)
    c.setopt(c.HTTPHEADER, content_type_header)
    c.setopt(c.HTTPHEADER, accept_header)
    c.setopt(c.HTTPHEADER, auth_token_header)
    c.setopt(c.POSTFIELDS, payload)
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    
    print "the HEADER:"
    print hdr_response
    print ""
    print "The BODY:"
    print body_response
    
    body.close()
    hdr.close()
    c.close()


  def checkStats(self, qname, method='stats'):
    """
    $ curl -i -X GET https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUNAME/stats \
    -H "X-Auth-Token: MYAUTHTOKEN"
    
    HTTP/1.1 200 OK
    Content-Length: 51
    Content-Type: application/json; charset=utf-8
    Content-Location: /v1/queues/NEWQUEUNAME/stats
    
    {"messages": {"claimed": 0, "total": 0, "free": 0}}
    
    
    TESTED SUCCESSFULLY
    """
    auth_token_header = "X-Auth-Token: %s" % self.api_token
    #q_url = "https://ord.queues.api.rackspacecloud.com/v1/queues/"  
    useragent = "KidRack"
    
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, (self.q_url + qname + '/' + method))
    c.setopt(c.VERBOSE,False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.USERAGENT, useragent)
    c.setopt(c.HTTPHEADER, [auth_token_header])
    c.perform()
    return_code = c.getinfo(pycurl.HTTP_CODE)
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    
    print "the HEADER:"
    print hdr_response
    print ""
    print "The BODY:"
    print body_response
    
    body.close()
    hdr.close()
    c.close()


  def listMessages():
    """
    GET /v1/queues/{queue_name}/messages{?marker,limit,echo,include_claimed}
    
    $ curl -i -X GET https://ord.queues.api.rackspacecloud.com/v1/queues/NEWQUEUNAME/messages \
    -H "Client-ID: QClient" \
    -H "X-Auth-Token: MYAUTHTOKEN" \
    -H "Accept: application/json"
    
    
    HAVING PROBLEMS LISTING MESSAGES!!!!!!
    """
    pass





class SyslogDB():
  """Manage connections to local mysql syslog database.  When we create the SyslogDB object it will automatically authenticate so we are
  ready to call methods to interact with db.
  
  ::target_host => This is where the syslog database will be located
  ::db_user => This is the mysql database user name used for interacting with the Syslog database
  ::db_password => This is the database user password
  ::Syslog_database => This is the syslog database name where all syslog messages are saved
  
  http://www.tutorialspoint.com/python/python_database_access.htm
  """
  
  def __init__(self, database, host=syslog_db_host, user=syslog_db_user, password=syslog_db_user_pwd):
    qlogger.info("======Initializing SyslogDB() object for mysql interface======")
    qlogger.info("Assembling arguments for our database object...")
    self.host = syslog_db_host
    self.database = database
    self.user = syslog_db_user
    self.password = syslog_db_user_pwd
    qlogger.info("Done!")



  def find_Bans(self, syslogID=0):
    """Execute SQL statements to interact with database and find banned IP addresses"""
    qlogger.info("Connecting to local Syslog database...")
    #Create connection
    db = mysqldb.connect(self.host, self.user, self.password, self.database)
    if db:
      qlogger.info("Successfully created database connection to %s!" % self.database)
    else:
      qlogger.error("Possible error connecting to database.  Check credentials")
    qlogger.info("Creating cursor() object used to send statements to mysql...")
    cursor = db.cursor()
    qlogger.info("Done creating cursor() object!")
    qlogger.info("======Syslog() database initialization complete!======")
    if syslogID:
      statement = "select ID,FromHost,DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%%' and Message like '%% Ban %%' and ID > %s;" % syslogID
    else:
      statement = "select ID,FromHost,DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%%' and Message like '%% Ban %%';" 
    #This will find all messages from fail2ban that contain the string 'Ban'
    qlogger.info("Executing statement: %s" % statement)
    cursor.execute(statement)
    #To get row count of returned results
    qlogger.info("Statement executed")
    cursor.rowcount       #<---read-only attribute
    ##To fetch a single row at a time
    #data = cursor.fetchone()
    #To fetch all rows at once into tuples
    qlogger.info("Parsing statement return value...")
    all_data = cursor.fetchall()
    #Set up a message that will eventually contain the syslog ID of the message and the banned IP
    my_messages = []
    #construct and compile search pattern that will find IP addresses
    ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    for row in all_data:
      syslog_id = str(row[0])
      source_host = str(row[1])
      ip = re.findall(ip_pattern, row[4])
      #convert this msg to json data so we can access like a dictionary later
      msg = json.loads('{"sourceHost": "%s", "syslogID": "%s", "bannedIP": "%s"}' % (source_host, syslog_id, ip[0]))
      my_messages.append(msg)
    db.close()
    return my_messages
 
  def getLastID(self):
    """Get the last syslogID in the list and archive this.  It will be the starting point of subsequent queries"""
    qlogger.info("Connecting to local Syslog database...")
    #Create connection
    db = mysqldb.connect(self.host, self.user, self.password, self.database)
    if db:
      qlogger.info("Successfully created database connection to %s!" % self.database)
    else:
      qlogger.error("Possible error connecting to database.  Check credentials")
    qlogger.info("Creating cursor() object used to send statements to mysql...")
    cursor = db.cursor()
    qlogger.info("Done creating cursor() object!")
    qlogger.info("======Syslog() database initialization complete!======")
    statement = "select ID,FromHost,DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%' and Message like '% Ban %' order by ID DESC;"
    #This will find all messages from fail2ban that contain the string 'Ban'
    qlogger.info("Executing statement: %s" % statement)
    cursor.execute(statement)
    #To get row count of returned results
    qlogger.info("Statement executed")
    last_record = cursor.fetchone()
    return last_record[0]

  def archiveMessage(self, statement):
    """We need to update our f2b database with the sent message.  This will allow us to mine this data
    for the last syslogID processed, and subsequently only send unprocessed messages to the queue
    """
    qlogger.info("Connecting to local Syslog database...")
    #Create connection
    db = mysqldb.connect(self.host, self.user, self.password, self.database)
    if db:
      qlogger.info("Successfully created database connection to %s!" % self.database)
    else:
      qlogger.error("Possible error connecting to database.  Check credentials")
    qlogger.info("Creating cursor() object used to send statements to mysql...")
    cursor = db.cursor()
    qlogger.info("Done creating cursor() object!")
    qlogger.info("======Syslog() database initialization complete!======")
    qlogger.info("Executing statement: %s" % statement)
    cursor.execute(statement)
    #To get row count of returned results
    qlogger.info("Statement executed")
    cursor.rowcount       #<---read-only attribute
    ##To fetch a single row at a time
    #data = cursor.fetchone()
    #To fetch all rows at once into tuples
    #qlogger.info("Parsing statement return value...")
    all_data = cursor.fetchall()
    db.close()





#========================================================================================
# LOGIC
#========================================================================================

#Create a connection to the f2b database
f2b_db_object = SyslogDB(F2BDB)
#Create a connection to the Syslog database
syslog_db_object = SyslogDB(syslog_db_name)

#Find the last syslogID that was processed and save it
last_syslogID = syslog_db_object.getLastID()
print last_syslogID

#Find all the banned IP addresses

#Return all messages unless syslogID provided to find_Bans() method
qmessages = syslog_db_object.find_Bans()   # <--this returns a list of strings
# print ""
# print ""

# #add banned ip address messages to f2b database
# for ban in qmessages:
#     #insert each 'ban' message into our f2b database to track syslogIDs
#     msg = "INSERT INTO archived_messages (host, syslogid, bannedIP) VALUES ('%s', '%s', '%s');" % (ban['sourceHost'], ban['syslogID'], ban['bannedIP'])
#     f2b_db_object.archiveMessage(msg)


print ""
print ""
for ban in qmessages:
    print ban

send_IPs_to_queue = [i['bannedIP'] for i in qmessages]
send_IPs_to_queue = set(send_IPs_to_queue)  # <-- de-duplicate the list of IP addresses using 'set'
# for ip in send_IPs_to_queue:
#     print ip


q = Cloud_Queue()



