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

#This written using example taken from: http://developer.rackspace.com/blog/openstack-marconi-api.html.
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

import requests
import json
#import pyrax
import getpass
import pycurl
import cStringIO
import subprocess
import logging
import re
import os
import json
import requests
import subprocess
import argparse
import sys
import pwd      # <---import 'the password database' to get access to user/group id info
import ConfigParser    # <----use to parse config file containing cloud credentials
import MySQLdb as mysqldb
from time import sleep

# username = 'my-user'
# apikey = 'my-api-key'
# url = 'https://test.my-marconi-server.com:443'

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

q_url = 'https://ord.queues.api.rackspacecloud.com'
url = q_url

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
    #Create connection
    db = mysqldb.connect(self.host, self.user, self.password, self.database)
    if db:
      qlogger.info("Successfully created database connection to %s!" % self.database)
    else:
      qlogger.error("Possible error connecting to database.  Check credentials")
    cursor = db.cursor()
    #statement = "select ID,FromHost,DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%' and Message like '% Ban %' order by ID DESC;"
    statement = "select syslogid from f2b.archived_messages order by syslogid desc;"
    #This will find all messages from fail2ban that contain the string 'Ban'
    qlogger.info("Executing statement: %s" % statement)
    cursor.execute(statement)
    qlogger.info("Statement executed")
    last_record = cursor.fetchone()
    db.close()
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
    #cursor.rowcount       #<---read-only attribute
    ##To fetch a single row at a time
    #data = cursor.fetchone()
    #To fetch all rows at once into tuples
    #qlogger.info("Parsing statement return value...")
    all_data = cursor.fetchall()
    db.close()



class Queue_Connection(object):

  def __init__(self, username, apikey):
    url = 'https://identity.api.rackspacecloud.com/v2.0/tokens'
    payload  = {"auth":{"RAX-KSKEY:apiKeyCredentials":{"username": username , "apiKey": apikey }}}
    headers = {'Content-Type': 'application/json'}
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    self.token = r.json()['access']['token']['id']
    self.headers = {'X-Auth-Token' : self.token, 'Content-Type': 'application/json', 'Client-ID': 'QClient1'}

  def token(self):
    return self.token

  def get(self, url, payload=None):
    r = requests.get(url, data=json.dumps(payload), headers=self.headers)
    return [r.status_code, r.headers, r.content]

  def post(self, url, payload=None):
    r = requests.post(url, data=json.dumps(payload), headers=self.headers)
    return [r.status_code, r.headers, r.content]

  def put(self, url, payload=None):
    r = requests.put(url, data=json.dumps(payload), headers=self.headers)
    return [r.status_code, r.headers, r.content]

  def delete(self, url, payload=None):
    r = requests.delete(url, data=json.dumps(payload), headers=self.headers)
    return [r.status_code, r.headers, r.content]


class Producer(Queue_Connection):

    def __init__(self, url, username, apikey):
        super(Producer, self).__init__(username, apikey)               
        self.base_url = url

    def queue_name():
        def fget(self):
            return self._queue_name
        def fset(self, value):
            self._queue_name = value
        def fdel(self):
            del self._queue_name
        return locals()
    queue_name = property(**queue_name())


    def queue_exists(self):
        url = self.base_url + '/v1/queues/' + self.queue_name + '/stats'
        if self.get(url)[0] == 200:
            return True
        return False

    def create_queue(self, payload=None):
        url = self.base_url + "/v1/queues/" + self.queue_name
        res =  self.put(url, payload)
        if res[0] == 200:
            print '%s created' % self.queue_name
        elif res[0] == 204:
            print 'A queue named %s is present' % self.queue_name
        else:
            print 'Problem with queue creation,'

    def post_messages(self, payload):
        url = self.base_url + '/v1/queues/' + self.queue_name + '/messages'
        res = self.post(url, payload)
        if res[0] == 201:
            return json.loads(res[2])['resources']
        else:
            print "Couldn't post messages"

class Consumer(Queue_Connection):

    def __init__(self, url, username, apikey):
        super(Consumer, self).__init__(username, apikey)                
        self.base_url = url

    def claim_messages(self, payload, limit=1):
        url = self.base_url + '/v1/queues/' + self.queue_name + '/claims?limit=' + str(limit)
        res = self.post(url, payload)
        if res[0] == 200:
            return json.loads(res[2])
        else:
            print "Couldn't claim messages"

    def get_messages(self, limit=10):
        """
        $curl -i -X GET "https://ord.queues.api.rackspacecloud.com/v1/queues/kidrack_queue/messages?echo=true" 
        -H "Client-ID: QClient" -H "X-Auth-Token: AUTHTOKEN" -H "Content-type: application/json"
        """
        url = self.base_url + '/v1/queues/' + self.queue_name + '/messages?echo=true&limit=' + str(limit)
        payload = {'X-Auth-Token' : self.token, 'Content-Type': 'application/json'}
        #res = self.get(url)
        res = self.get(url, payload)
        print res

    def delete_message(self, url):
        url = self.base_url + url
        res = self.delete(url)
        if res[0] == 204:
            print "Message deleted"


#========================================================================================
# LOGIC
#========================================================================================

# #Create a connection to the f2b database
# f2b_db_object = SyslogDB(F2BDB)
# #Create a connection to the Syslog database
# syslog_db_object = SyslogDB(syslog_db_name)

# #Find the last syslogID that was processed and save it.  This will come from the f2b database.  If this is the first run
# #and there isn't any table data yet then it will return a TypeError when trying to getLastID() in which case we just 
# #set the last_syslogID to 0.  Setting last_syslogID to 0 will enable a full list of banned messages.
# try:
#     last_syslogID = f2b_db_object.getLastID()
# except TypeError:
#     last_syslogID = 0
# print last_syslogID

# #Return all ban messages with a syslog ID greater that last_syslogID
# qmessages = syslog_db_object.find_Bans(last_syslogID)   # <--this returns a list of strings
# print qmessages

# #Add banned ip address messages to f2b database
# for ban in qmessages:
#     #insert each 'ban' message into our f2b database to track syslogIDs
#     msg = "INSERT INTO archived_messages (host, syslogid, bannedIP) VALUES ('%s', '%s', '%s');" % (ban['sourceHost'], ban['syslogID'], ban['bannedIP'])
#     #f2b_db_object.archiveMessage(msg)    # <---insert message into f2b database
#     print msg

# send_IPs_to_queue = [i['bannedIP'] for i in qmessages]
# send_IPs_to_queue = set(send_IPs_to_queue)  # <-- de-duplicate the list of IP addresses using 'set'


# #Create a producser that will push messages into the queue.  Each IP sent individually to queue
# pub = Producer(url,cloud_username,cloud_api_key)
# pub.queue_name = 'kidrack_queue'
# print pub.queue_name

# for ip in send_IPs_to_queue:
#   payload = [{"ttl": 600,"body": {"task":"one"}},{"ttl": 600,"body": {"task":"%s" % ip}}]    
#   pub.post_messages(payload)
#   print "posted message with ip %s" % ip 


#====================================================================================
def server():
    #Create a connection to the f2b database
    qlogger.info("Connecting to the f2b database")
    f2b_db_object = SyslogDB(F2BDB)
    qlogger.info("Done!")

    #Here we make an initial pass over the f2b database.  If no records found considered first run. 
    #Query for the last syslog ID in f2b database.  If no entries then TypeError exception returned and set last_syslogID to 0
    qlogger.info("Making inital pass over the f2b database.  If no syslog IDs found the considering this the 'first run'")
    try:
      last_syslogID = f2b_db_object.getLastID()
      last_syslogID_old = last_syslogID   # <--- initilize this variable to hold 'last' value during previous loop iteration
    except TypeError:
      last_syslogID = 0   # <--- Considering this the first run
      last_syslogID_old = last_syslogID  # <--- initilize this variable to hold 'last' value during previous loop iteration
    if last_syslogID == 0:
      qlogger.info("First Run!  Setting last syslogID to 0.  Mining for ALL messages in syslog database")
    else:
      qlogger.info("Last syslogID is set to: %s" % last_syslogID)

    #Create a connection to the Syslog database
    qlogger.info("Connecting to syslog database")
    syslog_db_object = SyslogDB(syslog_db_name)
    qlogger.info("Done!")



    #Start our while loop which will check for new banned IP address every 1 minute and process them accordingly
    while True:    
        try:
            last_syslogID = f2b_db_object.getLastID()
        except:
            last_syslogID = 0    
        qlogger.info("Last syslog ID: %s" % last_syslogID)

        #Make an initial pass on syslog database for bans. Return all ban messages with a syslog ID greater that last_syslogID
        qlogger.info("Making initial pass over syslog database looking for banned IP addresses")
        qmessages = syslog_db_object.find_Bans(last_syslogID)
        #Add banned ip address messages to f2b database. 
        for ban in qmessages:
            #insert each 'ban' message into our f2b database to track syslogIDs
            msg = "INSERT INTO archived_messages (host, syslogid, bannedIP) VALUES ('%s', '%s', '%s');" % (ban['sourceHost'], ban['syslogID'], ban['bannedIP'])
            f2b_db_object.archiveMessage(msg)    # <---insert message into f2b database
            qlogger.info("Archived Messages:\n%s" % msg) 

        #Set up banned IP list (de-duplicated)
        send_IPs_to_queue = [i['bannedIP'] for i in qmessages]
        send_IPs_to_queue = set(send_IPs_to_queue)  # <-- de-duplicate the list of IP addresses using 'set'

        #Create a producser that will push messages into the queue.  Each IP sent individually to queue
        qlogger.info("Creating message producer...")
        pub = Producer(url,cloud_username,cloud_api_key)
        pub.queue_name = 'kidrack_queue'
        qlogger.info("Plublishing to queue, %s" % pub.queue_name)

        qlogger.info("Sending IPs to queue for processessing")
        for ip in send_IPs_to_queue:
          payload = [{"ttl": 60,"body": {"banned IP":"%s" % ip}}]    
          pub.post_messages(payload)
          qlogger.info("posted message with ip %s" % ip)
        qlogger.info("Sleeping for 20 seconds!")
        sleep(20)


def client(qname):
    """
    Returns a json object containing all messages.

    $curl -i -X GET "https://ord.queues.api.rackspacecloud.com/v1/queues/kidrack_queue/messages?echo=true" 
    -H "Client-ID: QClient" -H "X-Auth-Token: AUTHTOKEN" -H "Content-type: application/json"

    self.headers = {'X-Auth-Token' : self.token, 'Content-Type': 'application/json', 'Client-ID': 'QClient1'}

    --
    test = client('kidrack_queue')
    try to grab messages until this exception  ValueError: No JSON object could be decoded
    it will get 10 messages at a time
    """
    useragent = "KidRack"
    my_base_url = 'https://ord.queues.api.rackspacecloud.com'
    url_location = '/v1/queues/%s/messages?echo=true&limit=10' % qname
    url_location_after_first_pass = ''
    #myurl = q_url
    #myurl = 'https://ord.queues.api.rackspacecloud.com/v1/queues/%s/messages?echo=true&limit=10' % qname
    myurl = my_base_url + url_location
    print 'this is my url \n%s' % myurl
    print ""
    cmd = """curl -i -X GET "%s" \
    -H "Content-type: application/json" \
    -H "Client-ID: QClient" \
    -H "X-Auth-Token: %s" \
    """ % (myurl, cloud_api_token)
    messages = []
    cmd_output = subprocess.check_output(cmd, shell=True)
    cmd_output = json.loads(cmd_output.split('\r\n\r\n', 1)[1])   # <----split the header off the results
    url_location_after_first_pass = cmd_output['links'][0]['href']      # <---this is url_location_after_first_pass
    return messages

server()

# def main():
#   parser = argparse.ArgumentParser(prog='Cloud_Queue.py', description='Used as Cloud Queue server or client for distributed fail2ban')
#   group = parser.add_mutually_exclusive_group()
#   group.add_argument("-s", "--server", help="Run in server mode.  Allows interaction with local databases.  \
#     Script becomes producer for cloud queue also.", action="store_true")
#   group.add_argument("-c", "--client", help="Run in client mode.  Poll the cloud queue for new 'banned ip' messages \
#     and process these messages accordingly.", action="store_true")
#   #parser.add_argument('--uuid', '-u',required=True, nargs=1, help='-u $SERVER_INSTANCE_ID|name-label UUID')
#   args = parser.parse_args()
#   #print ("Input file: %s" % args.uuid )
#   if args.server:
#     server()





# if __name__ == "__main__" :
#   try:
#     main()
#   except Exception, e:
#     print "Error: %s" % e
#     print ""
#     print 'Enter correct instance UUID or verify that instance exists and then retry'
#     print ""
#     sys.exit()


