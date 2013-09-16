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
import sys
import pwd      # <---import 'the password database' to get access to user/group id info
import ConfigParser    # <----use to parse config file containing cloud credentials
import MySQLdb as mysqldb

#========================================================================================
#SET UP GLOBAL VARIABLES
#========================================================================================
#RESPONSE = ''     #<----this will be used to capture pycurl buffer responses. we will reuse as necessary.
CONFIG_FILE = "/etc/Cloud_Queue.conf"
CREDS_FILE = "~/.rackspace_cloud_credentials"
LOG_FILE = '/var/log/Cloud_Queue.log'    # <--application log file
FIRST_RUN = True  # <--Must execute as root when first run so that it can create proper log files.  Assuming 'first-run' before check is done

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
### CAPTURE CLOUD USERNAME AND API KEY  -- if we run from command line will need this
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
c.setopt(c.VERBOSE, True)
c.setopt(c.SSL_VERIFYPEER, False)
c.setopt(c.FAILONERROR, True)
c.perform()
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
    self.content_type = content_type_header
    self.accept = accept_header
    #self.queue_name = queue_name

  def Auth(self):
    """
    curl -D - -H"X-Auth-User: rackerone" -H"X-Auth-Key:0d9dbaf3aaeb96eeacd3642ee4ce44d7" https://auth.api.rackspacecloud.com/v1.0
    This method works but it will not save the buffer output for parsing.  Prob variable scope issue....?/
    """
    c = pycurl.Curl()
    body = cStringIO.StringIO()
    hdr = cStringIO.StringIO()     # when we authenticate the information we require is returned in the header
    c.setopt(c.WRITEFUNCTION, body.write)
    c.setopt(c.HEADERFUNCTION, hdr.write)
    c.setopt(c.URL, auth_url)
    c.setopt(c.HTTPHEADER, ["X-Auth-User:%s" % cloud_username, "X-Auth-Key:%s" % cloud_api_key])
    c.setopt(c.CONNECTTIMEOUT, 5)
    c.setopt(c.TIMEOUT, 8)
    c.setopt(c.VERBOSE, False)
    c.setopt(c.SSL_VERIFYPEER, False)
    c.setopt(c.FAILONERROR, True)
    c.perform()
    hdr_response = hdr.getvalue()
    body_response = body.getvalue()
    #print "status code: %s" % c.getinfo(pycurl.HTTP_CODE)
    #print "effective URL: %s" % c.getinfo(pycurl.EFFECTIVE_URL)
    token_line = hdr_response.splitlines()[8]  #<--This line contains the api token
    cloud_api_token = token_line.split(":")[1].strip()
    qlogger.info("Retrieved API Token: %s" % cloud_api_token)
    return cloud_api_token
    c.close()


##CHANGE THIS LATER BY ADDING CONFIG FILE FOR THIS STUFF
#db_user = 'XXXXXXX'
#db_password = 'XXXXXX'
#target_host = 'localhost'
#Syslog_database = 'Syslog'

class SyslogDB():
  """Manage connections to local mysql syslog database.  When we create the SyslogDB object it will automatically authenticate so we are
  ready to call methods to interact with db.
  
  ::target_host => This is where the syslog database will be located
  ::db_user => This is the mysql database user name used for interacting with the Syslog database
  ::db_password => This is the database user password
  ::Syslog_database => This is the syslog database name where all syslog messages are saved
  
  http://www.tutorialspoint.com/python/python_database_access.htm
  """
  
  
  def __init__(self, host=syslog_db_host, user=syslog_db_user, password=syslog_db_user_pwd, database=syslog_db_name):
    qlogger.info("======Initializing SyslogDB() object for mysql interface======")
    qlogger.info("Assembling arguments for our database object...")
    self.host = syslog_db_host
    self.database = syslog_db_name
    self.user = syslog_db_user
    self.password = syslog_db_user_pwd
    qlogger.info("Done!")
    qlogger.info("Connecting to local Syslog database...")
    try:
      #Create connection
      db = mysqldb.connect(host, user, password, database)
    except Exception as e:
      qlogger.error(e)
    if db:
      qlogger.info("Successfully created database connection to %s!" % database)
    qlogger.info("Creating cursor() object used to send statements to mysql...")
    cursor = db.cursor()
    qlogger.info("Done creating cursor() object!")
    
    qlogger.info("======Syslog() database initialization complete!======")
  #  
  #def connect(self):
  #  """Connect to local Syslog database and create a cursor object to allow queries"""
  #  qlogger.info("Connecting to local Syslog database...")
  #  try:
  #    #Create connection
  #    db = mysqldb.connect(host, user, password, database)
  #  except Exception as e:
  #    qlogger.error(e)
  #  if db:
  #    qlogger.info("Successfully created database connection to %s!" % database)
  #  qlogger.info("Creating cursor() object used to send statements to mysql...")
  #  cursor = db.cursor()
  #  qlogger.info("Done creating cursor() object!")
  #  
  def find_Bans(self):
    """Execute SQL statements to interact with database"""
    statement = "select ID, DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%' and Message like '% Ban %';"
    #This will find all messages from fail2ban that contain the string 'Ban'
    qlogger.info("Executing statement: \n%s" % statement)
    cursor.execute(statement)
    #To get row count of returned results
    cursor.rowcount       #<---read-only attribute
    ##To fetch a single row at a time
    #data = cursor.fetchone()
    #To fetch all rows at once into a tuple
    all_data = cursor.fetchall()
    banned_IPs = {}
    ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    #findIP = re.findall(ipPattern,string)
    for row in all_data:
      string = row[3]    #<---this row contains the banned IP
      ip = re.findall(ip_pattern, string)
      banned_IPs.append(ip[0])
    return banned_IPs
    
    
  def db_Close():
    """Close our open database connection"""
    db.close()
    qlogger.info("Database closed!")
    return "Database Closed!"










#x = Cloud_Queue()
#y = x.q_Auth()
#print y     #<----prints api token
#  

  
    
###this does not capture value but does auth

###buf = cStringIO.StringIO()
### 
###c = pycurl.Curl()
###c.setopt(c.URL, 'http://news.ycombinator.com')
###c.setopt(c.WRITEFUNCTION, buf.write)
###c.perform()
### c.setopt(pycurl.HTTPHEADER, ['Accept: application/json'])
###print buf.getvalue()
###buf.close()



#### Echo server program
###import socket,os
###
###s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
###try:
###    os.remove("/tmp/socketname")
###except OSError:
###    pass
###s.bind("/tmp/socketname")
###s.listen(1)
###conn, addr = s.accept()
###while 1:
###    data = conn.recv(1024)
###    if not data: break
###    conn.send(data)
###conn.close()
###
###
#### Echo client program
###import socket
###
###s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
###s.connect("/tmp/socketname")
###s.send('Hello, world')
###data = s.recv(1024)
###s.close()
###print 'Received', repr(data)