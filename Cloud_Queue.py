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
$ curl -i -X PUT https://ord.queues.api.rackspacecloud.com/v1/queues/kidrack_queue -d'{"Aaron": "My Test Queue"}' \
                            -H"Content-type: application/json" -H"X-Auth-Token: 5436552e4948uf1b8d4f7d9he6fd777b" \
                            -H "Accept: application/json"

RETURN VALUE=====>>>
HTTP/1.1 201 CreatedContent-Length: 0
Location: /v1/queues/{queuename}
"""

#Need to use this url to get logging working...need console output for diagnostics while writing code
#--->  http://docs.python.org/dev/howto/logging.html

import pycurl
#import pyrax  # <----not needed
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
CREDS_FILE = "~/.rackspace_cloud_credentials"



#========================================================================================
#SET UP LOGGING
#========================================================================================

LOG_FILE = '/var/log/Cloud_Queue.log'    # <--application log file
FIRST_RUN = True  # <--Must execute as root when first run so that it can create proper log files.  Assuming 'first-run' before check is done

#Checking for the existence of the Cloud_Queue log file.  If it does not exist then leaving FIRST_RUN as True.
if os.path.exists(LOG_FILE):
  FIRST_RUN = False        #<---is log file exists then this is not first run

#Verifying that we can open and write to log file
f = ''    #<---initialze the file handle for our log file
try:
  f = open(LOG_FILE, "aw")
except IOError:
  if FIRST_RUN:
    print "This appears to be the first time you have executed this script.  You must execute with 'sudo' on first run!"
    #could also check for root with 'if os.getuid() != 0:'
    sys.exit(1)
  print "Unable to open log file '%s'.  Please check file permissions/ownership" % LOG_FILE
  sys.exit(1)
finally:
  if f:
    f.close()
    #I have to do extra work to get uid/gid because when we sudo this script on first run the uid is 0.
    #We don't want to set the ownership of our log to 0 (or root) so we need to know 'who' executed the script
    my_uid = pwd.getpwnam(os.getlogin()).pw_uid   #<--get the UID of the user logged into this machine
    my_gid = pwd.getpwnam(os.getlogin()).pw_gid   #<--get the GID of the user logged into this machine
    os.chown(LOG_FILE, my_uid, my_gid)

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
qlogger.info("Read and process local credential configuration file '%s'..." % CREDS_FILE)
my_config = ConfigParser.ConfigParser()
my_config.read(os.path.expanduser(CREDS_FILE))
my_config.sections()
rackspace_config = my_config.sections()[0]

def ParseConfigSections(section):
  """Parse the '.rackspace_cloud_credentials' file and save username and api key"""
  cred_dict = {}
  options = my_config.options(section)
  for option in options:
    try:
      cred_dict[option] = my_config.get(section, option)
    except Exception as e:
      qlogger.error(e)
  return cred_dict

my_creds = ParseConfigSections(rackspace_config)
cloud_username = my_creds['username']
cloud_api_key = my_creds['api_key']

qlogger.info('Username: %s' % cloud_username)
qlogger.info('API Key: %s' % cloud_api_key)
qlogger.info("Done processing local config file!")




#========================================================================================
# Authenticate to Rackspace cloud and retrieve API token:
#curl -D - -H"X-Auth-User: rackerone" -H"X-Auth-Key:0d9dbaf3aaeb96eeacd3642ee4ce44d7" https://auth.api.rackspacecloud.com/v1.0
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
c.setopt(c.HTTPHEADER, ["X-Auth-User:%s" % cloud_username, "X-Auth-Key:%s" % cloud_api_key])
c.setopt(c.CONNECTTIMEOUT, 5)
c.setopt(c.TIMEOUT, 8)
c.setopt(c.VERBOSE, False)
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


### CONNECT TO DATABASE
db_user = 'XXXXXXXXXXX'
db_password = 'XXXXXXXXXXX'
target_server = 'XXXXXXXXXXX'
my_database = 'XXXXXXXXXXX'
qlogger.info("======Initializing connection to local Syslog database======")
try:
  #Create connection
  db = mysqldb.connect(target_server, db_user, db_password, my_database)
except Exception as e:
  qlogger.error(e)
if db:
  qlogger.info("Successfully created database connection to %s!" % my_database)
cursor = db.cursor()
qlogger.info("======Syslog() database initialization complete!======")
statement = "select ID, DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%' and Message like '% Ban %';"
#This will find all messages from fail2ban that contain the string 'Ban'
qlogger.info("Executing statement: \n%s\n\n" % statement)
cursor.execute(statement)
#To get row count of returned results
cursor.rowcount       #<---read-only attribute
##To fetch a single row at a time
#data = cursor.fetchone()
#To fetch all rows at once into a tuple
all_data = cursor.fetchall()
banned_IPs = []
ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
#findIP = re.findall(ipPattern,string)
for row in all_data:
  string = row[3]    #<---this row contains the banned IP
  ip = re.findall(ip_pattern, string)
  banned_IPs.append(ip[0])
#we now have a list of banned IP addresses ==>banned_IPs
qlogger.info('We now have a list of banned IP addresses!!!!')
print "We have discovered the following IP address have been banned on Rackerone.com:"
for ip in banned_IPs:
  print ip





#========================================================================================
# SET UP CLASSES
#========================================================================================
#
#q_url = 'https://ord.queues.api.rackspacecloud.com/v1/queues/'
#
#class Cloud_Queue():
#  """Rackspace Cloud Queue"""
#  def __init__(self):
#    self.q_url = q_url
#    self.auth_url = auth_url
#    self.username = cloud_username
#    self.api_key = cloud_api_key
#    self.content_type = content_type_header
#    self.accept = accept_header
#    #self.queue_name = queue_name
#
#  def Auth(self):
#    """
#    curl -D - -H"X-Auth-User: rackspaceUsername" -H"X-Auth-Key:0d9dbawo9aeb96eerik3642ee4tj98d7" https://auth.api.rackspacecloud.com/v1.0
#    This method works but it will not save the buffer output for parsing.  Prob variable scope issue....?/
#    """
#    c = pycurl.Curl()
#    body = cStringIO.StringIO()
#    hdr = cStringIO.StringIO()     # when we authenticate the information we require is returned in the header
#    c.setopt(c.WRITEFUNCTION, body.write)
#    c.setopt(c.HEADERFUNCTION, hdr.write)
#    c.setopt(c.URL, auth_url)
#    c.setopt(c.HTTPHEADER, ["X-Auth-User:%s" % cloud_username, "X-Auth-Key:%s" % cloud_api_key])
#    c.setopt(c.CONNECTTIMEOUT, 5)
#    c.setopt(c.TIMEOUT, 8)
#    c.setopt(c.VERBOSE, False)
#    c.setopt(c.SSL_VERIFYPEER, False)
#    c.setopt(c.FAILONERROR, True)
#    c.perform()
#    hdr_response = hdr.getvalue()
#    body_response = body.getvalue()
#    #print "status code: %s" % c.getinfo(pycurl.HTTP_CODE)
#    #print "effective URL: %s" % c.getinfo(pycurl.EFFECTIVE_URL)
#    token_line = hdr_response.splitlines()[8]  #<--This line contains the api token
#    cloud_api_token = token_line.split(":")[1].strip()
#    qlogger.info("Retrieved API Token: %s" % cloud_api_token)
#    return cloud_api_token
#    c.close()
#
##CHANGE THIS LATER BY ADDING CONFIG FILE FOR THIS STUFF
#db_user = 'XXXXXXXXXXX'
#db_password = 'XXXXXXXXXXX'
#target_server = 'XXXXXXXXXXX'
#my_database = 'XXXXXXXXXXX'
#db = ''
#
#class SyslogDB():
#  """Manage connections to local mysql syslog database
#  http://www.tutorialspoint.com/python/python_database_access.htm
#  """
#  def __init__(self, server=target_server, user=db_user, password=db_password, database=my_database):
#    self.server = server
#    self.database = database
#    self.user = user
#    self.password = password
#    qlogger.info("Done!")
#    qlogger.info("Connecting to local Syslog database...")
#    try:
#      #Create connection
#      db = mysqldb.connect(host, user, password, database)
#    except Exception as e:
#      qlogger.error(e)
#    if db:
#      qlogger.info("Successfully created database connection to %s!" % database)
#    qlogger.info("Creating cursor() object used to send statements to mysql...")
#    cursor = db.cursor()
#    qlogger.info("Done creating cursor() object!")
#    qlogger.info("======Syslog() database initialization complete!======")
# 
#    
#    
#  #def connect(self, host=self.server, database=self.database, user=self.user, password=self.password):
#  #  """Connect to local Syslog database and create a cursor object to allow queries"""
#  #  qlogger.info("Connecting to local Syslog database...")
#  #  try:
#  #    #Create connection
#  #    db = mysqldb.connect(host, user, password, database)
#  #  except Exception as e:
#  #    qlogger.error(e)
#  #  if db:
#  #    qlogger.info("Successfully created database connection to %s!" % database)
#  #  qlogger.info("Creating cursor() object used to send statements to mysql...")
#  #  cursor = db.cursor()
#  #  qlogger.info("Done creating cursor() object!")
#    
#  def find_Bans(self):
#    """Execute SQL statements to interact with database"""
#    statement = "select ID, DeviceReportedTime,SyslogTag,Message from SystemEvents where SysLogTag like 'fail2ban%' and Message like '% Ban %';"
#    #This will find all messages from fail2ban that contain the string 'Ban'
#    qlogger.info("Executing statement: \n%s" % statement)
#    cursor.execute(statement)
#    #To get row count of returned results
#    cursor.rowcount       #<---read-only attribute
#    ##To fetch a single row at a time
#    #data = cursor.fetchone()
#    #To fetch all rows at once into a tuple
#    all_data = cursor.fetchall()
#    banned_IPs = {}
#    ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
#    #findIP = re.findall(ipPattern,string)
#    for row in all_data:
#      string = row[3]    #<---this row contains the banned IP
#      ip = re.findall(ip_pattern, string)
#      banned_IPs.append(ip[0])
#    return banned_IPs
#    
#    
#  def db_Close():
#    """Close our open database connection"""
#    db.close()
#    qlogger.info("Database closed!")
#    return "Database Closed!"
#
#
#
#
#queue = SyslogDB()






#x = Cloud_Queue()
#y = x.q_Auth()
#print y     #<----prints api token
#  

  
    
###this does not capture value but does auth

###buf = cStringIO.StringIO()
### 
###c = pycurl.Curl()
###c.setopt(c.URL, 'https://google.com')
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