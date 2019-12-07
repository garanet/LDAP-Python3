# https://ldap3.readthedocs.io/searches.html
# SEARCH AND CHANGE THE 'CHANGEME' value.

import boto3, json
from ldap3  import *
from botocore.exceptions import ClientError 

# ADD THE NEW USERS INFORMATIONS HERE
name = 'CHANGEME'
surname = 'CHANGEME'
initials = 'CHANGEME'
domain = '@CHANGEME.CHANGEME'
userpswd = 'CHANGEME'

### READ THE DB AUTH KEYS FROM SECRET MANAGERS 
def get_secret(secret_name,region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return json.loads(decoded_binary_secret)

 # GET CONNECTION TO SECRET MANAGER FOR AD
keys= get_secret("CHANGEME","CHANGEME")
# Retrive the credentials
domain = keys['domain']
loginun = 'CHANGEME\\' + keys['loginun']
loginpw = keys['loginpw']
adurl = keys['url']
port = keys['port']

s = Server(adurl+':'+port, use_ssl=True, get_info=ALL)
c=Connection(s,user=loginun, password=loginpw, check_names=True, lazy=False,raise_exceptions=False)

if not c.bind():
    exit(c.result)

# create user
username = name +'.'+surname
useremail = username + domain
userdn = 'CN={},CN=CHANGEME,DC=CHANGEME,DC=CHANGEME,DC=CHANGEME'.format(username)

c.add(userdn, attributes={
  'objectClass': ['organizationalPerson', 'person', 'top', 'user'],
  'givenName': name,
  'sn': surname,
  'initials': initials,
  'userPrincipalName': useremail,
  'sAMAccountName': username,
  'displayName': username,
  'mail': useremail
})


# set password - must be done before enabling user
# you must connect with SSL to set the password 
c.extend.microsoft.modify_password(userdn, userpswd)

# Assign the user to Member Of
#c.extend.microsoft.add_members_to_groups('cn=CHANGEME,cn=CHANGEME,dc=CHANGEME,dc=CHANGEME,dc=CHANGEME', 'cn=Enterprise Admins,cn=CHANGEME,dc=CHANGEME,dc=CHANGEME,dc=CHANGEME')

# # enable user (after password set)
c.modify(userdn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})

# # disable user
# c.modify(userdn, {'userAccountControl': [('MODIFY_REPLACE', 2)]})

print(c.result)
# # close the connection
c.unbind()
