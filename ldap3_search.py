# https://ldap3.readthedocs.io/searches.html
import boto3, json, base64
from botocore.exceptions import ClientError 
from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE, ALL_ATTRIBUTES
 
### READ THE DB AUTH KEYS FROM SECRET MANAGERS 
def get_secret(secret_name,region_name):
    # Create a Secrets Manager client
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

def get_ldap_info(u):
    # GET CONNECTION TO SECRET MANAGER FOR AD
    keys= get_secret("CHANGEME","CHANGEME")
    print(keys)
    # Retrive the credentials
    domain = keys['domain']
    loginun = 'CHANGEME\\' + keys['loginun']
    loginpw = keys['loginpw']
    adurl = keys['url']
    port = keys['port']
    
    with Connection(Server('CHANGEME', port=636, use_ssl=True),
                    auto_bind=AUTO_BIND_NO_TLS,
                    read_only=True,
                    check_names=True,
                    user=loginun, password=loginpw) as c:
 
        c.search(search_base='CN=CHANGEME,DC=CHANGEME,DC=CHANGEME,DC=CHANGEME',
                 search_filter='(&(samAccountName=' + u + '))',
                 search_scope=SUBTREE,
                 attributes=ALL_ATTRIBUTES,
                 get_operational_attributes=True)
 
    print(c.response_to_json())
    print(c.result)

get_ldap_info('CHANGEME')
