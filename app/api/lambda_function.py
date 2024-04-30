import logging
from os import environ
from requests import get
from ipaddress import ip_address, ip_network
from botocore.exceptions import ClientError 

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
disable_warnings(exceptions.InsecureRequestWarning)

# us-east-1 is needed if applying ipset at cloudfront(global) level
# if you're working with an regional resource make sure to change accordingly
waf_client = boto3.client('wafv2', region_name='us-east-1')

IPV4_IP_LIST = []
IPV4_SET_ID=environ['IPV4_SET_ID'].strip() 
IPV4_SET_NAME=environ['IPV4_SET_NAME'].strip()  

IPV6_IP_LIST = []
IPV6_SET_ID=environ['IPV6_SET_ID'].strip()  
IPV6_SET_NAME=environ['IPV6_SET_NAME'].strip()  

ASN = environ['ASN_NUMBER']


def get_reverse_lookup(ASN:str) -> list:
    """Uses IPinfo.io to perform reverse whois lookup based on the ASN attribute.

    Parameters
    ----------
    ASN : str (environ)
        AS Number for the ip block/domain.
    Returns
    -------
    ip_range : List with all ip blocks refference
    """
    response = get(f"https://ipinfo.io/{ASN}?token={environ['API_TOKEN']}")
    ip_range = []
    return ip_range

def get_ipset_lock_token(IP_SET_NAME, IP_SET_ID, client):
    """Gets lock token from AWS WAF IPset Paginator.

    Parameters
    ----------
    IP_SET_NAME : str (environ)
        IPSet Name.
    IP_SET_ID : str (environ)
        IPSet Id.
    client : boto3.client object
        Boto3 WAFv2 Globally configured.

    Returns
    -------
    Dict
    """
    response = client.get_ip_set(
        Id=IP_SET_ID,
        Name=IP_SET_NAME,
        Scope='CLOUDFRONT' #If you want to fit with APIGW or LB resource, change this to REGIONAL 
    )
   
    return response['LockToken']

def update_ip_set(IP_SET_NAME, IP_SET_ID,  IP_LIST, client):
    """Gets lock token from AWS WAF IPset Paginator.

    Parameters
    ----------
    IP_SET_NAME : str (environ)
        IPSet Name.
    IP_SET_ID : str (environ)
        IPSet Id.
    IP_LIST : List
        Whois function response with CIDR list
    client : boto3.client object
        Boto3 WAFv2 Globally configured.

    Returns
    -------
    Dict
    """
    lock_token = get_ipset_lock_token(IP_SET_NAME, IP_SET_ID, client)
    response = client.update_ip_set(
        Name = IP_SET_NAME,
        Scope = 'CLOUDFRONT', #If you want to fit with APIGW or LB resource, change this to REGIONAL
        Id = IP_SET_ID,
        LockToken= lock_token,
        Addresses=IP_LIST
    )
    return response

def lambda_handler(event, context):
    for network in whois_lookup(get_ip_addresses(domain))['nets']:
        if (type(ip_network(network['cidr'])).__name__) == "IPv4Network":
            print(network['cidr'])
            IPV4_IP_LIST.append(network['cidr'])
        elif (type(ip_network(network['cidr'])).__name__) == "IPv6Network":
            print(network['cidr'])
            IPV6_IP_LIST.append(network['cidr'])
        else:
            print(f"{network['cidr']} is not a valid network")

    try:
        if len(IPV4_IP_LIST) > 0:
            update_ip_set(IPV4_SET_NAME, IPV4_SET_ID,  IPV4_IP_LIST, client)
            return {'status': 200, 'message': 'IPV4 Ipset Updated'}
        if len(IPV6_IP_LIST) > 0:
            update_ip_set(IPV6_SET_NAME, IPV6_SET_ID,  IPV6_IP_LIST, client)
            return {'status': 200, 'message': 'IPV6 Ipset Updated'}
    except ClientError as e: 
        return e