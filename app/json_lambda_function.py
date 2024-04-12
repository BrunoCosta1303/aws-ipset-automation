from os import environ
import logging
import requests
import boto3
from urllib3 import disable_warnings, exceptions

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
disable_warnings(exceptions.InsecureRequestWarning)

#https://docs.python.org/3/library/ipaddress.html 

waf_client = boto3.client('wafv2', region_name='us-east-1')

IPV4_IP_LIST = []
IPV4_SET_ID=environ['IPV4_SET_ID'].strip() #"block-seo-ipsets-ipv4" 
IPV4_SET_NAME=environ['IPV4_SET_NAME'].strip() #"block-seo-ipsets-ipv4" 

IPV6_IP_LIST = []
IPV6_SET_ID=environ['IPV6_SET_ID'].strip() #"block-seo-ipsets-ipv6" 
IPV6_SET_NAME=environ['IPV6_SET_NAME'].strip() #"block-seo-ipsets-ipv6" 

def bot_ip_addresses():
    bots_urls = [
        'https://developers.google.com/search/apis/ipranges/googlebot.json',
        'https://www.bing.com/toolbox/bingbot.json'
    ]
    for url in bots_urls:
        bot_resp = requests.get(url)
        return bot_resp.json() 

def get_ipset_lock_token(IP_SET_NAME, IP_SET_ID, client):
    response = client.get_ip_set(
        Id=IP_SET_ID,
        Name=IP_SET_NAME,
        Scope='CLOUDFRONT'
    )
   
    return response['LockToken']

def update_ip_set(IP_SET_NAME, IP_SET_ID,  IP_LIST, client):
    lock_token = get_ipset_lock_token(IP_SET_NAME, IP_SET_ID, client)
    response = client.update_ip_set(
        Name = IP_SET_NAME,
        Scope = 'CLOUDFRONT',
        Id = IP_SET_ID,
        LockToken= lock_token,
        Addresses=IP_LIST
    )
    return response

def lambda_handler(event, context):

    ip_ranges = bot_ip_addresses()
    for index in range(0, len(ip_ranges['prefixes'])): 
        try:
            IPV4_IP_LIST.append(ip_ranges['prefixes'][index]['ipv4Prefix'])
        except :
            IPV6_IP_LIST.append(ip_ranges['prefixes'][index]['ipv6Prefix'])

    try:
        ipv6_response = update_ip_set(IPV6_SET_NAME, IPV6_SET_ID,  IPV6_IP_LIST , waf_client)
        ipv4_response = update_ip_set(IPV4_SET_NAME, IPV4_SET_ID, IPV4_IP_LIST, waf_client)
        return {"statusCode": 200}
    except ClientError: 
        return {
            "Message": "Failed while updating ipset",
            "IPV6_response": ipv6_response['ResponseMetadata']['HTTPStatusCode'],
            "IPV4_response": ipv4_response['ResponseMetadata']['HTTPStatusCode']
        }


