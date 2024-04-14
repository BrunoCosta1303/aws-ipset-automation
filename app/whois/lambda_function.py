from whois import whois 
from boto3 import client 
from json import loads, dumps
from subprocess import run
from botocore.exceptions import exceptions
from os import environ, system 
from traceback import format_exc as traceback

import logging
logger = logging.getLogger()
logger.setLevel("INFO")

# Uses local whois binary for executing reverse searches
def get_ips_from_reverse_whois_lookup(domain:string):
    '''Updates the AWS WAF IP set'''
    try:
        lookup = run(f"whois -h {environ['WHOIS_HOST']} | grep ^route")
        return whois(domain)
    except Exception as e:
        return logger.error(f'Function failed with code: {e} \n full call trace: {traceback()}') 

def get_ips_from_list():
    pass

# From https://github.com/aws-samples/aws-waf-ipset-auto-update-aws-ip-ranges
def update_waf_ipset(ipset_name,ipset_id,address_list):
    '''Updates the AWS WAF IP set'''

    waf_client = client('wafv2')
    lock_token = get_ipset_lock_token(waf_client,ipset_name,ipset_id)
    logging.info(f'Got LockToken for AWS WAF IP Set "{ipset_name}": {lock_token}')

    waf_client.update_ip_set(
        Name=ipset_name,
        Scope='REGIONAL',
        Id=ipset_id,
        Addresses=address_list,
        LockToken=lock_token
    )

    print(f'Updated IPSet "{ipset_name}" with {len(address_list)} CIDRs')

# From https://github.com/aws-samples/aws-waf-ipset-auto-update-aws-ip-ranges
def get_ipset_lock_token(client,ipset_name,ipset_id):
    '''Returns the AWS WAF IP set lock token'''
    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='REGIONAL',
        Id=ipset_id)
    
    return ip_set['LockToken']


def lambda_handler(event, context):

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
