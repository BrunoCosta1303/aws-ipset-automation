import logging
from os import environ
from requests import get
from ipaddress import ip_address, ip_network
from botocore.exceptions import ClientError 

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

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
    response = get(f"https://ipinfo.io/{ASN}?token=")
    print(response)
    ip_range = []
    return ip_range

print(get_reverse_lookup(""))

# for network in get_reverse_lookup():
#     if (type(ip_network(network['cidr'])).__name__) == "IPv4Network":
#         print(network['cidr'])
#         IPV4_IP_LIST.append(network['cidr'])
#     elif (type(ip_network(network['cidr'])).__name__) == "IPv6Network":
#         print(network['cidr'])
#         IPV6_IP_LIST.append(network['cidr'])
#     else:
#         print(f"{network['cidr']} is not a valid network")