#! /bin/env python

"""
This script updates all A-records for specific CloudFlare DNS zones (domain names) to the current IP address.
Run with "-l" to find the zones list

Requirements:
pip install requests

History:
0.2 - Removed use of httplib
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "0.2"

import argparse
import json
import requests

"""Begin editable section"""
cf_username = ""
cf_api_key = ""
# The ID's of the CloudFlare DNS zones to update
cf_zone_ids = [""]
"""End editable section"""

cf_headers = {
    "X-Auth-Email": cf_username,
    "X-Auth-Key": cf_api_key,
    "Content-Type": "application/json"
}
cf_base = "https://api.cloudflare.com/client/v4/zones"


def get_zones():
    resp = requests.get("{}".format(cf_base), headers=cf_headers).json()
    for record in resp['result']:
        print("{:>20.20} = {}".format(record['name'], record['id']))


def update_cloudflare(new_ip):
    for zone_id in cf_zone_ids:
        resp = requests.get("{}/{}/dns_records".format(cf_base, zone_id), headers=cf_headers).json()
        for rec in resp['result']:
            if rec['type'] == 'A':
                record_id = rec['id']
                domain = rec['name']
                ip = rec['content']
                print("A record {} has id {} and ip {}".format(domain, record_id, ip))
                body = {
                    "content": new_ip,
                    "name": domain,
                    "type": "A"
                }

                url = "{}/{}/dns_records/{}".format(cf_base, zone_id, record_id)
                upd_resp = requests.put(url, data=json.dumps(body), headers=cf_headers).json()
                print("DNS Updated? {}".format(upd_resp['success']))


def main():
    parser = argparse.ArgumentParser(
        description="""This script updates all A-records for specific CloudFlare DNS zones (domain names) to the current IP address"""
    )
    parser.add_argument('--list', '-l', dest="list", help="List the zones in Cloudflare instead of updating", required=False, action="store_true")
    parser.add_argument('--version', '-v', action='version', version='%(prog)s {}'.format(__version__))
    args = parser.parse_args()

    try:
        if args.list:
            get_zones()
        else:
            new_ip = str(requests.get("https://api.ipify.org").text.strip())
            update_cloudflare(new_ip)
    except Exception as e:
        print("ERROR: unable to retrieve IP", e)


main()
