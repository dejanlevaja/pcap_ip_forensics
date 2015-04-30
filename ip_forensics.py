#! /usr/bin/env python

import sys
import os
import json
import logging
import requests
# ignore scapy ipv6 warning on load
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ipwhois import IPWhois
from progress.bar import Bar
from tabulate import tabulate
from BeautifulSoup import BeautifulSoup as BS


__author__ = 'Dejan Levaja'
__email__ = 'dejan@levaja.com'
__license__ = 'GPLv2'
__version__ = "1.0.0"


TIMEOUT = 10
ips = []
table = []
exceptions = []


def get_org(ip):
    url = 'http://www.speedguide.net/ip/%s' % ip
    r = requests.post(url,timeout = TIMEOUT)
    soup = BS(r.text)
    table = soup.find("table",{"class":"t1 ip-info"})
    rows = table.findAll('tr')
    for row in rows:
        if 'Organization' in row.text:
            org = ''.join(unicode(row.text).split(':')[1])
            return org

    return 'Unknown'


def get_server(ip):
    url = 'http://%s/' % ip
    r = requests.head(url,timeout = TIMEOUT)
    if 'server' in r.headers:
        return r.headers['server']
    return 'Unknown'


def get_data(ip):
    try:
        obj = IPWhois(ip)
        results = json.loads(json.dumps(obj.lookup()))['nets'][0]
        owner = results['name'].strip()
        country =  results['country'].strip()
        org = get_org(ip)
        server = get_server(ip)
        desc = ' '.join(results['description'].split('\n'))
        text = '%s, %s, %s, %s, %s,%s' % (ip,owner,country,org,server,desc)
        table.append(text.split(','))
    except requests.exceptions.Timeout:
        msg = 'Timeout - %s' % ip
        exceptions.append(msg)
    except requests.exceptions.ConnectionError:
        msg = 'Connection error - %s' % ip
        exceptions.append(msg)
    except Exception as e:
        exceptions.append(str(e))



def main():
    infile = raw_input('Input file name: ')
    if os.path.exists(infile):
        print '\n[!] Loading PCAP file. Please wait, it might take a while...'
        ips = sorted(set(p[IP].src for p in PcapReader(infile) if IP in p))

        total = len(ips)
        print '[!] Total number of IP addresses: %d\n' % total

        bar = Bar('Processing', max=total)
        for ip in ips:
            get_data(ip)
            bar.next()
        bar.finish()

        headers = ['IP', 'OWNER','COUNTRY', 'ORGANIZATION','SERVER','DESCRIPTION']
        print '\n\n'
        print tabulate(table,headers,tablefmt='grid')
        if exceptions:
            print '\nExceptions:'
            for e in exceptions:
                print '*\t%s' % e
            print '\n\n[!] Done.\n\n'
    else:
        print '[!] Cannot find file "%s"\n\tExiting...' % infile
        sys.exit()



if __name__ == '__main__':
    main()
    sys.exit()




