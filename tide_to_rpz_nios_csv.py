#!/usr/local/bin/python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''
 ABSOLUTELY NO WARRANTY WITH THIS PACKAGE. USE IT AT YOUR OWN RISK.

 TIDE data to RPZ Infoblox CSV import format

 Requirements:
   Requires bloxone module

 Author: Chris Marrison

 ChangeLog:
   20211022    v2.0    Updated for BloxOne Threat Defence
   20180501    v1.0    CLI Option for APIKEY zone
   20180501    v0.7    CLI Options for RPZ zone
                       profile, threatclass and record limit
   20180501    v0.5    Outputs to Infoblox CSV
   20180430    v0.1    Initial Test Version

 Todo:

 Copyright (c) 2021 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.ghts Reserved.

'''

import sys
import argparse
import json
import requests
import bloxone

### Global Variables ###
totalthreats = 0

### Functions ###

def parseargs():
    """ Parse Arguments Using argparse """
    """
        Returns arguments
    """
    parse = argparse.ArgumentParser(description='TIDE host IOC data to Infoblox CSV RPZ Import format')
    #parse.add_argument('-o', '--output', type=str, help="CSV Output to <filename>")
    #parse.add_argument('-s', '--silent', action='store_true', help="Silent mode")
    parse.add_argument('-z', '--rpzzone', type=str, required=True, help="base label(s) for RPZ zone")
    parse.add_argument('-c', '--config', type=str, default="config.ini", help="Override config file")
    parse.add_argument('-p', '--profile', type=str, default="IID", help="TIDE data source profile")
    parse.add_argument('-C', '--threatclass', type=str, default="MalwareC2", help="Threat Class")
    parse.add_argument('-l', '--limit', type=str, default="1000", help="Restrict record limit")
    parse.add_argument('-d', '--debug', action='store_true', help="Enable debug messages")

    return parse.parse_args()


### Main ###

# Parse Arguments
args = parseargs()
zone = args.rpzzone
rzone = bloxone.utils.reverse_labels(zone)
profile = args.profile
tclass = args.threatclass
limit = args.limit
b1td = bloxone.b1td(args.config)

if args.debug:
    print("Args supplied: {}".format(args))

# Get host data for specified source and profile from TIDE
response = b1td.tideactivefeed("host", profile=profile, threatclass=tclass,
                                  rlimit=limit)
if response.status_code in b1td.return_codes_ok:
    if args.debug:
        print("Raw JSON:")
        print(response.text)
    # Parse JSON response
    parsed_json = json.loads(response.text)
    # Print CSV Header
    print("header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,comment,disabled,parent_zone,ttl,view")
    if args.debug:
        print("Formated CSV:")
    # For each host ouput CSV for Block BlockNxdomainDomain
    for ioc in parsed_json["threat"]:
        line = 'responsepolicycnamerecord,'+ioc["host"]+'.'+zone+',,,,False,'+rzone+',,default'
        print(line)

else:
    print("Query Failed with response: {}".format(rcode))
    print("Body response: {}".format(rtext))

### End Main ###
