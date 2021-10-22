========
Examples
========

::
  $ ./tide_to_rpz_nios_csv.py --help

    usage: tide_to_rpz_nios_csv.py [-h] -z RPZZONE [-c CONFIG] [-p PROFILE] [-C THREATCLASS] [-l LIMIT] [-d]

    TIDE host IOC data to Infoblox CSV RPZ Import format

    optional arguments:
      -h, --help            show this help message and exit
      -z RPZZONE, --rpzzone RPZZONE
                            base label(s) for RPZ zone
      -c CONFIG, --config CONFIG
                            Override config file
      -p PROFILE, --profile PROFILE
                            TIDE data source profile
      -C THREATCLASS, --threatclass THREATCLASS
                            Threat Class
      -l LIMIT, --limit LIMIT
                            Restrict record limit
      -d, --debug           Enable debug messages


  $ ./tide_to_rpz_nios_csv.py --config csp.ini --rpzzone custom.local.rpz
  header-responsepolicycnamerecord,fqdn*,_new_fqdn,canonical_name,comment,disabled,parent_zone,ttl,view
  responsepolicycnamerecord,statsdev.com.custom.local.rpz,,,,False,rpz.local.custom,,default
  responsepolicycnamerecord,securityupdatewin32.org.custom.local.rpz,,,,False,rpz.local.custom,,default
  responsepolicycnamerecord,sanduallsocco.ru.custom.local.rpz,,,,False,rpz.local.custom,,default
  responsepolicycnamerecord,looduchavens.ru.custom.local.rpz,,,,False,rpz.local.custom,,default
  responsepolicycnamerecord,codeingasmylife.com.custom.local.rpz,,,,False,rpz.local.custom,,default
  responsepolicycnamerecord,nix1.xyz.custom.local.rpz,,,,False,rpz.local.custom,,default
  ...


