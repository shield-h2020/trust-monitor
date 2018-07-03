#!/usr/bin/env python
# -*- coding: utf-8 -*
# start verify used to contact django API to start with verification process.
# Use django API: http://django/get_verify and use a post method.

import requests
import sys
import os
import json
from requests.exceptions import ConnectionError
from setting import *

if __name__ == '__main__':
    try:
        url = BASE_URL_TRUST_MONITOR + '/get_verify/'
        headers = {'content-type': 'application/json'}
        print('Call start_verify used to contact django API')
        distro = 'CentOS7'
        analysis = 'load-time+cont-check'
        print('Use env variable to set a json object')
        distro = os.environ.get('OS', distro)
        analysis = os.environ.get('ANALYSIS', analysis)
        report_url = os.environ.get('URL')
        report_id = int(os.environ.get('IR', 0))
        jsonVerify = {'distribution': distro, 'analysis': analysis,
                      'report_url': report_url, 'report_id': report_id}
        print('Json object is set: %s', jsonVerify)
        result = requests.post(url, data=json.dumps(jsonVerify),
                               headers=headers, verify=False)
        print(result.text)
        sys.exit(int(result.text))
    except ConnectionError as e:
        print('Exception ConnectionException %s', e)
        sys.exit(2)
