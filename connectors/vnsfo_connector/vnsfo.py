from flask import Flask
from flask import request
import json
import logging
import flask
from docker import *
from requests.exceptions import ConnectionError
import vnsfo_settings
import requests

vnsfo_baseurl = vnsfo_settings.VNSFO_BASE_URL
app = flask.Flask('vnsfo_connector')


@app.route("/vnsfo_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of vnsfo_connector')
    jsonResponse = {'Active': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


# Get list of VIM with their IP throught vNSFO
@app.route("vnsfo_connector/list_vim_instances", methods=["GET"])
def listVimInstances():
    app.logger.debug('Get the list of VIMs from vNSFO')
    list_vim_ip = []
    jsonResult = getVimInformationFromVNSFO()
    # TODO: translate jsonResult in list_vim_ip
    app.logger.info(list_vim_ip)
    return flask.Response(json.dumps(list_vim_ip))


# API call towards VNSFO
def getVimInformationFromVNSFO():
    url = vnsfo_baseurl + "/nfvi/nodes"
    app.logger.info(url)
    response = requests.get(url)
    logger.debug('Response received from vNSFO API: ' + response.text)
    return response.json()


# Get the list of vnfs
@app.route("/vnsfo_connector/list_vnf_instances", methods=["GET"])
def listVnfInstances():
    app.logger.info('Get the list of VNFs from vNSFO')
    list_vnf = []
    jsonResult = getVNSFInformationFromVNSFO()
    # TODO: translate jsonResult in list_vnf
    jsonResponse = {'vim_vnf': list_vnf}
    return flask.Response(json.dumps(jsonResponse))


# API call toward vnsfo
def getVNSFInformationFromVNSFO():
    url = vnsfo_baseurl + "/vnsf/running"
    app.logger.info(url)
    response = requests.get(url)
    logger.debug('Response received from vNSFO API: ' + response.text)
    return response.json()


# started from list of ip of node to get the name of vim with their ip, if the
# ip are equivalent
@app.route("/vnsfo_connector/get_vim_by_ip", methods=["POST"])
def get_vim_by_ip():
    list_ip = []
    app.logger.info('Get list VIM by ip')
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        app.logger.info('The data are: %s' % data)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    list_ip_by_TM = data['ip']
    jsonResult = getVimInformationFromVNSFO()
    # TODO: translate jsonResult in list_vim_ip

    if isinstance(list_vim_ip, list):
        app.logger.info('The list of vim with their ip is %s'
                        % str(list_vim_ip))
        for vim in list_vim_ip:
            app.logger.debug('Analyze vim %s' % str(vim))
            if vim['ip'] not in list_ip_by_TM:
                app.logger.debug('Remove vim to the list')
                list_vim_ip.remove(vim)
    return flask.Response(json.dumps(list_vim_ip))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vnsfo_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
