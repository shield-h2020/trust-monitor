from flask import Flask
from flask import request
import json
import logging
import flask
from subprocess import *
from requests.exceptions import ConnectionError
import vnsfo_settings
import requests
import os

vnsfo_baseurl = vnsfo_settings.VNSFO_BASE_URL
app = flask.Flask('vnsfo_connector')


@app.route("/vnsfo_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of vnsfo_connector')
    jsonResponse = {'Active': True}
    app.logger.info(str(jsonResponse))
    return flask.Response(json.dumps(jsonResponse))


# Get list of Nodes (compute, switches) with their IP throught vNSFO
@app.route("/vnsfo_connector/list_nodes", methods=["GET"])
def list_nodes():
    app.logger.debug('Get the list of nodes from vNSFO')
    listJsonNodes = getNodeInformationFromVNSFO()
    app.logger.info(str(listJsonNodes))
    return flask.Response(json.dumps(listJsonNodes))


# Retrieve the VIM name from IP
@app.route("/vnsfo_connector/get_vim_by_ip", methods=["POST"])
def get_vim_by_ip():
    if request.is_json:
        data = request.get_json()
    else:
        jsonResponse = {'Error': 'Missing vim_ip data'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))

    vim_ip = data['vim_ip']
    app.logger.info('Get VIM by ip: ' + vim_ip)
    jsonNodes = getNodeInformationFromVNSFO()
    app.logger.debug(jsonNodes)

    for jsonNode in jsonNodes:
        app.logger.debug('Analyze node %s' % str(jsonNode["node"]))
        if jsonNode['ip'] == vim_ip:
            return flask.Response(json.dumps(jsonNode))

    return flask.Response({'Error': 'No VIM found with ip_address ' + vim_ip})


# Get the list of vnfs for a specific VIM
@app.route("/vnsfo_connector/list_vnfs_vim", methods=["POST"])
def list_vnfs_vim():
    if request.is_json:
        req_data = request.get_json()
    else:
        jsonResponse = {'Error': 'Missing vim_name data'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))

    vim_name = req_data['vim_name']
    app.logger.info('Retrieve VNFs for VIM: %s' % vim_name)

    list_vim_vnf = getVNSFInformationFromVNSFO(vim_name)
    return flask.Response(json.dumps(list_vim_vnf))


# API call toward vnsfo
# get list of running vnf for a specific VIM
# returns a list of objects:
# {'vim': <host_name>, 'list_vnf': [{'name': 'vnf_name', 'id': 'vnf_id}]}
def getVNSFInformationFromVNSFO(vim_name):
    url = vnsfo_baseurl + "/vnsf/running"
    app.logger.info(url)
    response = requests.get(url, verify=False)
    app.logger.debug('Response received from vNSFO API: ' + response.text)
    vnsfsJson = response.json()
    vnf_list = []

    try:
        # for each running VNF, verify if it belongs to this VIM
        for vnsfJson in vnsfsJson:
            if vnsfJson['vim'] == vim_name:
                vnf_list.append(
                    {'name': vnsfJson['vnf_name'], 'id': vnsfJson['vnf_id']})
    except Exception:
        # single JSON result
        vnf_list.append(
            {'name': vnsfsJson['vnf_name'], 'id': vnsfsJson['vnf_id']})

    return {'node': vim_name, 'list_vnf': vnf_list}


# API call towards VNSFO
# returns a list of objects: {'node': <node>, 'uuid': <uuid>, 'ip': <ip>}
def getNodeInformationFromVNSFO():
    url = vnsfo_baseurl + "/node"
    app.logger.info(url)
    response = requests.get(url, verify=False)
    app.logger.debug('Response received from vNSFO API: ' + response.text)
    nodesJson = response.json()
    list_vim_ip = []
    try:
        for nodeJson in nodesJson:
            dict = {'node': nodeJson['host_name'],
                    'uuid': nodeJson['node_id'],
                    'ip': nodeJson['ip_address']}
            list_vim_ip.append(dict)

    except Exception:
        # single result, JSON dict
        list_vim_ip.append(
            {'node': nodesJson['host_name'],
             'uuid': nodesJson['node_id'],
             'ip': nodesJson['ip_address']})

    if not list_vim_ip:
        app.logger.warning("No nodes detected from VNSFO")

    return list_vim_ip


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vnsfo_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
