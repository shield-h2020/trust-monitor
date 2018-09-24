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
    logger.debug('Response received from vNSFO API: ' + response.text)
    vnsfsJson = response.json()
    vnf_list = []

    if isinstance(vnsfsJson, dict):
        vnsfsJson = [vnsfsJson]

    # for each running VNF, verify if it belongs to this VIM
    for vnsfJson in vnsfsJson:
        if vnsfJson['vim'] == vim_name:
            vnf_list.append(
                {'name': vnsfJson['vnf_name'], 'id': vnsfJson['vnf_id']})

    return {'node': vim_name, 'list_vnf': vnf_list}

    # bash_ns_osm = "osm ns-list"
    # process_ns_list = Popen(bash_ns_osm.split(),
    #                         stdout=PIPE, stderr=PIPE, env=getOSMEnv())
    # output_ns, error = process_ns_list.communicate()
    # if not error:
    #     app.logger.info('Start process to get list ns in execution')
    #     for line in output_ns.split('\n')[3:-2]:
    #         app.logger.debug('Analyze NS: %s' % line)
    #         line_split = line.split()
    #         if len(line_split) > 1 and line_split[5] == 'running':
    #             ns = line_split[1]
    #             app.logger.debug('ns_name %s' % ns)
    #             data = getVNF(ns, vim_name)
    #             if data:
    #                 app.logger.debug('Data: %s added to the list' % data)
    #                 list_vim_vnf.append(data)
    #     app.logger.debug(str(list_vim_vnf))
    #     return list_vim_vnf
    # else:
    #     app.logger.error("Impossible to retrieve list of VIMs with VNFs")
    #     raise Exception('Error while retrieving list of VIMs with VNFs: ' +
    #                     str(error))


# returns a list of objects: {'vim': <host_name>, 'list_vnf': ["vnf_id_ref1",
# "vnf_id_ref2"]}
# def getVNF(ns, list_vim):
#     app.logger.info(list_vim)
#     vnfd = False
#     list_vnf = []
#     vim_vnf = {}
#     app.logger.debug('Analyze ns_name %s' % ns)
#     bash_ns_show = "osm ns-show %s" % ns
#     process_ns_show_list = Popen(bash_ns_show.split(),
#                                  stdout=PIPE, stderr=PIPE, env=getOSMEnv())
#     output_ns_show, error = process_ns_show_list.communicate()
#     if not error:
#         for line in output_ns_show.split('\n')[3:-2]:
#             line_split = line.split()
#             if len(line_split) > 1:
#                 if line_split[2].find("constituent-vnfd") != -1:
#                     vnfd = True
#                 if (vnfd is True
#                    and line_split[2].find("vnfd-id-ref") != -1):
#                     app.logger.debug('vnf name is %s' % line_split[3])
#                     list_vnf.append(line_split[3][1:-1])
#                 if (line_split[1].find('rw-nsr:datacenter') != -1
#                    and line_split[3][1:-1] in list_vim):
#                     vim = line_split[3][1:-1]
#                     app.logger.debug('Create dictionary with VIM ' + vim
#                                      + ' and vnfs ' + str(list_vnf))
#                     vim_vnf = {'vim': vim, 'list_vnf': list_vnf}
#     else:
#         app.logger.error('Impossible to connect to vNSFO')
#         jsonResponse = {'Impossible to connect to vNSFO':
#                         error.split('\n')[len(error.split('\n'))-2]}
#         return jsonResponse
#     app.logger.info(vim_vnf)
#     return vim_vnf


# API call towards VNSFO
# returns a list of objects: {'node': <node>, 'uuid': <uuid>, 'ip': <ip>}
def getNodeInformationFromVNSFO():
    url = vnsfo_baseurl + "/node"
    app.logger.info(url)
    response = requests.get(url, verify=False)
    logger.debug('Response received from vNSFO API: ' + response.text)
    nodesJson = response.json()

    if isinstance(nodesJson, dict):
        nodesJson = [nodesJson]

    list_vim_ip = []
    for nodeJson in nodesJson:
        dict = {'node': nodeJson['host_name'],
                'uuid': nodeJson['node_id'],
                'ip': nodeJson['ip_address']}
        list_vim_ip.append(dict)

    if not list_vim_ip:
        app.logger.warning("No nodes detected from VNSFO")

    return list_vim_ip

    # bash_vim_osm = "osm vim-list"
    # process_vim_list = Popen(bash_vim_osm.split(),
    #                          stdout=PIPE, stderr=PIPE, env=getOSMEnv())
    # output_vim, error = process_vim_list.communicate()
    # list_vim = []
    # list_vim_ip = []
    # if not error:
    #     app.logger.info('Start process to get list VIM')
    #     for line in output_vim.split('\n')[3:-2]:
    #         app.logger.debug('analyze vim: %s' % line)
    #         line_split = line.split()
    #         if len(line_split) > 1:
    #             dict = {'node': line_split[1],
    #                     'uuid': line_split[3]}
    #             list_vim.append(dict)
    # else:
    #     app.logger.error('Impossible to connect vNSFO')
    #     jsonResponse = {'Error':
    #                     error.split('\n')[len(error.split('\n'))-2]}
    #     return jsonResponse
    # if not list_vim:
    #     jsonError = {'Error': 'Empty VIM list in vNSFO'}
    #     app.logger.error(jsonError)
    #     return jsonError
    # for vim in list_vim:
    #     app.logger.info('Get IP from: %s' % vim['node'])
    #     bash_vim_show = "osm vim-show %s" % vim['node']
    #     process_vim_show = Popen(bash_vim_show.split(),
    #                              stdout=PIPE, stderr=PIPE, env=getOSMEnv())
    #     output_vim_show, error = process_vim_show.communicate()
    #     if not error:
    #         app.logger.debug('Get ip address for each vim')
    #         for line in output_vim_show.split('\n')[3:-2]:
    #             line_split = line.split()
    #             if len(line_split) > 1 and line_split[1] == 'vim_url':
    #                 vim_url = line_split[3]
    #                 app.logger.debug('vim_url: ' + vim_url +
    #                                  ' vim: ' + vim['node'])
    #             if len(line_split) > 1 and line_split[1] == 'type':
    #                 app.logger.debug('type vim ' + vim['node'] + ' ' +
    #                                  line_split[3])
    #                 if line_split[3].find("openstack"):
    #                     if vim_url.find("identity") == -1:
    #                         ip = vim_url.split(':')[1][2:]
    #                         app.logger.info('IP address '
    #                                         + ip + ' for ' + vim['node'])
    #                         dict = {'node': vim['node'],
    #                                 'uuid': vim['uuid'],
    #                                 'ip': ip}
    #                         list_vim_ip.append(dict)
    #     else:
    #         app.logger.error('Impossible to connect to vNSFO')
    #         jsonResponse = {'Impossible to connect to vNSFO':
    #                         error.split('\n')[len(error.split('\n'))-2]}
    #         return jsonResponse
    # if not list_vim_ip:
    #     jsonError = {'Error': 'No VIM connected with Open Source Mano'}
    #     app.logger.error(jsonError)
    #     return jsonError
    # return list_vim_ip


# def getOSMEnv():
#     osm_env = dict(os.environ)
#     osm_env['OSM_HOSTNAME'] = vnsfo_settings.OSM_IP
#     osm_env['OSM_RO_HOSTNAME'] = vnsfo_settings.OSM_IP
#     return osm_env

if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vnsfo_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
