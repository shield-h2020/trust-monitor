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
@app.route("/vnsfo_connector/list_nodes", methods=["GET"])
def list_nodes():
    # TODO: Implement API call and result translation
    # app.logger.debug('Get the list of VIMs from vNSFO')
    # list_nodes = []
    # jsonResult = getNodeInformationFromVNSFO()

    # app.logger.info(list_nodes)
    # return flask.Response(json.dumps(list_nodes))
    pass


# Get the list of vnfs
@app.route("/vnsfo_connector/list_vnfs_vim", methods=["POST"])
def list_vnfs_vim():
    # TODO: Implement API call and result translation
    # app.logger.info('Get the list of VNFs from vNSFO')
    # list_vnf = []
    # jsonResult = getVNSFInformationFromVNSFO()
    # jsonResponse = {'vim_vnf': list_vnf}
    # return flask.Response(json.dumps(jsonResponse))
    pass


# started from list of ip of node to get the name of vim with their ip, if the
# ip are equivalent
@app.route("/vnsfo_connector/get_vim_by_ip", methods=["POST"])
def get_vim_by_ip():
    # TODO: Implement API call and result translation
    # list_ip = []
    # app.logger.info('Get list VIM by ip')
    # if request.is_json:
    #     app.logger.info('Received a json object')
    #     data = request.get_json()
    #     app.logger.info('The data are: %s' % data)
    # else:
    #     jsonResponse = {'error': 'Accept only json objects'}
    #     app.logger.error(jsonResponse)
    #     return flask.Response(json.dumps(jsonResponse))
    # list_ip_by_TM = data['ip']
    # jsonResult = getNodeInformationFromVNSFO()
    # if isinstance(list_vim_ip, list):
    #     app.logger.info('The list of vim with their ip is %s'
    #                     % str(list_vim_ip))
    #     for vim in list_vim_ip:
    #         app.logger.debug('Analyze vim %s' % str(vim))
    #         if vim['ip'] not in list_ip_by_TM:
    #             app.logger.debug('Remove vim to the list')
    #             list_vim_ip.remove(vim)
    # return flask.Response(json.dumps(list_vim_ip))
    pass


# API call toward vnsfo
def getVNSFInformationFromVNSFO():
    url = vnsfo_baseurl + "/vnsf/running"
    app.logger.info(url)
    response = requests.get(url)
    logger.debug('Response received from vNSFO API: ' + response.text)
    return response.json()


# API call towards VNSFO
def getNodeInformationFromVNSFO():
    url = vnsfo_baseurl + "/nfvi/nodes"
    app.logger.info(url)
    response = requests.get(url)
    logger.debug('Response received from vNSFO API: ' + response.text)
    return response.json()


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vnsfo_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
