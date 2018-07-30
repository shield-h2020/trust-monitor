from flask import Flask
from flask import request
from flask import jsonify
import json
import logging
import flask
import yaml
import store_settings
import requests
import os.path

app = Flask('store_connector')


@app.route("/store_connector/get_vnsfs_digests",
           methods=["POST"])
def store_vnsfs_digests():
    app.logger.debug('In post method of store_connector/get_vnsfs_digests')
    # Input: { 'list_vnf' : ['name_vnf', 'name2_vnf']}
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        app.logger.info('The data are: %s' % data)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    app.logger.debug('parsing data')
    list_digest = retrieve_digests_from_store(data)
    app.logger.info('Measures: %s' % str(list_digest))
    return flask.Response(json.dumps(list_digest))


def load_security_manifest_from_store(vnf):

    result = {}
    if os.path.isfile(str(vnf) + '.yaml'):
        app.logger.debug('Analyze file %s' % str(vnf))
        stream = file(str(vnf)+'.yaml')
        result = yaml.load(stream)
    else:
        app.logger.debug('Contact vNSF Store API to retrieve security manifest')
        # Compose URL by attaching vnf identifier to base url
        url = store_settings.STORE_BASE_URL + '/' + str(vnf)
        app.logger.info(url)
        response = requests.get(url)
        logger.debug('Response received from vNSF Store API')
        result = yaml.load(response.text)

    logger.info("vNSF Store API response is: " + result)
    return result


def retrieve_digests_from_store(data):
    app.logger.info('Parser data')
    app.logger.info(data)
    app.logger.info(data['list_vnf'])
    list_digest = []
    for vnf in data['list_vnf']:
        try:
            sec_manifest = load_security_manifest_from_store(vnf)
            values = (sec_manifest['manifest:vnsf']['security_info']['vdu']
                      [0]['attestation'])
            if values is not None:
                app.logger.debug('Measure %s' % str(values))
                for key, value in values.iteritems():
                    temp = {key: value}
                    list_digest.append(temp)
        except IOError as ioe:
            json_error = {'Error': 'impossible to find vnf'}
            app.logger.error(json_error)
        except yaml.YAMLError, exc:
            json_error = {'Error in configuration file': exc}
            app.logger.error(json_error)
        except Exception as e:
            json_error = {'Generic error': e}
            app.logger.error(json_error)
    return list_digest


@app.route("/store_connector", methods=["GET"])
def get_store_running():
    app.logger.debug('In get method of dare_connector')
    app.logger.info('running')
    jsonResponse = {'Active': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/store_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
