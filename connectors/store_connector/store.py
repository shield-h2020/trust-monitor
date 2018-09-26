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
    # Input: { 'list_vnfd' : ['name_vnf', 'name2_vnf']}
    data = request.get_json()

    list_digest = retrieve_digests_from_store(data['list_vnfd'])
    app.logger.info('Measures: %s' % str(list_digest))
    return flask.Response(json.dumps(list_digest))


def load_attestation_data_from_store(vnfd):
    app.logger.debug(
        'Contact vNSF Store API to retrieve attestation file')

    if os.path.isfile(str(vnfd) + '.json'):
        app.logger.debug('Analyze file %s' % str(vnfd))
        stream = file(str(vnfd)+'.json')
        data = json.load(stream)
    else:
        # Compose URL by attaching vnf identifier to base url
        url = store_settings.STORE_BASE_URL + str(vnfd)
        app.logger.info(url)
        response = requests.get(url, verify=False)
        logger.debug('Response received from vNSF Store API')
        data = json.load(response.text)

    app.logger.info(data)
    digests_list = []
    for vdu_digest in data["digests"]:
        for key in vdu_digest.keys():
            if key != "instance":
                digests_list.append({key: vdu_digest[key]})

    return digests_list


def retrieve_digests_from_store(list_vnfd):
    list_digest = []
    for vnfd in list_vnfd:
        try:
            # sec_manifest = load_security_manifest_from_store(vnf)
            # values = (sec_manifest['manifest:vnsf']['security_info']['vdu']
            #           [0]['attestation'])
            # if values is not None:
            #     app.logger.debug('Measure %s' % str(values))
            #     for key, value in values.iteritems():
            #         temp = {key: value}
            #         list_digest.append(temp)
            list_digest.extend(load_attestation_data_from_store(vnfd))
        except Exception as e:
            json_error = {'Generic error': e}
            app.logger.error(str(e))
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
