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

    list_vnfd_digest = retrieve_digests_from_store(data['list_vnfd'])
    app.logger.info('Measures: %s' % str(list_vnfd_digest))
    return flask.Response(json.dumps(list_vnfd_digest))


def retrieve_digests_from_store(list_vnfd):
    list_vnfd_digest = []
    for vnfd_id in list_vnfd:
        try:
            list_vnfd_digest.append(load_attestation_data_from_store(vnfd_id))
        except Exception as e:
            json_error = {'Generic error': e}
            app.logger.error(str(e))
    return list_vnfd_digest


def load_attestation_data_from_store(vnfd_id):
    app.logger.debug(
        'Contact vNSF Store API to retrieve attestation file')

    attestation_filename = str(vnfd_id) + "_attestation.json"
    if os.path.isfile(attestation_filename):
        app.logger.debug('Analyze file %s' % attestation_filename)
        stream = file(attestation_filename)
        data = json.load(stream)
    else:
        # Compose URL by attaching vnf identifier to base url
        url = store_settings.STORE_BASE_URL + str(vnfd_id)
        app.logger.info(url)
        response = requests.get(url, verify=False,
                                timeout=int(store_settings.STORE_TIMEOUT))
        app.logger.debug('Response received from vNSF Store API: ' +
                         response.text)
        data = json.loads(response.text)

    app.logger.info(data)
    digests_list = []
    for vdu_digest in data["digests"]:
        for key in vdu_digest.keys():
            if key != "instance":
                digests_list.append({key: vdu_digest[key]})

    return {'vnfd_id': vnfd_id, 'digests': digests_list}


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
