from flask import Flask
from flask import request
from flask import jsonify
import json
import logging
import flask
import yaml

app = Flask('store_connector')


@app.route("/store_connector/get_vnsfs_digests",
           methods=["POST"])
def store_vnsfs_digests():
    app.logger.debug('In post method of store_connector/get_vnsfs_digests')
    if request.is_json:
        app.logger.info('Received a json object')
        data = request.get_json()
        app.logger.info('The data are: %s' % data)
    else:
        jsonResponse = {'error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))
    app.logger.debug('parsing data')
    list_digest = parser_data(data)
    app.logger.info('Measures: %s' % str(list_digest))
    return flask.Response(json.dumps(list_digest))


def parser_data(data):
    app.logger.info('Parser data')
    app.logger.info(data)
    app.logger.info(data['list_vnf'])
    list_digest = []
    try:
        for vnf in data['list_vnf']:
            app.logger.info('Analyze file %s' % str(vnf))
            stream = file(str(vnf)+'.yaml')
            doc = yaml.load(stream)
            values = (doc['manifest:vnsf']['security_info']['vdu']
                      [0]['attestation'])
            if values is not None:
                app.logger.debug('Measure %s' % str(values))
                for key, value in values.iteritems():
                    temp = {key: value}
                    list_digest.append(temp)
    except IOError as ioe:
        json_error = {'Error': 'impossible to find vnf'}
        app.logger.error(json_error)
        return json_error
    except yaml.YAMLError, exc:
        json_error = {'Error in configuration file': exc}
        app.logger.error(json_error)
        return json_error
    return list_digest


@app.route("/store_connector", methods=["GET"])
def get_store_running():
    app.logger.debug('In get method of dare_connector')
    app.logger.info('running')
    jsonResponse = {'running': True}
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
