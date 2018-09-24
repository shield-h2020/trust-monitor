from flask import Flask
from flask import request
import json
import logging
import flask
from subprocess import *
from docker import *
from requests.exceptions import ConnectionError
import vimemu_settings


app = flask.Flask('vimemu_connector')


@app.route("/vimemu_connector", methods=["GET"])
def getStatus():
    app.logger.debug('In get method of vimemu_connector')
    jsonResponse = {'Active': True}
    app.logger.info(jsonResponse)
    return flask.Response(json.dumps(jsonResponse))


# Start with VIM with thier ip and get the list of vim with docker
@app.route("/vimemu_connector/get_vimemu_instance", methods=["POST"])
def get_vimemu_instance():
    app.logger.debug('In vimemu_connector/get_vimemu_instance')
    if request.is_json:
        info_vim = request.get_json()
    else:
        jsonResponse = {'Error': 'Accept only json objects'}
        app.logger.error(jsonResponse)
        return flask.Response(json.dumps(jsonResponse))

    info_vim = get_containers_per_vimemu(info_vim)
    return flask.Response(json.dumps(info_vim))


# start with vim with its ip, this method uses this information to
# define the list of docker in execution for the vim,
# info_vim = [{'ip', 'xxx.xxx.xxx.xxx', 'uuid': 'uuid_vim', 'node': 'name'}]
# return info_vim with docker_id ['id1', 'id2']
def get_containers_per_vimemu(info_vim):
    try:
        app.logger.info('Analyze VIM: ' +
                        info_vim['node'] + ' ip: ' + info_vim['ip'])

        docker_server = ('tcp://' + info_vim['ip'] + ':' +
                         vimemu_settings.VIM_EMU_DOCKER_PORT)

        app.logger.debug("Docker client connect to : " + docker_server)
        client = Client(base_url=docker_server,
                        timeout=10)
        app.logger.debug('Connected with vim, now get list docker Id')
        list_containers = []
        for container in client.containers():
            if container['State'] == 'running':
                app.logger.debug('Container Id: %s'
                                 % container['Id'][0:12])
                list_containers.append(
                    {'id': container['Id'][0:12],
                        # TODO: get ip address
                     'address': 'x.x.x.x',
                     'image': 'example'})

        if not list_containers:
            app.logger.warning('No docker running')
        app.logger.info('Add list containers at VIM')
        info_vim.update({'containers': list_containers})
    except ConnectionError as exc:
        jsonResponse = {'Error': "Connection error with VIM-emu"}
        app.logger.error(str(exc))
        client.close()
        return jsonResponse
    client.close()
    app.logger.debug(str(info_vim))
    return info_vim


if __name__ == '__main__':
    logFormatStr = (' %(levelname)s [%(asctime)s] %(module)s'
                    ' - %(message)s')
    formatter = logging.Formatter(logFormatStr, '%Y-%b-%d %H:%M:%S')
    fileHandler = logging.FileHandler("/logs/vimemu_connector.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.run(debug=True, host='0.0.0.0')
