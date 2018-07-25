from django.conf import settings
import requests
from requests.exceptions import ConnectionError
import logging
import json
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from trust_monitor.models import Host
import redis
import pycassa
from trust_monitor.verifier.structs import *
from trust_monitor.verifier.instantiateDB import *
from trust_monitor_driver.driverOAT import DriverOAT
from trust_monitor_driver.driverOpenCIT import DriverCIT
from trust_monitor_driver.driverHPE import DriverHPE

headers = {'content-type': 'application/json'}
distCassandra = settings.CASSANDRA_LOCATION
port = settings.CASSANDRA_PORT

logger = logging.getLogger('django')


###############################################################################
# Interaction with connectors
###############################################################################


def send_notification_dare(jsonResult):
    logger.info('Send attestation result to DARE connector')
    # send attestation result to DARE_connector
    try:
        url = settings.BASIC_URL_DARE + "/dare_connector/attest_result"
        resp = requests.post(url, data=json.dumps(jsonResult),
                             headers=headers)
        logger.info('Attestation result sent to DARE connector')

    except ConnectionError as e:
        error = {'Impossible to contact': url}
        logger.warning('Warning: ' + str(e))


def send_notification_dashboard(jsonMessage):
    # if (jsonMessage['NFVI'] == 'untrusted'):
    logger.info('Send attestation notification to dashboard connector')
    try:
        url = (
            settings.BASIC_URL_DASHBOARD +
            "/dashboard_connector/attest_notification")
        response = requests.post(url, data=json.dumps(jsonMessage),
                                 headers=headers)
        logger.info('Attestation failed sent to dashboard connector')
    except ConnectionError as e:
        error = {'Error impossible to contact': url}
        logger.warning('Warning: ' + str(e))


def get_nodes_from_vnsfo():
    logger.info('Retrieve nodes from vNSFO')
    url_vnsfo_connector = (
        settings.BASIC_URL_VNSFO +
        'vnsfo/list_nodes'
    )
    return requests.get(url_vnsfo_connector).json()


def get_vimemu_vims(list_info_vim):
    logger.info('Retrieve VIM-emu instances from NFVI')
    url_vimemu_connector = (
        settings.BASIC_URL_VIMEMU +
        'vimemu/list_vimemu_instances')

    return requests.post(
        url_vimemu_connector,
        json=list_info_vim).json()


def get_vim_by_ip(ip):
    logger.info('Retrieve VIM by IP address')
    url_vnsfo_connector = (
        settings.BASIC_URL_VNSFO +
        'vnsfo/get_vim_by_ip'
    )
    return requests.post(
        url_vnsfo_connector,
        json={'ip': [ip]}).json()


def get_vnsfs_from_vim(vim):
    try:
        logger.info('Get the VNSF instances from VIM: %s' % vim)
        url_vnsfo_connector = (
            settings.BASIC_URL_VNSFO +
            'vnsfo/list_vnfs_vim'
        )
        responseJson = requests.post(
            url_vnsfo_connector).json()
        logger.info(responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible to contact VNSFO connector'}
        logger.error(jsonError)
        return False


def get_connectors_status():
    logger.info('Get status of connectors')
    message = []
    logger.debug('Verify if Cassandra works at: ' + distCassandra + ':' +
                 port)
    try:
        pool = pycassa.ConnectionPool('system', [distCassandra + ':' +
                                                 port])
        pool.dispose()
        message_cass = {'Cassandra works': True}
        logger.info('%s' % str(message_cass))
        message.append(message_cass)
    except pycassa.pool.AllServersUnavailable as e:
        logger.error('Cassandra do not work')
        error_cass = {'Cassandra works': False}
        message.append(error_cass)
    urlDare = settings.BASIC_URL_DARE + '/dare_connector'
    nameConnector = 'DARE'
    get_connector_status(message, urlDare, nameConnector)
    urlDashboard = settings.BASIC_URL_DASHBOARD + '/dashboard_connector'
    nameConnector = 'Dashboard'
    get_connector_status(message, urlDashboard, nameConnector)
    urlVNSFO = settings.BASIC_URL_VNSFO + '/vnsfo_connector'
    nameConnector = 'VNSFO'
    get_connector_status(message, urlVNSFO, nameConnector)
    urlVIMEMU = settings.BASIC_URL_VIMEMU + '/vimemu_connector'
    nameConnector = 'VIMEMU'
    get_connector_status(message, urlVIMEMU, nameConnector)
    urlStore = settings.BASIC_URL_STORE + '/store_connector'
    nameConnector = 'Store'
    get_connector_status(message, urlStore, nameConnector)
    get_redis_status(message)
    return message


def get_connector_status(message, urlConnector, nameConnector):
    logger.debug('Verify if connector ' + nameConnector + ' works')
    try:
        logger.debug('Try to contact ' + nameConnector +
                     ' connector on %s' % urlConnector)
        resp = requests.get(urlConnector)
        logger.debug('Status = ' + str(resp.status_code))
        mess = {nameConnector + ' connector works': True}
        logger.info('%s' % str(mess))
        message.append(mess)
    except ConnectionError as e:
        error = {nameConnector + ' connector works': False}
        logger.error('Error impossible to contact ' + nameConnector +
                     ' connector')
        message.append(error)

###############################################################################
# Attestation methods
###############################################################################


# TODO: add call to connectors
def attest_nodes(node_list):

    if not node_list:
        logger.info("Attest nodes: no information supplied on nodes. Will try \
            with all nodes.")
        node_list = get_nodes_from_vnsfo()

    logger.info('Received attestation request for: ' + str(node_list))
    global_status = AttestationStatus()
    for node in node_list:
        host = Host.objects.get(hostName=node['node'])
        if host.driver == 'OpenCIT':
            attest_result = attest_compute(node)
        elif host.driver == 'OAT':
            attest_result = attest_compute(node)
        # Append HPE nodes to list_hpe object
        elif host.driver == "HPESwitch":
            attest_result = attest_sdn_component(node)
        else:
            logger.warning('Node %s has unknown driver' % host.hostName)

        global_status.update(attest_result)

    send_notification_dare(attest_result)
    send_notification_dashboard(attest_result)

    return global_status


def attest_sdn_component(node):
    return DriverHPE().pollHost(node)


def attest_compute(node):
    host = Host.objects.get(hostName=node)
    logger.debug('Node found with ip %s' % host.address)

    try:
        logger.info('Query vNSFO (and VIM-EMU) to see if containers \
            should be added')

        list_info_vim = get_vim_by_ip(host.address)
        logger.debug('VIM: ' + str(list_info_vim))

        responseJson = get_vimemu_vims(list_info_vim)

        logger.debug("VIM-emu connector response for VIM: " + str(responseJson))

        list_vim_docker = responseJson['VIM']

        logger.info('The information are %s'
                    % str(list_vim_docker))

        list_docker_id = list_vim_docker[0]['docker_id']

        if not list_docker_id:
            logger.warning('No Docker running in the VIM')
            jsonAttest = {'node': host.hostName}
        else:
            logger.debug('With this docker id: %s'
                         % str(list_docker_id))
            jsonAttest = {'node': host.hostName, 'vnfs':
                          list_docker_id}

        list_vim_vnf = get_vnsfs_from_vim(list_info_vim[0]['vim'])

        add_container_measures_to_db(list_vim_vnf, list_info_vim)

    except Exception as e:
        logger.error(str(e))
        logger.warning("The vNSFO is not reachable. Will fallback to host \
            attestation only.")
        jsonAttest = {'node': host.hostName}

    if host.driver == 'OpenCIT':
        return DriverCIT().pollHost(jsonAttest)
    elif host.driver == 'OAT':
        return DriverOAT().pollHost(jsonAttest)


###############################################################################
# Interaction with Redis database (for known digests)
###############################################################################


def add_container_measures_to_db(list_vim_vnf, list_vim):
    if list_vim_vnf is False:
        logger.warning('Impossible to get the information of vnfs '
                       'for each vim (list of vNSF is empty)')
    if isinstance(list_vim_vnf, dict):
        list_vnf = []
        for vim in list_vim_vnf['vim_vnf']:
            list_vnf.extend(vim['list_vnf'])
        logger.info('All vnfs are %s' % str(list_vnf))
        list_digest = store_vnsfs_digests(list_vnf)
        if list_digest is False:
            logger.warning('Impossible to obtain the list of digest')
        if list_digest:
            value = redis_db(list_digest)
            if value is not True:
                logger.warning('Impossible to communicate with Redis, '
                               'the measure not are added in DB')
    else:
        logger.warning('No vnf for vim: '+str(list_vim)+' are in executions')


def store_vnsfs_digests(list_vnf):
    try:
        logger.info('Call method of store_connector to get the digests of '
                    'vnfs')
        urlStore = (settings.BASIC_URL_STORE +
                    '/store_connector/get_vnsfs_digests')
        jsonListVnf = {'list_vnf': list_vnf}
        responseJson = requests.post(urlStore, json=jsonListVnf).json()
        logger.info('Response is %s' % responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to store connector'}
        logger.error(jsonError)
        return False


# Start with list of digest obtained to the method store_vnsfs_digests
# list_digest = [{'pathFile': 'digest_of_measure'}]
def redis_db(list_digest):
    logger.info('Added digest to Redis DB')
    logger.info('list digest %s' % list_digest)
    try:
        from trust_monitor.verifier.instantiateDB import DigestListUpdater
        redisDB = redis.Redis(host='tm_database_redis', port='6379')
        for digest in list_digest:
            for key, value in digest.items():
                data = redisDB.get(key)
                if data is None:
                    logger.debug('The digest is not present in redis')
                    logger.info('Set in redisDB key: '+key+' value: '+value)
                    redisDB.set(key, value)
                    DigestListUpdater.append_known_digest(value)
                else:
                    if data == value:
                        logger.debug('The digest already exist in redis')
                    else:
                        logger.debug('The digest is changed update redis')
                        redisDB(key, value)
                        DigestListUpdater.remove_known_digest(data)
                        DigestListUpdater.append_known_digest(value)
        return True
    except redis.ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to Redis db'}
        logger.warning(jsonError)
        return jsonError
    finally:
        del redisDB


# method used to instantiate the firsh time the lis of known_digests throught
# redis element
def redis_instantiate():
    logger.info('instantiate known_digests with elements in Redis DB')
    list_digest = []
    try:
        redisDB = redis.Redis(host='tm_database_redis', port='6379')
        list_keys = redisDB.keys('*')
        for key in list_keys:
            logger.debug('Added value of key: %s in list' % key)
            value = redisDB.get(key)
            list_digest.append(value)
    except redis.ConnectionError as e:
        jsonError = {'Error', 'Impossible to contact to Redis DB'}
        logger.warning('Impossible included the digests in Redis DB')
        logger.warning(jsonError)
    return list_digest


def get_redis_status(message):
    logger.debug('Verify if redis works')
    try:
        redisDB = redis.Redis('tm_database_redis', '6379')
        redisDB.ping()
        mess = {'Redis works': True}
        logger.info(mess)
        message.append(mess)
    except redis.ConnectionError as e:
        error = {'Redis works': False}
        logger.error('Error impossible to contact Redis')
        message.append(error)
    finally:
        del redisDB
