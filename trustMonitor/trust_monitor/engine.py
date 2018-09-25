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
from trust_monitor.verifier.instantiateDB import DigestListUpdater
from trust_monitor_driver.driverOAT import DriverOAT
from trust_monitor_driver.driverOpenCIT import DriverCIT
from trust_monitor_driver.driverHPE import DriverHPE
from trust_monitor_driver.driverConstants import *
from trust_monitor.attestation_data import AttestationStatus


headers = {'content-type': 'application/json'}

logger = logging.getLogger('django')


###############################################################################
# Interaction with connectors
###############################################################################


def get_vnsfs_digests_from_store(list_vnfd):
    try:
        logger.info('Call method of store_connector to get the digests of '
                    'vnfs')
        urlStore = (settings.BASIC_URL_STORE +
                    '/store_connector/get_vnsfs_digests')
        jsonListVnf = {'list_vnfd': list_vnfd}
        responseJson = requests.post(urlStore, json=jsonListVnf).json()
        logger.info('Response is %s' % responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to store connector'}
        logger.error(jsonError)
        return False


def send_notification_dare(jsonResult):
    logger.info('Send attestation result to DARE connector')
    # send attestation result to DARE_connector
    url = settings.BASIC_URL_DARE + "/dare_connector/attest_result"
    resp = requests.post(url, data=json.dumps(jsonResult),
                         headers=headers)
    if not resp.status_code == 200:
        logger.error(
            'Unable to send a notification to the DARE via its connector')
    else:
        logger.info('Notification sent to DARE connector')


def send_notification_dashboard(jsonMessage):
    logger.info('Send attestation notification to Dashboard connector')

    url = (
        settings.BASIC_URL_DASHBOARD +
        "/dashboard_connector/attest_notification")
    resp = requests.post(url, data=json.dumps(jsonMessage),
                         headers=headers)
    if not resp.status_code == 200:
        logger.error(
            'Unable to send a notification to the Dashboard via its connector')
    else:
        logger.info('Notification sent to Dashboard connector')


def get_nodes_from_vnsfo():
    logger.info('Retrieve nodes from vNSFO')
    url_vnsfo_connector = (
        settings.BASIC_URL_VNSFO +
        '/vnsfo_connector/list_nodes'
    )
    return requests.get(url_vnsfo_connector).json()


def get_vimemu_vim(info_vim):
    logger.info('Retrieve VIM-emu instance from NFVI')
    url_vimemu_connector = (
        settings.BASIC_URL_VIMEMU +
        '/vimemu_connector/get_vimemu_instance')

    return requests.post(
        url_vimemu_connector,
        json=info_vim).json()


def get_vnsfs_from_vim(vim):
    try:
        logger.info('Get the VNSF instances from VIM: %s' % vim)
        url_vnsfo_connector = (
            settings.BASIC_URL_VNSFO +
            '/vnsfo_connector/list_vnsfs_vim'
        )
        responseJson = requests.post(
            url_vnsfo_connector,
            json={'vim_name': vim}).json()
        logger.info(responseJson)
        return responseJson
    except ConnectionError as e:
        jsonError = {'Error': 'Impossible to contact VNSFO connector'}
        logger.error(str(e))
        return False


def get_vim_by_ip(ip):
    logger.info('Retrieve VIM by IP address')
    url_vnsfo_connector = (
        settings.BASIC_URL_VNSFO +
        '/vnsfo_connector/get_vim_by_ip'
    )
    return requests.post(
        url_vnsfo_connector,
        json={'vim_ip': ip}).json()


def get_drivers_status():
    logger.info('Get status of drivers')
    message = []
    message.append(DriverOAT().getStatus())
    message.append(DriverCIT().getStatus())
    message.append(DriverHPE().getStatus())
    logger.debug(message)
    return message


def get_connectors_status():
    logger.info('Get status of connectors')
    message = []
    urlDare = settings.BASIC_URL_DARE + '/dare_connector'
    nameConnector = 'DARE'
    message.append(get_connector_status(urlDare, nameConnector))
    urlDashboard = settings.BASIC_URL_DASHBOARD + '/dashboard_connector'
    nameConnector = 'Dashboard'
    message.append(get_connector_status(urlDashboard, nameConnector))
    urlVNSFO = settings.BASIC_URL_VNSFO + '/vnsfo_connector'
    nameConnector = 'VNSFO'
    message.append(get_connector_status(urlVNSFO, nameConnector))
    urlVIMEMU = settings.BASIC_URL_VIMEMU + '/vimemu_connector'
    nameConnector = 'VIM-EMU'
    message.append(get_connector_status(urlVIMEMU, nameConnector))
    urlStore = settings.BASIC_URL_STORE + '/store_connector'
    nameConnector = 'vNSF Store'
    message.append(get_connector_status(urlStore, nameConnector))
    logger.debug(message)
    return message


def get_databases_status():
    message = []
    logger.debug('Verify if the databases are reachable.')
    configured = False
    active = False
    if settings.CASSANDRA_LOCATION and settings.CASSANDRA_PORT:
        configured = True
        try:
            pool = pycassa.ConnectionPool(
                'system',
                [settings.CASSANDRA_LOCATION + ':' + settings.CASSANDRA_PORT]
            )
            pool.dispose()
            active = True
        except Exception as e:
            logger.error('No connection with the database')
            active = False
    message.append(
        {'whitelist-db': {'configuration': configured, 'active': active}})

    configured = True
    active = False
    try:
        # Redis DB is part of the Docker-Compose environment, so it is hardcoded
        redisDB = redis.Redis('tm_database_redis', '6379')
        redisDB.ping()
        active = True
    except Exception as e:
        logger.error('No connection with known-digests in-memory database')
        active = False
    finally:
        del redisDB
    message.append(
        {'known-digests': {'configuration': configured, 'active': active}})

    return message


def get_connector_status(urlConnector, nameConnector):
    logger.debug('Verify if connector ' + nameConnector + ' works')
    try:
        logger.debug('Try to contact ' + nameConnector +
                     ' connector on %s' % urlConnector)
        resp = requests.get(urlConnector)
        logger.debug('Status = ' + str(resp.status_code))
        active = True
    except Exception as e:
        active = False
        logger.error('Error impossible to contact ' + nameConnector +
                     ' connector')
    return {nameConnector: {'configuration': True, 'active': active}}

###############################################################################
# Attestation methods
###############################################################################


def register_node(node):

    logger.debug('The information of the node are:')
    logger.debug('Name: ' + node.hostName)
    logger.debug('Address: ' + node.address)
    logger.debug('PCR-0: ' + node.pcr0)
    logger.debug('Distribution: ' + node.distribution)
    logger.debug('Attestation driver: ' + node.driver)
    logger.debug('AnalysisType: ' + node.analysisType)

    logger.info('Call driver to manage new host')
    if node.driver == OAT_DRIVER:
        logger.info('Register node OAT')
        DriverOAT().registerNode(node)
        logger.info('OAT node registered in DB')
    elif node.driver == CIT_DRIVER:
        logger.info('Register node OpenCIT')
        DriverCIT().registerNode(node)
        logger.info('CIT node registered in DB')
    # The host is being registered in the TM application
    # Distribution is required for other drivers,
    # use generic value here.
    elif node.driver == HPE_DRIVER:
        logger.info('Register node HPESwitch')
        DriverHPE().registerNode(node)
        logger.info('HPESwitch node registered in DB')
    else:
        logger.warning("Node has unknown attestation driver")
        raise ValueError("Unknown attestation driver")


def attest_nodes(node_list):

    if not node_list:
        logger.info("Attest nodes: no information supplied on nodes. Will try \
            with all nodes.")
        # Node list should be in the form of {"node": <name>} objects
        node_list = get_nodes_from_vnsfo()

    logger.info('Received attestation request for: ' + str(node_list))
    global_status = AttestationStatus()
    for node in node_list:
        host = Host.objects.get(hostName=node['node'])
        if host.driver == CIT_DRIVER or host.driver == OAT_DRIVER:
            attest_result = attest_compute(node)
        # Append HPE nodes to list_hpe object
        elif host.driver == HPE_DRIVER:
            attest_result = attest_sdn_component(node)
        else:
            logger.warning('Node %s has unknown driver' % host.hostName)

        global_status.update(attest_result)

    try:
        send_notification_dare(global_status.json())
        send_notification_dashboard(global_status.json())
    except Exception as e:
        logger.warning("Notification issue with connectors: " + str(e))

    return global_status


def attest_sdn_component(node):
    return DriverHPE().pollHost(node)


def attest_compute(node):
    host = Host.objects.get(hostName=node['node'])
    logger.debug('Node found with ip %s' % host.address)

    list_digest = []
    try:
        logger.info('Query vNSFO (and VIM-EMU) to see if containers' +
                    ' should be added')

        info_vim = get_vim_by_ip(host.address)
        logger.debug('VIM information: ' + str(info_vim))

        # {'ip', 'xxx.xxx.xxx.xxx', 'uuid': 'uuid_vim', 'node': 'name',
        # 'containers':
        # [{'id': '121238123', 'vnfd_name': 'xxxx', 'ns_name': 'xxxx',
        # 'image':'xxx'}]}
        vim_docker = get_vimemu_vim(info_vim)

        logger.debug("VIM-emu connector response for VIM: " +
                     str(vim_docker))

        # {'node': 'name',
        # 'list_vnf': [
        # {'vnf_name': 'instance_name', 'vnf_id': 'instance_id',
        # 'vnfd_name': 'vnf_descriptor_name'
        # 'ns_name': 'ns_instance_name',
        # 'ns_id': 'ns_instance_id'}]
        vim_vnf = get_vnsfs_from_vim(host.hostName)

        logger.debug("vNSFO connector response for vNSFs: " +
                     str(vim_vnf))

        list_vnf_containers = []
        if vim_docker['containers']:
            for container in vim_docker['containers']:
                for vnf in vim_vnf['list_vnf']:
                    # TODO: verify this equality from VNSFO API
                    if (container['ns_name'] == vnf['ns_name'] and
                            container['vnfd_name'] == vnf['vnfd_name']):

                        list_vnf_containers.append(
                            {"container_id": container["id"],
                             "vnfd_name": container["vnfd_name"],
                             "vnf_id": vnf["vnf_id"],
                             "ns_id": vnf["ns_id"]})

        if not list_vnf_containers:
            logger.warning('No Docker running in the VIM ' +
                           host.hostName)
            jsonAttest = {'node': host.hostName}
        else:
            logger.debug('VIM ' + host.hostName + ' runs VNSFs: %s'
                         % str(list_vnf_containers))
            jsonAttest = {'node': host.hostName, 'vnfs':
                          list_vnf_containers}

        list_digest = add_vnfs_measures_to_db(list_vnf_containers)

    except Exception as e:
        logger.error(str(e))
        logger.warning("The vNSFO is not reachable. Will fallback to host" +
                       " attestation only.")
        jsonAttest = {'node': host.hostName}

    if host.driver == CIT_DRIVER:
        result = DriverCIT().pollHost(jsonAttest)
    elif host.driver == OAT_DRIVER:
        result = DriverOAT().pollHost(jsonAttest)

    if 'vnfs' in jsonAttest:
        # One or more VNFs have been attested for the compute node
        remove_vnfs_measures_from_db(list_digest)

    return result

###############################################################################
# Interaction with Redis database (for known digests)
###############################################################################


def remove_vnfs_measures_from_db(list_digest):
    logger.info("Removing VNF entries from whitelist data")
    value = delete_from_redis_db(list_digest)
    if value is not True:
        logger.warning('Impossible to communicate with Redis, '
                       'the measure not are removed from DB')


# [{"container_id": container["id"],
# "vnfd_name": container["vnfd_name"],
# "vnf_id": vnf["id"],
# "ns_id": vnf["ns_id"]}]
def add_vnfs_measures_to_db(list_vnf_containers):
    logger.info("Including VNF entries in whitelist data")

    list_vnfd = []
    for vnf in list_vnf_containers:
        list_vnfd.extend(vnf["vnfd_name"])

    logger.info('All vnfds are %s' % str(list_vnfd))
    list_digest = get_vnsfs_digests_from_store(list_vnfd)
    if list_digest is False:
        logger.warning('Impossible to obtain the list of digest')
    if list_digest:
        value = add_to_redis_db(list_digest)
        if value is not True:
            logger.warning('Impossible to communicate with Redis, '
                           'the measure not are added in DB')
    return list_digest


# Start with list of digest obtained to the method store_vnsfs_digests
# list_digest = [{'pathFile': 'digest_of_measure'}]
def add_to_redis_db(list_digest):
    logger.info('Adding digests to Redis DB')
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
                        logger.debug('The digest already exists in redis')
                    else:
                        logger.debug('The digest is changed. Update redis')
                        redisDB(key, value)
                        DigestListUpdater.remove_known_digest(data)
                        DigestListUpdater.append_known_digest(value)

        logger.info("Removed digests from Redis DB")
        return True
    except redis.ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to Redis db'}
        logger.warning(jsonError)
        return jsonError
    finally:
        del redisDB


def delete_from_redis_db(list_digest):
    logger.info('Remove digests from Redis DB')
    logger.info('list digest %s' % list_digest)
    try:
        from trust_monitor.verifier.instantiateDB import DigestListUpdater
        redisDB = redis.Redis(host='tm_database_redis', port='6379')
        for digest in list_digest:
            for key, value in digest.items():
                data = redisDB.get(key)
                if data is None:
                    logger.debug('The digest is not present in redis')
                else:
                    redisDB.delete(key)
                DigestListUpdater.remove_known_digest(data)

        logger.info("Removed digests from Redis DB")
        return True
    except redis.ConnectionError as e:
        jsonError = {'Error': 'Impossible contact to Redis db'}
        logger.warning(jsonError)
        return jsonError
    finally:
        del redisDB
