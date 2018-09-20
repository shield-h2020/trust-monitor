import json
import requests
from trust_monitor.models import Host
from requests.exceptions import ConnectionError
from django.core.exceptions import ObjectDoesNotExist
import logging
from django.conf import settings
import pycassa
import redis
from trust_monitor_driver.driverOATSettings import *
from trust_monitor_driver.informationDigest import MapDigest, InformationDigest
from trust_monitor.attestation_data import (
    HostAttestation, HostAttestationExtraInfo, ContainerAttestation)
from trust_monitor_driver.driverConstants import *
from rest_framework.response import Response
from rest_framework import status
import urlparse
from trust_monitor.verifier.instantiateDB import InstantiateDigest
import ast

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger('driver')


class DriverOAT():

    headers = {'content-type': 'application/json'}

    def registerNode(self, host):
        logger.info('In registerNode method of driverOAT')
        self.confOem()
        self.confAnalysisType(host)
        self.confOs(host)
        self.confMle(host)
        self.confHost(host)
        self.confPCR(host)

    def confAnalysisType(self, host):
        logger.info('Configure AnalysisType')
        analysis = host.analysisType.split(',')[0]
        url = ('https://' + OAT_LOCATION +
               ':' + OAT_PORT + '/WLMService/resources/analysisTypes')
        jsonAnalysis = {
                'name': analysis,
                'module': 'RAVerifier', 'version': '2',
                'url': PATH_CALLBACK,
                'deleted': '0',
                'required_pcr_mask': '000000'}
        resp = requests.post(url, data=json.dumps(jsonAnalysis),
                             headers=self.headers, verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def confOem(self):
        logger.info('Configure Oem')
        url = (
            'https://'+OAT_LOCATION+':' + OAT_PORT + '/WLMService/resources/oem'
            )

        jsonOem = {'Name': 'OEM1', 'Description': 'Test id'}
        resp = requests.post(url, data=json.dumps(jsonOem),
                             headers=self.headers,
                             verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def confOs(self, host):
        logger.info('Configure Os')
        url = (
            'https://'+OAT_LOCATION+':' + OAT_PORT + '/WLMService/resources/os'
        )
        jsonOs = {'Name': host.distribution, 'Version': 'v1234',
                  'Description': 'Test1'}
        resp = requests.post(url, data=json.dumps(jsonOs),
                             headers=self.headers, verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def confMle(self, host):
        logger.info('Configure MLE')
        url = (
            'https://'+OAT_LOCATION+':'
            + OAT_PORT + '/WLMService/resources/mles'
            )
        jsonMle = {'Name': host.hostName + '-' + host.distribution,
                   'Version': '123', 'OsName': host.distribution,
                   'OsVersion': 'v1234', 'Attestation_Type': 'PCR',
                   'MLE_Type': 'VMM', 'Description': 'Test ad'}
        resp = requests.post(url, data=json.dumps(jsonMle),
                             headers=self.headers, verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def confHost(self, host):
        logger.info('Configure Host')
        url = ('https://' + OAT_LOCATION +
               ':' + OAT_PORT + '/AttestationService/resources/hosts')
        jsonHost = {'HostName': host.hostName, 'IPAddress': host.address,
                    'Port': '9999',
                    'VMM_Name': host.hostName + '-' + host.distribution,
                    'VMM_Version': '123', 'VMM_OSName': host.distribution,
                    'VMM_OSVersion': 'v1234',
                    'Email': '', 'AddOn_Connection_String': '',
                    'Description': 'null'}
        resp = requests.post(url, data=json.dumps(jsonHost),
                             headers=self.headers,
                             verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def confPCR(self, host):
        logger.info('Configure pcr value at host: ' + host.hostName)
        url = (
            'https://'+OAT_LOCATION+':' + OAT_PORT +
            '/WLMService/resources/mles'
            '/whitelist/pcr'
        )
        jsonPcr0 = {'pcrName': '0', 'pcrDigest': host.pcr0,
                    'mleName': host.hostName + '-' + host.distribution,
                    'mleVersion': '123', 'osName': host.distribution,
                    'osVersion': 'v1234'}
        resp = requests.post(url, data=json.dumps(jsonPcr0),
                             headers=self.headers,
                             verify=False)
        logger.debug('Response OAT, url: ' + url)
        logger.debug('Status = ' + str(resp.status_code))
        logger.debug('Message: ' + str(resp.text))
        return resp

    def pollHost(self, node):
        logger.info('In pollHost method in driverOAT')
        url = (
            'https://'+OAT_LOCATION+':' + OAT_PORT +
            '/AttestationService/resources'
            '/PollHosts')

        logger.info('Analyze node: ' + node['node'])
        listvnf = ''

        # Retrieve (if available) list of containers to attest
        try:
            logger.debug('Define list of vnfs for node: '
                         + node['node'])
            for vnf in node['vnfs']:
                listvnf += vnf + '+'
        except KeyError as keyErr:
            logger.warning('No vnf for node: ' + node['node']
                           + " vnfs set to ''")
        if (listvnf != ""):
            listvnf = listvnf[:-1]
            logger.info('Vnfs for node: ' + node['node'] + ' are: '
                        + str(listvnf))

        try:
            logger.debug('Search node: ' + node['node']
                         + ' in the database of Django')
            host = Host.objects.get(hostName=node['node'])
            logger.info('Node found ' + host.hostName + ' with '
                        'this analysisType: ' + host.analysisType
                        + listvnf)
            # Define structure to send to OAT Verifier
            jsonAttest = {'hosts': [host.hostName],
                          'analysisType': host.analysisType + listvnf}
            logger.debug('Define json object %s to be sent to OAT '
                         'to perform attestation' % jsonAttest)
            respo = requests.post(url, data=json.dumps(jsonAttest),
                                  headers=self.headers, verify=False)

            # PollHosts only attests a single node per time, extract the Json
            # of the first (and only) host in the response
            jsonResponse = json.loads(respo.text)['hosts']
            jsonElem = jsonResponse[0]

            # Extract initial information from report
            trust = extractTrustLevelFromResult(jsonElem['trust_lvl'])
            analysis_status = extractAnalysisStatusFromResult(
                jsonElem['analysis_details']['status'])

            # Retrieve extra info on digests from global map
            info_digest = MapDigest.mapDigest[host.hostName]

            listNotFound = ast.literal_eval(info_digest.list_not_found)
            listFakeLib = ast.literal_eval(info_digest.list_fake_lib)

            extra_info = HostAttestationExtraInfo(
                info_digest.n_digests_ok,
                info_digest.n_digests_not_found,
                info_digest.n_digests_fake_lib,
                listNotFound,
                listFakeLib,
                info_digest.n_packages_ok,
                info_digest.n_packages_security,
                info_digest.n_packages_unknown,
                info_digest.n_packages_not_security
            )

            # Retrieve containers information (if available)
            list_container_attestation = []
            if info_digest.list_containers:
                for container in info_digest.list_containers.split('+'):
                    if(container in info_digest.list_prop_not_found):
                        trust_cont = False
                    else:
                        trust_cont = True
                    container_attestation = ContainerAttestation(
                        container,
                        trust_cont,
                        # TODO: missing vnf id and name
                        "vnf_id",
                        "vnf_name"
                    )
                    list_container_attestation.append(container_attestation)

            # Create (and return) the final HostAttestation object
            host_attestation = HostAttestation(
                host.hostName,
                trust,
                analysis_status,
                extra_info,
                list_container_attestation,
                OAT_DRIVER
            )
            try:
                del MapDigest.mapDigest[host.hostName]
            except KeyError as ke:
                logger.warning('Node %s no in map' % host.hostName)
            InformationDigest.host = ''
        except Exception as e:
            logger.error("Error occurred in driverOAT pollHost: " + str(e))
            return None

        return host_attestation

    def getStatus(self):
        logger.info('Get Status of Driver OAT')
        configured = False
        active = False
        if not OAT_LOCATION:
            logger.warning('The OAT driver is not configured')
            configured = False
        else:
            configured = True

        try:
            url = (
                'https://' + OAT_LOCATION + ':'
                + OAT_PORT + '/WLMService/resources/oem')

            logger.debug('Try to contact OAT on %s' % url)
            resp = requests.get(url, verify=False, timeout=5)
            logger.debug('Status = ' + str(resp.status_code))
            active = True
        except Exception as e:
            active = False
            logger.error('Error impossible to contact OAT %s' % str(e))

        return {OAT_DRIVER: {'configuration': configured, 'active': active}}


def extractTrustLevelFromResult(trust_lvl):
    if trust_lvl == "trusted":
        return True
    else:
        return False


def extractAnalysisStatusFromResult(analysis_status):
    if analysis_status == "ANALYSIS_COMPLETED":
        return 0
    else:
        return -1


def resolveOATVerifierUrl(report_url):
    parsed_url = urlparse.urlparse(report_url)
    resolved_url = report_url.replace(
        parsed_url.netloc,
        OAT_LOCATION + ':' + OAT_PORT)

    return resolved_url


def verify_callback(distro, analysis, report_url, report_id):
    report_url = resolveOATVerifierUrl(report_url)

    logger.debug('Serializaton of information passed of post '
                 'method are valid, the information are: \n'
                 'Distro: %s, Analysis: %s, Report_url: %s, '
                 'Report_id: %s', distro, analysis, report_url,
                 report_id)
    logger.info('Subprocessing OAT verification')
    from subprocess import Popen, PIPE
    bash = ("python trust_monitor_driver/subprocess_oat.py"
            " --analysis " + str(analysis) + " --report_url "
            + str(report_url) + " --distro " + str(distro) +
            " --report_id " + str(report_id) + " --listdigest " +
            " ".join(item for item in InstantiateDigest.known_digests)
            + " --portCassandra " + settings.CASSANDRA_PORT +
            " --ipCassandra " + settings.CASSANDRA_LOCATION)
    process = Popen(bash.split(), stdout=PIPE, stderr=PIPE)
    out, err = process.communicate()
    logger.info('Returned from OAT verification')
    if out:
        info_digest = InformationDigest()
        list_data = out.split('\n')
        result = int(list_data[0])
        if result == 2:
            return Response(result,
                            status=(status.
                                    HTTP_500_INTERNAL_SERVER_ERROR))
        info_digest.list_not_found = list_data[1]
        info_digest.list_fake_lib = list_data[2]
        info_digest.n_digests_ok = int(list_data[3])
        info_digest.n_digests_not_found = int(list_data[4])
        info_digest.n_digests_fake_lib = int(list_data[5])
        info_digest.list_containers = list_data[6]
        info_digest.list_prop_not_found = list_data[7]
        info_digest.n_packages_ok = int(list_data[8])
        info_digest.n_packages_security = int(list_data[9])
        info_digest.n_packages_not_security = int(list_data[10])
        info_digest.n_packages_unknown = int(list_data[11])
        info_digest.host = list_data[12]
        MapDigest.mapDigest[info_digest.host] = info_digest
        del info_digest
        return Response(result, status=status.HTTP_200_OK)
    else:
        logger.error('Missing expected output from subprocess_OAT')
        logger.error(err)
        return Response(2, status=(status.
                                   HTTP_500_INTERNAL_SERVER_ERROR))
