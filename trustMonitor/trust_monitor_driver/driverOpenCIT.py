import json
import requests
from rest_framework import status
from rest_framework.response import Response
from requests.exceptions import ConnectionError
from django.core.exceptions import ObjectDoesNotExist
import logging
from django.conf import settings
from trust_monitor_driver.defineJsonCIT import DefineJsonCIT
from requests.auth import HTTPBasicAuth
from trust_monitor.verifier.parsingCIT import ParsingCIT, XML_CIT_ReportParser
from trust_monitor_driver.informationDigest import InformationDigest, MapDigest
from trust_monitor.verifier.ra_verifier import RaVerifier
import time

requests.packages.urllib3.disable_warnings()

logger = logging.getLogger('django')
distCassandra = settings.CASSANDRA_LOCATION
port = settings.CASSANDRA_PORT
verifier_cit = settings.CIT_LOCATION
defineJsonCIT = DefineJsonCIT()


def getTime():
    return int(round(time.time()*1000))


class DriverCIT():

    headers_json = {'content-type': 'application/json'}
    headers_xml = {'accept': 'application/xml'}

    # Register OpenCIT node
    def registerNode(self, host):
        logger.info('In registerNode method of driverCIT')
        pass

    # Attest OpenCIT node
    def pollHost(self, host_list, info_att_cit):
        logger.info('In pollHost method in driverOpenCIT')
        list_attest = []
        for host in host_list:
            url = ('https://'+verifier_cit +
                   ':8443/mtwilson/v2/host-attestations')
            logger.info('Analyze node: ' + host.hostName)
            try:

                jsonAttest = {'host_uuid': host.uuid_host}
                logger.debug('Define json object to be sent to OpenCIT '
                             'to perform attestation')
                start = getTime()
                respo = requests.post(url,
                                      auth=HTTPBasicAuth(
                                        'admin',
                                        'u1iGYAz3DSI9csf73qg2zA'),
                                      data=json.dumps(jsonAttest),
                                      headers=self.headers_json, verify=False)
                if respo.status_code == 200:
                    end = getTime()
                    logger.info('Performance: Attestation: %s ms' %
                                (end-start))
                    start = getTime()
                    logger.info('Get report from %s' % host.hostName)
                    url = ("https://"+verifier_cit +
                           ":8443/mtwilson/v2/host-attestations?nameEqualTo=" +
                           host.hostName)
                    report = requests.get(url,
                                          headers=self.headers_xml,
                                          auth=HTTPBasicAuth(
                                            'admin',
                                            'u1iGYAz3DSI9csf73qg2zA'),
                                          verify=False)
                    if report.status_code == 200:
                        parsingCIT = ParsingCIT()
                        parsingCIT.get_saml(report.content, info_att_cit)
                        rep_parser = XML_CIT_ReportParser(report.content)
                        rep_parser.createReport()
                        InformationDigest.host = host.hostName
                        end = getTime()
                        logger.info('Performance: Report and Parsing: %s ms' %
                                    (end-start))
                        start = getTime()
                        # Call the verify method from the ra_verifier.py
                        ra_verifier = RaVerifier()
                        infoDigest = InformationDigest()
                        result = ra_verifier.verifier(host.distribution,
                                                      host.analysisType,
                                                      infoDigest,
                                                      checked_containers=False,
                                                      report_id=0)
                        end = getTime()
                        logger.info('Performance: Ra_verifier: %s ms' %
                                    (end-start))
                        if result and info_att_cit.getTrust():
                            trust_level = 'trusted'
                        else:
                            trust_level = 'untrusted'
                        info_att_cit.changeLvlTrust(trust_level)
                        response = self.createSingleJson(host=host,
                                                         trust_lvl=trust_level)
                        try:
                            del MapDigest.mapDigest[host.hostName]
                        except KeyError as ke:
                            logger.warning('Node %s no in map' % host.hostName)
                        InformationDigest.host = ''
                    else:
                        jsonError = {'Error':
                                     'Impossible to contact with node:'
                                     + host.hostName}
                        logger.error(jsonError)
                        return Response(jsonError, status=respo.status_code)
                else:
                    jsonError = {'Error':
                                 'Impossible to contact with node:'
                                 + host.hostName}
                    logger.error(jsonError)
                    return Response(jsonError, status=respo.status_code)
                list_attest.append(response)
            except ConnectionError as connErr:
                error = {'Error impossible to contact': url}
                logger.error('Error: ' + str(error))
                return Response(error,
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as ex:
                error = {'Error': ex.message}
                logger.error(error)
                return Response(error,
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return list_attest

    def createSingleJson(self, host, trust_lvl):
        createJson = defineJsonCIT.createJson(host=host,
                                              mapDigest=MapDigest.mapDigest,
                                              trust_lvl=trust_lvl)
        return createJson

    # See if Attestation Server (OpenCIT) is alive
    def getStatus(self, message):
        logger.info('Get Status of Driver OpenCIT')

        if not verifier_cit:
            logger.info('The CIT driver is not configured')
            message.append({'Driver CIT configured': False})
            return message
        else:
            message.append({'Driver CIT configured': True})

        try:
            url = 'https://'+verifier_cit+':8443/mtwilson-portal'
            logger.debug('Try to contact OpenCIT on %s' % url)
            resp = requests.get(url, verify=False, timeout=5)
            logger.debug('Status = ' + str(resp.status_code))
            message_cit = {'Driver OpenCIT works': True}
            logger.info(message_cit)
            message.append(message_cit)
        except Exception as e:
            error_oat = {'Driver OpenCIT works': False}
            logger.error('Error impossible to contact OpenCIT %s' % e)
            message.append(error_oat)
        return message


class InformationAttestation():
    def __init__(self):
        self.trust_lvl = 'trusted'
        self.vtime = ''
        self.trust_lvl_global = 'trusted'

    def changeTime(self, time):
        self.vtime = time

    def changeLvlTrust(self, trust):
        if trust == 'false':
            self.trust_lvl = 'untrusted'
        else:
            self.trust_lvl = 'trusted'
        if self.trust_lvl_global == 'trusted':
            if trust == 'false' or trust == 'untrusted':
                self.trust_lvl_global = 'untrusted'
            else:
                self.trust_lvl_global = 'trusted'

    def getTime(self):
        return self.vtime

    def getTrust(self):
        return self.trust_lvl

    def getTrustGlobal(self):
        return self.trust_lvl_global
