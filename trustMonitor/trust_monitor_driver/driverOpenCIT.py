import json
import requests
from requests.exceptions import ConnectionError
from django.core.exceptions import ObjectDoesNotExist
import logging
from django.conf import settings
from requests.auth import HTTPBasicAuth
from trust_monitor_driver.informationDigest import InformationDigest, MapDigest
from trust_monitor.verifier.ra_verifier import RaVerifier
from driverCITSettings import *
import xmltodict
import untangle
from trust_monitor.models import Host
from trust_monitor.verifier.structs import IMARecord
from trust_monitor.attestation_data import (
    HostAttestation, HostAttestationExtraInfo)
from trust_monitor_driver.driverConstants import *


requests.packages.urllib3.disable_warnings()

logger = logging.getLogger('django')


class DriverCIT():

    headers_json = {'content-type': 'application/json'}
    headers_xml = {'accept': 'application/xml'}

    # Register OpenCIT node
    def registerNode(self, host):
        logger.info('In registerNode method of driverCIT')
        # TODO: implement method
        pass

    # Attest OpenCIT node
    def pollHost(self, node):
        logger.info('In pollHost method in driverOpenCIT')
        host = Host.objects.get(hostName=node['node'])
        url = (
            'https://' + CIT_LOCATION + ':8443/mtwilson/v2/host-attestations')
        logger.info('Analyse node: ' + host.hostName)
        try:
            # First, query the AS to attest the host
            jsonAttest = {'host_uuid': host.uuid_host}
            logger.debug('Define json object to be sent to OpenCIT '
                         'to perform attestation')
            respo = requests.post(
                url,
                auth=HTTPBasicAuth(
                    CIT_API_LOGIN,
                    CIT_API_PASSWORD),
                data=json.dumps(jsonAttest),
                headers=self.headers_json, verify=False)
            logger.info('Get report from %s' % host.hostName)

            # Then, retrieve the AS report
            url = (
                "https://" + CIT_LOCATION +
                ":8443/mtwilson/v2/host-attestations?nameEqualTo=" +
                host.hostName)
            report = requests.get(
                url,
                headers=self.headers_xml,
                auth=HTTPBasicAuth(
                    CIT_API_LOGIN,
                    CIT_API_PASSWORD),
                verify=False)

            # Then, parse the report and extract data (time, trust)
            data = xmltodict.parse(report.content)
            saml = []
            try:
                saml = (data['host_attestation_collection']
                        ['host_attestations']['host_attestation'][0]['saml'])
            except Exception as ex:
                saml = (data['host_attestation_collection']
                        ['host_attestations']['host_attestation']['saml'])
            samlobj = untangle.parse(saml)

            # Extract trust information
            trust = (
                    samlobj
                    .saml2_Assertion
                    .saml2_AttributeStatement
                    .saml2_Attribute[2]
                    .saml2_AttributeValue
                    .cdata)

            # Create IMARecord for IMA verification
            rep_parser = XML_CIT_ReportParser(report.content)
            rep_parser.createReport()
            InformationDigest.host = host.hostName

            # Call the verify method from the ra_verifier.py script
            ra_verifier = RaVerifier()
            info_digest = InformationDigest()

            known_digests = " ".join(
                item for item in InstantiateDigest.known_digests)

            result = ra_verifier.verifier(
                host.distribution,
                host.analysisType,
                info_digest,
                checked_containers=False,
                report_id=0,
                known_digests=known_digests,
                port=settings.CASSANDRA_PORT,
                ip=settings.CASSANDRA_LOCATION)

            # If IMA verification fails, attestation is false
            if not result:
                trust = False

            # Parse the IMA verification output (in info_digest)
            MapDigest.mapDigest[host.hostName] = info_digest

            listNotFound = (
                [] if len(info_digest.list_not_found) == 0
                else info_digest.list_not_found)
            listFakeLib = (
                [] if len(info_digest.list_fake_lib) == 0
                else info_digest.list_fake_lib)

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

            del info_digest

            # Create (and return) the final HostAttestation object
            host_attestation = HostAttestation(
                host.hostName,
                trust,
                0,
                extra_info,
                "Not supported",
                CIT_DRIVER
            )
            try:
                del MapDigest.mapDigest[host.hostName]
            except KeyError as ke:
                logger.warning('Node %s no in map' % host.hostName)

            InformationDigest.host = ''

            return host_attestation

        except Exception as e:
            logger.error(
                'Exception occurred while attesting CIT host: ' +
                str(e))
            return None

    # See if Attestation Server (OpenCIT) is alive
    def getStatus(self):
        logger.info('Get Status of Driver OpenCIT')
        configured = False
        active = False
        if not CIT_LOCATION:
            logger.info('The CIT driver is not configured')
            configured = False
        else:
            configured = True

        try:
            url = 'https://'+CIT_LOCATION+':8443/mtwilson-portal'
            logger.debug('Try to contact OpenCIT on %s' % url)
            resp = requests.get(url, verify=False, timeout=5)
            logger.debug('Status = ' + str(resp.status_code))
            active = True
        except Exception as e:
            logger.error('Error impossible to contact OpenCIT %s' % str(e))
            active = False
        return {CIT_DRIVER: {'configuration': configured, 'active': active}}


class XML_CIT_ReportParser(object):

    def createReport(self):
        try:
            ima_xml = []
            data = xmltodict.parse(self.report)
            try:
                ima_xml = (data['host_attestation_collection']
                           ['host_attestations']['host_attestation'][0]
                           ['trustReport']['hostReport']['pcrManifest']
                           ['imaMeasurementXml'])
            except Exception:
                ima_xml = (data['host_attestation_collection']
                           ['host_attestations']
                           ['host_attestation']['trustReport']['hostReport']
                           ['pcrManifest']['imaMeasurementXml'])

            ima_obj = untangle.parse(ima_xml)
        except Exception as ex:
            raise Exception(ex.message)
        for measure in ima_obj.IMA_Measurements.File:
            pcr = "10"
            template_digest = "null"
            template_name = "ima-ng"
            template_desc = "ima-ng"
            event_digest = measure.cdata
            event_name = measure['Path']
            id_docker = "host"
            template_data = ("sha1:" + event_digest + " " + event_name +
                             " " + id_docker)
            # sha1:event_digest event_name id_docker
            file_line = (pcr + " " + template_digest + " " +
                         template_name + " " + template_data)

            IMARecord(file_line)
        # for child in root:
        #    print child.tag, child.attrib

    def __init__(self, report_xml):
        self.report = report_xml
        logger.info('Get report')
