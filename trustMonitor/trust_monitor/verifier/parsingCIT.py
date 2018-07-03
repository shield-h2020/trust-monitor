import xmltodict
import untangle
import logging
from structs import IMARecord


logger = logging.getLogger('django')


class ParsingCIT():

    def get_saml(self, response, info_att_cit):
        try:
            data = xmltodict.parse(response)
            saml = []
            try:
                saml = (data['host_attestation_collection']
                        ['host_attestations']['host_attestation'][0]['saml'])
            except Exception as ex:
                saml = (data['host_attestation_collection']
                        ['host_attestations']['host_attestation']['saml'])
            samlobj = untangle.parse(saml)
            info_att_cit.changeTime(samlobj.saml2_Assertion['IssueInstant'])
            info_att_cit.changeLvlTrust(samlobj
                                        .saml2_Assertion
                                        .saml2_AttributeStatement
                                        .saml2_Attribute[2]
                                        .saml2_AttributeValue.cdata)
        except Exception as ex:
            raise Exception(ex.message)


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
            # I have to build a string similar to ima record
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
