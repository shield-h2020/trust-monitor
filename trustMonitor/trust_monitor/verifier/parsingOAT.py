from structs import *
from statistics import *
from suds.client import Client
from parser import IRParser, IMAMeasureHandler
from parser import ContainerCheckAnalysis
import logging
import gc
import xmltodict
import ssl
# use logging system of django.
logger = logging.getLogger('perform_attestation')


class ParsingOAT():

    def __init__(self):
        logger.info('Parsing OAT Set structures')
        Digest.digests_dict = {}
        Digest.digests_query_done = False
        Digest.packages_query_done = False
        Digest.packages_query = set()
        Package.pkg_dict = {}
        IMARecord.records = []
        Subject.subj_label_dict = {}
        Object.obj_label_dict = {}
        ssl._create_default_https_context = ssl._create_unverified_context

    def parsing(self, analysis, checked_containers,
                report_url, report_id, infoDigest):
        doCheckContAnalysis = False
        containers = {}
        if 'cont-check' in analysis:
            doCheckContAnalysis = True
            logger.info('Understand what kind of analysis to do')
            for item in analysis.split(','):
                if item.startswith('cont-list'):
                    logger.info('Analysis include containters')
                    checked_containers = item.split('=')[1]
                    break
        try:
            if report_url is not None and report_id != 0:
                client = Client(report_url)
                logger.info('report url ' + str(report_url))
                logger.info('report id ' + str(report_id))
                report_str = client.service.fetchReport(report_id)
            logger.info('Start to parser IR %s', str(report_id))
            IRParser(report_str, ContainerCheckAnalysis(doCheckContAnalysis,
                                                        containers,
                                                        checked_containers,
                                                        infoDigest))
            logger.info('Parsing of IR done.')
            try:
                data_xml = xmltodict.parse(report_str)
                host_name = (data_xml['ns3:Report']['ns3:QuoteData']
                             ['ns3:TpmSignature']['ns3:KeyInfo']['KeyName'])
            except Exception:
                host_name = (data_xml['ns3:Report']['ns3:QuoteData']
                             ['ns3:TpmSignature']['ns3:KeyInfo']
                             ['ns2:KeyName'])
            logger.info(host_name)
            infoDigest.host = host_name
            gc.collect()
        except Exception as e:
            logger.error('Error opening IR, %s', e)
            del report_str
            gc.collect()
            return 2
        return 0
