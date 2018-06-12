from structs import *
from statistics import *
from suds.client import Client
from parser import IRParser, IMAMeasureHandler
from parser import ContainerCheckAnalysis
import logging

# use logging system of django.
logger = logging.getLogger('django')


def parsing(analysis, checked_containers,
            report_url, report_id, infoDigest):
    Statistics.start_timer()
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
    except Exception as e:
        logger.error('Error opening IR, %s', e)
        return 2
    Statistics.set_elapsed_time('time_parse_ima_list')
    return 0
