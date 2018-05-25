#!/usr/bin/env python
# -*- coding: utf-8 -*-

# parser.py: parse an integrity report
#
# Copyright (C) 2014 Politecnico di Torino, Italy
#                    TORSEC group -- http://security.polito.it
#
# Author: Roberto Sassu <roberto.sassu@polito.it>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

import base64
import struct
from structs import IMARecord
import xml.sax
import logging
from trust_monitor_driver.driverOAT import Driver

logger = logging.getLogger('django')


def parse_IMA_Image(hash_str, type_str, image_blob, containerCheckAnalysis):
    offset = 0
    type_val = ''
    # if check-cont analysis is indicated and IMA template is not ima-cont-id,
    # then it raise an exception
    if (not type_str == 'ima-cont-id' and
            containerCheckAnalysis.doCheckContAnalysis):
        raise Exception('Invalid IMA template for making cont-check analysis')

    line = '10 %s ' % (hash_str.encode('hex'))
    if type_str == 'ima':
        line += type_str + ' ' + image_blob[offset:20].encode('hex')
        offset += 20
        namelen = struct.unpack("<L", image_blob[offset:offset + 4])[0]
        line += ' ' + image_blob[offset:namelen]
    elif type_str == 'ima-ng':
        line += type_str
        type_str = 'd-ng|n-ng'
        i = 0
        while offset < len(image_blob):
            field_len = struct.unpack("<L", image_blob[offset:offset + 4])[0]
            offset += 4
            if field_len == 0:
                line += ' '
                i += 1
                continue

            field = image_blob[offset:offset + field_len]
            offset += field_len
            field_id = type_str.split('|')[i]
            if field_id == 'd-ng':
                algo = field.split('\0')[0]
                digest = field[len(algo) + 1:].encode('hex')
                line += ' ' + algo + digest
            else:
                if field_id in ['hook-id', 'hook-mask']:
                    field = struct.unpack("<L", field)[0]
                elif field_id == 'lw':
                    field = struct.unpack("<Q", field)[0]
                elif field_id in ['n-ng', 'n']:
                    field = field[:-1]
                elif field_id in ['subj', 'obj', 'bprm-subj']:
                    field = field[:-2]
                line += ' ' + str(field)
            i += 1
    elif type_str == 'ima-cont-id':
        line += 'ima-ng'
        type_str = 'dev-id|d-ng|n-ng'
        i = 0
        while offset < len(image_blob):
            field_len = struct.unpack("<L", image_blob[offset:offset + 4])[0]
            offset += 4
            if field_len == 0:
                i += 1
                continue

            field = image_blob[offset:offset + field_len]
            offset += field_len
            field_id = type_str.split('|')[i]
            if field_id == 'd-ng':
                algo = field.split('\0')[0]
                digest = field[len(algo) + 1:].encode('hex')
                line += ' ' + algo + digest
                logger.debug(digest)
            else:
                if field_id in ['hook-id', 'hook-mask']:
                    field = struct.unpack("<L", field)[0]
                elif field_id == 'lw':
                    field = struct.unpack("<Q", field)[0]
                elif field_id in ['n-ng', 'n']:
                    field = field[:-1]
                elif field_id == 'dev-id':
                    field = field[:-1]
                    if containerCheckAnalysis.doCheckContAnalysis:
                        if ('0:' not in field and field not in
                                containerCheckAnalysis.containers.keys()):
                            logger.info("Discarding measure relative"
                                        " to a stopped container")
                            return
                        check_measure = False
                        if (field.startswith('0:') or
                            containerCheckAnalysis.containers.get(field) ==
                                'host'):
                            check_measure = True
                            type_val = 'host'
                        else:
                            listS = containerCheckAnalysis.checked_containers
                            for item in listS.split('+'):
                                if (containerCheckAnalysis.containers[field] ==
                                        item):
                                    logger.info('The measure relative to '
                                                'container ' + item)
                                    check_measure = True
                                    type_val = item
                                    break
                        if not check_measure:
                            logger.info(
                                "Discarding measure relative to container %s" %
                                containerCheckAnalysis.containers.get(field))
                            return
                elif field_id in ['subj', 'obj', 'bprm-subj']:
                    field = field[:-2]
                if not field_id == 'dev-id':
                    line += ' ' + str(field)
            i += 1
    line += ' ' + type_val
    IMARecord(line)


class IMAMeasureHandler(xml.sax.ContentHandler):
    def __init__(self, containerCheckAnalysis):
        logger.info('In IMAMeasureHandler use to perform parsing')
        self.type_str = ''
        self.image_blob = ''
        self.content = ''
        self.capture = False
        self.containerId = ''
        self.hostElement = False
        self.containerCheckAnalysis = containerCheckAnalysis
        self.cont_measure = 0

    def startElement(self, name, attrs):
        if "Objects" in name:
            self.type_str = attrs.getValue('Type')
            self.image_blob = attrs.getValue('Image')
        if "ns4:Hash" in name and attrs.getValue('Id').startswith('PCR_10_'):
            self.capture = True
        if "Container" in name:
            self.containerId = attrs.getValue('Id')
        if "Host" in name:
            self.hostElement = True
        if "DevId" in name:
            self.capture = True

    def endElement(self, name):
        if "ns4:Hash" in name:
            self.capture = False
        if "Host" in name:
            self.hostElement = False
        if "DevId" in name:
            self.capture = False

    def characters(self, content):
        if not self.capture:
            return

        if self.containerId == '' and not self.hostElement:
            self.content += content
            if len(self.content) != 28:
                return
            self.cont_measure += 1
            logger.debug('Measure %s', self.cont_measure)
            line = parse_IMA_Image(base64.decodestring(self.content),
                                   self.type_str, base64.decodestring(
                self.image_blob), self.containerCheckAnalysis)
            self.content = ''
        elif self.hostElement:
            self.containerCheckAnalysis.containers[content] = 'host'
        else:
            self.containerCheckAnalysis.containers[content] = self.containerId
            self.containerId = ''
            self.content = ''


class XMLParser(object):
    def parse_report_pyxb(self, report_xml, containerCheckAnalysis):
        report = xml_parser.ir_simple_parser.CreateFromDocument(report_xml)

        ima_snap = [snap for snap in report.SnapshotCollection
                    if snap.ComponentID.Id.split('_')[1] == '10'][0]
        for v in ima_snap.Values:
            conta = conta + 1
            item = v.orderedContent()[0].value.Objects[0]
            line = parse_IMA_Image(
                item.Hash[0].value(), item.Type, item.Image,
                containerCheckAnalysis, cont)

    def __init__(self, report_xml, containerCheckAnalysis):
        xml.sax.parseString(
            report_xml, IMAMeasureHandler(containerCheckAnalysis))


class ASCIIParser(object):
    def __init__(self, report_ascii, containerCheckAnalysis):
        for file_line in report_ascii.split('\n'):
            file_line = file_line.replace('  ', ' ')
            if len(file_line) == 0:
                continue
            # if check-cont analysis is indicated and IMA template is not
            # ima-cont-id, then it raise an exception
            ima_template = file_line.split(' ')[2]
            if (containerCheckAnalysis.doCheckContAnalysis and
                    not ima_template == 'ima-cont-id'):
                raise Exception(
                    'Invalid IMA template for making cont-check analysis')

            if ima_template == 'ima-cont-id':
                # If check-cont analysis is not indicated, it directly
                # insert the IMA measure
                if (not containerCheckAnalysis.doCheckContAnalysis or
                        'boot_aggregate' in file_line):
                    if 'boot_aggregate' in file_line:
                        line = (file_line.split(' ')[0] + " " +
                                file_line.split(' ')[1] + " ima-ng " +
                                file_line.split(' ')[3] + " " +
                                file_line.split(' ')[4])
                    else:
                        line = (file_line.split(' ')[0] + " " +
                                file_line.split(' ')[1] + " ima-ng " +
                                file_line.split(' ')[4] + " " +
                                file_line.split(' ')[5])
                    IMARecord(line)
                    continue

                self.dev_id = file_line.split(' ')[3]
                self.check_measure = False
                if ('0:' not in self.dev_id and self.dev_id not in
                        containerCheckAnalysis.containers.keys()):
                    logger.info(
                        "Discarding measure relative to a stopped container")
                    continue
                if (self.dev_id.startswith('0:') or
                        containerCheckAnalysis.containers.get(self.dev_id) ==
                        'host'):
                    self.check_measure = True
                else:
                    listS2 = containerCheckAnalysis.checked_containers
                    for item in listS2.split('+'):
                        if (containerCheckAnalysis.containers[self.dev_id] ==
                                item):
                            self.check_measure = True
                            break
                if not self.check_measure:
                    logger.info("Discarding measure relative to container ",
                                containerCheckAnalysis.containers[self.dev_id])
                    continue
                else:
                    line = (file_line.split(' ')[0] + " " +
                            file_line.split(' ')[1] + " ima-ng " +
                            file_line.split(' ')[4] + " " +
                            file_line.split(' ')[5])
                    IMARecord(line)
            else:
                IMARecord(file_line)


class IRParser(object):
    def __init__(self, report_str, containerCheckAnalysis):
        if report_str.startswith('<?xml'):
            logger.info('Use XML parser to parsing IR')
            XMLParser(report_str, containerCheckAnalysis)
        else:
            logger.info('Use ASCII parser to parsing IR')
            ASCIIParser(report_str, containerCheckAnalysis)


class ContainerCheckAnalysis(object):
    def __init__(self, doCheckContAnalysis, containers, checked_containers):
        self.doCheckContAnalysis = doCheckContAnalysis
        self.containers = containers
        self.checked_containers = checked_containers
        logger.info('The list of containers %s ' % checked_containers)
        Driver.list_containers = self.checked_containers
