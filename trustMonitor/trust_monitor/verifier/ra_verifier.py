#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ra_verifier.py: execute the integrity analyses
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
import gc
import os
import sys
import getopt
import string
import traceback
from connection import *
import pycassa
from graph import *
from structs import *
from statistics import *
from aggregation import *
from action import *
from analysis import *
import networkx as nx
from django.conf import settings
from informationDigest import InformationDigest
import logging

# use logging system of django.
logger = logging.getLogger('perform_attestation')

# if graph type is 'auto', RA Verifier determines the best choice depending
# on available information from IMA measurements list
graph_types = ['auto', 'digests', 'lsm', 'lsm+inode', 'lsm+selinux']


class RaVerifier():

    def __del__(self):
        logger.debug('delete RaVerifier and clean structures')
        del Digest.digests_dict
        del Digest.digests_query_done
        del Digest.packages_query_done
        del Digest.packages_query
        del Package.pkg_dict
        del Subject.subj_label_dict
        del Object.obj_label_dict

    def __init__(self):
        logger.info('Set structures')
        Analysis.analysis_list = []

    def verifier(self, distro, analysis, infoDigest,
                 checked_containers, report_id, known_digests, port, ip):
        logger.info('In verifier method of RaVerifier.')
        cassandraHost = (ip + ':' + port)
        logger.info('Define the Cassandra host: %s', cassandraHost)
        graph_type = 'auto'
        keyspace = 'PackagesDB'
        selinux = False
        selinux_policy_path = None
        results_dir = '.'

        graph = nx.DiGraph()
        try:
            logger.debug('verify conncection cassandra')
            conn = DBConnection(keyspace, [cassandraHost])
        except pycassa.pool.AllServersUnavailable as e:
            logger.error('error connection cassandra %s', e)
            return 2
        lsm_fields = ['subj', 'obj', 'bprm-subj']
        lsm_inode_fields = lsm_fields + ['lw']

        if 'check-cert' in analysis:
            logger.info('Analysis is check-cert')
            for item in analysis.split(','):
                if item.startswith('cert_digest'):
                    add_known_digest(item.split('=')[1])
                    break
        logger.info('Define the type of graph')
        if graph_type == 'auto':
            if IMARecord.default_template() in ['ima', 'ima-ng',
                                                'ima-cont-id']:
                graph_type = 'digests'
            elif IMARecord.default_template_contains_fields(lsm_inode_fields):
                graph_type = 'lsm+inode'
            elif IMARecord.default_template_contains_fields(lsm_fields):
                graph_type = 'lsm'
        logger.info('The type of graph is %s', str(graph_type))
        if graph_type == 'auto':
            logger.error('Graph type cannot be determined, exiting.')
            return 2

        if graph_type == 'digests':
            logger.info('Define query to cassandra for graph_type %s',
                        str(graph_type))
            FileTypeAggregation(conn, distro, graph, known_digests)
            DBLibrariesAction(conn, distro, graph, known_digests)
            logger.info('Aggregation and DBLibrariesAction are done')
            # no distinction is possible between code and data
        elif graph_type == 'lsm':
            LSMLabelAggregation(conn, distro, graph)
            LSMLabelLoadAction(conn, distro, graph)

            LSMLabelAggregationRunTime(conn, distro, graph)
            LSMLabelFlowAction(conn, distro, graph)
        elif graph_type == 'lsm+inode':
            LSMLabelInodeAggregation(conn, distro, graph)
            LSMLabelLoadAction(conn, distro, graph)
            LSMLabelInodeFlowAction(conn, distro, graph)
        elif graph_type == 'lsm+selinux':
            LSMLabelAggregation(conn, distro, graph)
            LSMLabelSELinuxAction(conn, distro, graph, selinux_policy_path)

        Statistics.set_elapsed_time('time_build_graph')

        global_result = True
        analysis_name = analysis.split(',')[0]
        analysis_params = analysis[len(analysis_name) + 1:]
        load_time_requirement = []
        load_time_topic = 'code'
        load_time_prop_only = True
        draw_graph = False
        priv_processes_check = True
        target = ''
        tcb = []
        priv_processes = []
        cert_digest = None

        if analysis_name not in ['load-time', 'run-time', 'load-time+run-time',
                                 'check-cert', 'load-time+check-cert',
                                 'load-time+cont-check']:
            logger.error('Unknown analysis %s' % analysis_name)
            return 2

        for item in analysis_params.split(','):
            offset = len(item.split('=')[0]) + 1
            if item.startswith('tcb='):
                tcb = item[offset:].split('|')
            elif item.startswith('target='):
                target = item[offset:]
            elif item.startswith('draw_graph='):
                draw_graph = eval(item[offset:])
            elif item.startswith('priv_check='):
                priv_processes_check = eval(item[offset:])
            elif item.startswith('l_req='):
                load_time_requirement = item[offset:].split('|')
            elif item.startswith('l_topic='):
                load_time_topic = item[offset:]
            elif item.startswith('l_prop_only='):
                load_time_prop_only = eval(item[offset:])
            elif item.startswith('cert_digest='):
                cert_digest = item[offset:]
            elif item.startswith('cont-list='):
                checked_containers = item[offset:]
            else:
                logger.error('Unknown parameter %s' % item)
                return 2
    #   TCB for graph built with LSM labels and last write information
        tcb_init_t_inode = ['sendmail_t', 'initrc_t', 'chronyd_t', 'udev_t',
                            'systemd_tmpfiles_t', 'getty_t',
                            'NetworkManager_t']

    #   TCB for graph build with LSM labels only and open events
        tcb_init_t_lsm = tcb_init_t_inode + ['crond_t', 'system_dbusd_t']

    #   TCB for graph build with LSM labels from execution events and
    #   interactions inferred from the SELinux policy
        tcb_init_t_selinux = tcb_init_t_lsm + ['insmod_t', 'fsadm_t',
                                               'kernel_t', 'mount_t',
                                               'setfiles_t',
                                               'iptables_t', 'netutils_t',
                                               'chkpwd_t', 'ifconfig_t',
                                               'auditctl_t', 'audisp_t',
                                               'policykit_t']

        for item in tcb:
            if 'demo_inode' in tcb:
                tcb.remove('demo_inode')
                tcb += tcb_init_t_inode
            elif 'demo_lsm'in tcb:
                tcb.remove('demo_lsm')
                tcb += tcb_init_t_lsm
            elif 'demo_selinux' in tcb:
                tcb.remove('demo_selinux')
                tcb += tcb_init_t_selinux
            elif 'predecessors' in tcb:
                tcb.remove('predecessors')
                if len(target) == 0:
                    logger.error('Missing target parameter')
                    return 2
                try:
                    a = ProcTransAnalysis(conn, distro, graph, target=target)
                    tcb += list(a.get_predecessors(target))
                    if draw_graph:
                        a.view_graph()
                except Exception as e:
                    logger.error(e)
                    return 2
        # Perform the ProcWrite analysis to see if some processed changed their
        # context or that of the next execve(). If one or more processes are
        # found different actions are done depending on the analyses to be
        # executed.
        # For the load-time analysis, perform the propagation with topic
        # code+data
        # (the configuration files affect the context written to /proc).
        # For the run-time analysis, processes are added to the chosen tcb to
        # detect whether an untrusted process tried to compromise their
        # integrity.
        # Further, if a requirement has been provided for the load-time
        # analysis, this is concatenated with a new requirement on privileged
        # processes:their severity level must be 'ok' because otherwise it
        # would be not possible to correctly associate the code executed and
        # configuration files read to subject labels (privileged processes can
        # take an arbitrary context).
        if priv_processes_check and graph_type != 'digests':
            a = ProcWriteAnalysis()
            priv_processes = a.get_subj_list()
            if ((len(target) > 0 or len(tcb) > 0) and
                    target not in priv_processes
                    and len(set(tcb) & set(priv_processes)) == 0):
                tcb.extend(priv_processes)

        error_message = {}
        if 'load-time' in analysis_name:
            logger.info('Analysis is load-time')
            try:
                a = LoadTimeAnalysis(conn, distro, graph,
                                     target=target, tcb=tcb,
                                     results_dir=results_dir,
                                     report_id=report_id,
                                     informationDigest=infoDigest,
                                     known_digests=known_digests)
                a.propagate_errors(load_time_topic)
                if len(priv_processes) > 0 and 'data' not in load_time_topic:
                    a.propagate_errors('data', priv_processes)

            except Exception as e:
                logger.error(e)
                return 2

            if len(load_time_requirement) > 0:
                logger.debug('analysis: %s ', load_time_requirement)
                global_result &= a.satisfies_requirement(load_time_requirement,
                                                         error_message)
                logger.info(
                    'The value of global_result after satisfies_requirement of'
                    ' analysis process is %s', global_result)
                if len(priv_processes) > 0:
                    global_result &= a.satisfies_requirement_priv(
                        priv_processes, error_message)
                    logger.info(
                        'The value of global result after'
                        ' satisfies_requirement_priv is %s', global_result)
            if draw_graph:
                a.view_graph(only_prop_true=load_time_prop_only)

            Statistics.set_elapsed_time('time_load_time_analysis')

        if 'run-time' in analysis_name:
            logger.info('Analysis type is run-time')
            if IMARecord.default_template() in ['ima', 'ima-ng']:
                logger.error('Run-time analysis is not supported for'
                             ' template%s', IMARecord.default_template())
                return 2

            if len(tcb) == 0 and len(target) == 0:
                logger.error(
                    'Missing parameters (tcb, target) for run-time analysis')
                return 2

            try:
                a = RunTimeAnalysis(conn, distro, graph, target=target,
                                    tcb=tcb, results_dir=results_dir,
                                    report_id=report_id)
            except Exception as e:
                logger.error(e)
                return 2

            global_result &= a.satisfies_requirement(error_message)

            if draw_graph:
                a.view_graph()

            Statistics.set_elapsed_time('time_run_time_analysis')
        if 'check-cert' in analysis_name:
            logger.info('Analysis type is check-cert')
            result = cert_digest in Digest.digests_dict.keys()
            if not result:
                error_message['cert'] = ['not found']
            global_result &= result

        Statistics.set_current_time('time_total')
        logger.info(
            'The global result of attestation is: %s' %
            ('trusted' if global_result else 'untrusted'))
        global_result_list = [global_result, infoDigest]
        return global_result_list
