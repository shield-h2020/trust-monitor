#!/usr/bin/env python
# -*- coding: utf-8 -*-

# aggregation.py: create graph nodes
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

import os
from util import *
from statistics import *
from structs import *


class Aggregation(object):
    def __init__(self, method):
        return


class FileTypeAggregation(Aggregation):
    def __init__(self, conn, distro, graph, known_digests):
        Digest.execute_digests_query(conn, distro, known_digests)

        for digest_obj in Digest.digests_dict.values():
            # set of instances which a digest is linked to
            items = set()
            if digest_obj.event_type == 'lib':
                # lib_aliases contains also the name of the regular file
                for key in digest_obj.lib_aliases:
                    items.add(Object.get(key))
            elif digest_obj.event_type == 'exec':
                items.add(Subject.get(digest_obj.fullpath, False))

            for item in items:
                if not hasattr(item, 'digests'):
                    item.digests = set()

                item.digests.add(digest_obj)


class LSMLabelAggregation(Aggregation):
    def imarecord_set_subj(self, imarecord):
        if hasattr(imarecord, 'subj'):
            return

        hook = int(imarecord.get_data(HOOK_ID_FIELD))
        if ima_hooks[hook] == 'BPRM_CHECK':
            label = imarecord.get_data(TARGET_SUBJ_CTX_FIELD)
        else:
            label = imarecord.get_data(SUBJ_CTX_FIELD)

        imarecord.subj = Subject.get(label)

    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            r.obj = Object.get('%s-#%d' % (r.get_data(OBJ_CTX_FIELD), r.rank))
            self.imarecord_set_subj(r)


class LSMLabelAggregationRunTime(LSMLabelAggregation):
    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            r.obj = Object.get(r.get_data(OBJ_CTX_FIELD))
            self.imarecord_set_subj(r)


class LSMLabelInodeAggregation(LSMLabelAggregation):
    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            self.imarecord_set_subj(r)
            flows_new = False
            fake_subj = None
            last_r = None

            hook = int(r.get_data(HOOK_ID_FIELD))
            mask = int(r.get_data(HOOK_MASK_FIELD))
            lastwrite = int(r.get_data(LASTWRITE_FIELD))

            Statistics.inc_stat('n_tot_meas')
            if lastwrite == 0:
                flows_new = True
            else:
                # boot_aggregate record is not in the list
                last_r = IMARecord.records[lastwrite - 2]

                if ima_hooks[hook] == 'FILE_CHECK' and mask & MAY_WRITE:
                    last_hook = int(last_r.get_data(HOOK_ID_FIELD))
                    last_mask = int(last_r.get_data(HOOK_MASK_FIELD))
                    last_digest = last_r.entry['event_digest']
                    last_lastwrite = int(last_r.get_data(LASTWRITE_FIELD))

                    tomtou_violation = (
                        last_hook == 'RDWR_VIOLATION_CHECK' and
                        last_digest in
                        [DIGEST_VIOLATION, DIGEST_VIOLATION_FLOW_TOMTOU])

                    if not tomtou_violation:
                        flows_new = True
                    elif last_lastwrite == 0:
                        if last_mask != mask:
                            raise Exception('Record mask != Violation mask')
                        fake_subj = Subject.get(str(r.rank), fake=True)

            if flows_new:
                r.flows_new_record = r
                if last_r is None:
                    r.last_flows_new_record = r
                else:
                    r.last_flows_new_record = last_r.flows_new_record
                r.obj = Object.get(
                    '%s-#%d' %
                    (r.get_data(OBJ_CTX_FIELD), r.rank))
            else:
                r.flows_new_record = last_r.flows_new_record
                r.obj = last_r.obj

            if fake_subj:
                graph.add_edge(fake_subj, r.obj, edge_tag_flow=True)
