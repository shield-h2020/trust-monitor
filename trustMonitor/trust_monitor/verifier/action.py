#!/usr/bin/env python
# -*- coding: utf-8 -*-

# action.py: create graph edges
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

from selinux import *
from structs import *
from util import *


class Action(object):
    def __init__(self):
        return


class DBLibrariesAction(Action):
    def get_exec_libraries(self, lib_list):
        ln = set()

        for lname in lib_list:
            if len(lname) == 0:
                continue
            if (lname.startswith('linux-vdso') or
                    lname.startswith('linux-gate')):
                continue

            obj = Object.get(lname)

            # No object with this lname exists. Add a fake digest to it
            if not hasattr(obj, 'digests'):
                fake_digest = Digest.get(None, lname, True)
                fake_digest.libraries = []
                fake_digest.lib_aliases = [lname]
                fake_digest.severity_level = 'fake-lib'
                # the full path is not available, use the file name
                fake_digest.fullpath = lname
                obj.digests = set([fake_digest])

            # we have to consider all digests as for the same file name there
            # may be different libraries which may have different dependencies
            ln.update(obj.digests)

            for lib in obj.digests:
                if lib in self.libraries_deps_cache:
                    result = self.libraries_deps_cache[lib]
                else:
                    result = self.get_exec_libraries(lib.libraries)
                    self.libraries_deps_cache[lib] = result

                ln.update(result)

        return ln

    def __init__(self, conn, distro, graph, known_digests):
        self.libraries_deps_cache = {}

        Digest.execute_digests_query(conn, distro, known_digests)

        unknown_digests = [digest for digest in Digest.digests_dict.values()
                           if digest.event_type == '' and not digest.is_fake]

        for subj in Subject.subj_label_dict.values():
            # Link unknown digests to set subject severity level to not-found.
            # Without knowing what is the event type of an unknown digest,
            # it may have been executed by a process.
            # This link must be created even if all executable dependencies
            # have been recognized as these libraries may have been used by
            # other executables (it is possible to load an arbitrary library
            # for a process by using the LD_PRELOAD environment variable.
            for digest in unknown_digests:
                event_name = digest.ima_records[0].entry['event_name']
                digest.fullpath = event_name
                digest.libraries = []

                obj = Object.get(os.path.basename(event_name))
                if not hasattr(obj, 'digests'):
                    obj.digests = set()
                obj.digests.add(digest)

                graph.add_edge(digest, obj, edge_tag_digest=True)
                graph.add_edge(obj, subj, edge_tag_digest=True)

            for subj_digest in subj.digests:
                graph.add_edge(subj_digest, subj, edge_tag_digest=True)
                for library in self.get_exec_libraries(subj_digest.libraries):
                    obj = Object.get(os.path.basename(library.fullpath))
                    for obj_digest in obj.digests:
                        graph.add_edge(obj_digest, obj, edge_tag_digest=True)
                    graph.add_edge(obj, subj, edge_tag_exec=True)


# Different operations on the same digest, how they should be considered?
# We cannot have granularity of single executable as we don't know to which
#  executable a library has been mapped to.
class LSMLabelLoadAction(Action):
    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            hook = int(r.get_data(HOOK_ID_FIELD))
            mask = int(r.get_data(HOOK_MASK_FIELD))

            graph.add_edge(r.digest, r.obj, edge_tag_digest=True)
            # handle violations by connecting an unknown digest to a subject
            if (ima_hooks[hook] in ['BPRM_CHECK', 'MMAP_CHECK', 'MODULE_CHECK']
                    or (ima_hooks[hook] == 'RDWR_VIOLATION_CHECK' and
                        mask == MAY_EXEC)):
                graph.add_edge(r.obj, r.subj, edge_tag_exec=True)
            # Consider the impact only of read data (execution events are
            # considered only for the other system calls, execve and mmap).
            # Execution will be taken into account during the information flow
            # analysis.
            elif (ima_hooks[hook] in ['FILE_CHECK', 'RDWR_VIOLATION_CHECK'] and
                    mask & MAY_READ):
                graph.add_edge(r.obj, r.subj, edge_tag_data_read=True)


class LSMLabelFlowAction(Action):
    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            hook = int(r.get_data(HOOK_ID_FIELD))
            mask = int(r.get_data(HOOK_MASK_FIELD))

            if ima_hooks[hook] in ['FILE_CHECK', 'RDWR_VIOLATION_CHECK']:
                if mask & MAY_READ or mask & MAY_EXEC:
                    graph.add_edge(r.obj, r.subj, edge_tag_flow=True)
                if mask & MAY_WRITE:
                    graph.add_edge(r.subj, r.obj, edge_tag_flow=True)


class LSMLabelInodeFlowAction(Action):
    def __init__(self, conn, distro, graph):
        for r in IMARecord.records:
            hook = int(r.get_data(HOOK_ID_FIELD))
            mask = int(r.get_data(HOOK_MASK_FIELD))

            if ima_hooks[hook] in ['FILE_CHECK', 'RDWR_VIOLATION_CHECK']:
                if mask & MAY_READ or mask & MAY_EXEC:
                    graph.add_edge(r.obj, r.subj, edge_tag_flow=True)
                if mask & MAY_WRITE:
                    graph.add_edge(r.subj, r.obj, edge_tag_flow=True)

            if r.flows_new_record == r and r.last_flows_new_record != r:
                for node in graph.predecessors(r.obj):
                    if not isinstance(node, Subject):
                        continue
                    graph.add_edge(node, r.obj, edge_tag_flow=True)


class LSMLabelSELinuxAction(Action):
    def __init__(self, conn, distro, graph, selinux_policy_path):
        subjs = [s.split(':')[2] for s in Subject.subj_label_dict.keys()]
        s = SELinux(active_processes=subjs, policy_path=selinux_policy_path)
        for subj_label in s.reads:
            subj = Subject.get_by_type(subj_label)
            for obj_label in s.reads[subj_label]:
                obj = Object.get('undefined_u:undefined_r:%s:undefined_level' %
                                 obj_label)
                graph.add_edge(obj, subj, edge_tag_flow=True)

        for subj_label in s.writes:
            subj = Subject.get_by_type(subj_label)
            for obj_label in s.writes[subj_label]:
                obj = Object.get('undefined_u:undefined_r:%s:undefined_level' %
                                 obj_label)
                graph.add_edge(subj, obj, edge_tag_flow=True)
