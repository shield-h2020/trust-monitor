#!/usr/bin/env python
# -*- coding: utf-8 -*-

# util.py: some useful functions
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

from collections import deque


def merge_dict(dest_dict, source_dict):
    try:
        keys = source_dict.keys()
        childdictkeys = source_dict[keys[0]].keys()
        for key in keys:
            try:
                merge_dict(dest_dict[key], source_dict[key])
            except Exception:
                dest_dict[key] = source_dict[key]
    except Exception:
        dest_dict.update(source_dict)


def propagation_rule(status, propagation):
    propagation_map = {}
    propagation_map['ok'] = 0
    propagation_map['newpackage'] = 0
    propagation_map['testing'] = 0
    propagation_map['release'] = 0
    propagation_map['name-mismatch'] = 1
    propagation_map['enhancement'] = 2
    propagation_map['updates'] = 2
    propagation_map['bugfix'] = 3
    propagation_map['security'] = 4
    propagation_map['unknown'] = 4
    propagation_map['not-found'] = 10
    propagation_map['fake-lib'] = 10
    propagation_map['undefined'] = -1
    propagation_map['error'] = -1
    return propagation_map[status] < propagation_map[propagation]


def edge_list_tags(graph, source, target):
    return [tag[9:] for tag in graph[source][target]
            if tag.startswith('edge_tag_')]


def edge_match_tags(graph, source, target, tags):
    return tags is None or \
        len(set(edge_list_tags(graph, source, target)) & set(tags)) > 0


def bfs(g, source, edge_list=None, prop_set=False, only_prop_true=False):
    queue = deque([(None, source)])
    while queue:
        parent, n = queue.popleft()
        yield parent, n
        new = set(g[n])
        queue.extend(
            [(n, child) for child in new
             if edge_match_tags(g, n, child, edge_list)
             and (not prop_set or ('propagation' in g[n][child] and (
                not only_prop_true or g[n][child]['propagation'] is True)))])


def selinux_type(label):
    label_split = label.split(':')
    if len(label_split) < 4:
        return label

    return label_split[2]
