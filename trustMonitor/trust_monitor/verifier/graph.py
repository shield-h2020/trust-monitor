#!/usr/bin/env python
# -*- coding: utf-8 -*-

# graph.py: create and draw a graph
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

from structs import *
import pygraphviz as pgv


node_draw_settings = {
    Digest: {'shape': 'diamond', 'node_size': 150, 'linewidth': 1},
    Package: {'shape': 'pentagon', 'node_size': 200, 'linewidth': 1},
    Subject: {'shape': 'circle', 'node_size': 250, 'linewidth': 2},
    Object: {'shape': 'square', 'node_size': 250, 'linewidth': 2}
}


node_color = {
    'default': {'ok': 'green',
                'newpackage': 'green',
                'enhancement': 'pink',
                'bugfix': 'orange',
                'security': 'red',
                'unknown': 'violet',
                'not-found': 'blue',
                'fake-lib': 'cyan',
                'error': 'gray',
                'undefined': 'marron'},
    'grayscale': {'ok': '#cccccc',
                  'newpackage': '#cccccc',
                  'enhancement': '#666666',
                  'bugfix': '#666666',
                  'security': '#666666',
                  'unknown': '#666666',
                  'not-found': '#666666',
                  'fake-lib': '#666666',
                  'error': '#666666',
                  'undefined': 'white'}
}


edge_draw_settings = {
    'pkg': {'width': 2, 'style': 'dashed', 'color': 'yes'},
    'digest': {'width': 2, 'style': 'dashed', 'color': 'yes'},
    'exec': {'width': 2, 'style': 'dotted', 'color': 'yes'},
    'data_read': {'width': 2, 'style': 'dashed', 'color': 'yes'},
    'flow': {'width': 2, 'style': 'filled', 'color': 'no'},
    'proc_trans': {'width': 3, 'style': 'dashed', 'color': 'no'},
}


class AGraph(object):
    def __init__(self, graph):
        self.G = graph

    def draw(self, outfile=None, show_labels=False, color_mode='default',
             edge_types=None, only_propagation=False, graph_edges=None,
             clusters=[], prog='fdp'):
        self.A = pgv.AGraph(directed=True)
        self.A.graph_attr['splines'] = 'line'
        self.A.node_attr['fixedsize'] = 'true'
        self.A.graph_attr['concentrate'] = 'true'
        self.A.graph_attr['overlap'] = '30:true'
        self.A.graph_attr['K'] = 1.7
        self.A.graph_attr['sep'] = '+15,5'
        self.A.graph_attr['strict'] = 'false'
        self.A.graph_attr['fontsize'] = 30
        self.A.node_attr['fontsize'] = 22
        self.A.edge_attr['arrowsize'] = 1.9
        self.A.graph_attr['pad'] = 1.5
        self.A.graph_attr['rankdir'] = 'BT'
        self.A.graph_attr['nodesep'] = 1.2
        self.A.graph_attr['ranksep'] = 1.4
        self.A.graph_attr['ratio'] = 0.8

        nodes_list = set()
        edges_list = set()

        if graph_edges is None:
            graph_edges = self.G.edges()

        for (u, v) in graph_edges:
            if not edge_match_tags(self.G, u, v, edge_types):
                continue

            if only_propagation is True and 'prop_path' not in self.G[u][v]:
                continue

            if u.__class__ == GenericNode or v.__class__ == GenericNode:
                continue

            nodes_list.update([u, v])
            edges_list.add((u, v))

        # always display Target and TCB nodes
        for (nodes, name, label) in clusters:
            if label in ['TCB', 'Target']:
                nodes_list.update(nodes)

        self.A.add_nodes_from(nodes_list)
        self.A.add_edges_from(edges_list)

        for n in nodes_list:
            self.A.get_node(n).attr['shape'] = \
                node_draw_settings[n.__class__]['shape']
            self.A.get_node(n).attr['fillcolor'] = \
                node_color[color_mode][n.severity_level]
            self.A.get_node(n).attr['style'] = 'filled'
            self.A.get_node(n).attr['penwidth'] = \
                node_draw_settings[n.__class__]['linewidth'] * 1.5
            self.A.get_node(n).attr['regular'] = True
            self.A.get_node(n).attr['width'] = 0.5

            node_label = os.path.basename(n.name)
            if isinstance(n, Subject) or isinstance(n, Object):
                node_label = selinux_type(n.name[2:])
                if '-#' in n.name:
                    node_label += '-#' + n.name.split('-#')[1]

            self.A.get_node(n).attr['label'] = '<<B>%s</B><BR/><B>[%s]' \
                '</B><BR/> <BR/> <BR/> <BR/> <BR/>>' % \
                (node_label, n.severity_level)

        for e in edges_list:
            edge = self.A.get_edge(e[0], e[1])
            edge_type_list = edge_list_tags(self.G, e[0], e[1])
            if edge_types is not None:
                edge_type_list = list(set(edge_type_list) & set(edge_types))
            edge_type = edge_type_list[0]
            if edge_draw_settings[edge_type]['color'] == 'yes':
                edge.attr['color'] = (
                        node_color[color_mode][e[0].severity_level])
            edge.attr['penwidth'] = edge_draw_settings[edge_type]['width'] + 1
            edge.attr['style'] = \
                edge_draw_settings[edge_type]['style'] + ',bold'

        for (nodes, name, label) in clusters:
            if label in ['TCB', 'Target']:
                nbunch = list(nodes)
            else:
                nbunch = list(nodes & set(nodes_list))

            if len(nbunch) == 0:
                continue

            cluster_label = '<<B>%s</B><BR/><BR/> <BR/> <BR/>>' % label
            self.A.subgraph(nbunch=nbunch, name=name, label=cluster_label)

        max_retries = 10
        current_retries = 0
        while current_retries < max_retries:
            try:
                self.A.layout(prog=prog)
                self.A.draw(outfile)
                break
            except Exception:
                current_retries += 1

        if current_retries == max_retries:
            raise Exception('Graph drawing error')
