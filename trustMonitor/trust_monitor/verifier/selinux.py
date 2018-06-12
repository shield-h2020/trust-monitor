#!/usr/bin/env python
# -*- coding: utf-8 -*-

# selinux.py: query a SELinux policy
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

from subprocess import *
import os

SELINUX_POLICY_VERSION = 29
SELINUX_POLICY_PATH_DEFAULT = ('/etc/selinux/targeted/policy/policy.' +
                               str(SELINUX_POLICY_VERSION))
selinux_class_list = ['file']
tcb_subjects = []


class SELinux(object):

    def parse_rule(self, rule=None):
        rule_is_cond = False
        r = rule.split()
        if len(r) == 0:
            return None

        if r[0] == 'ET' or r[0] == 'DT':
            if r[0] == 'DT':
                return None
            del r[0]
            rule_is_cond = True

        if r[0] == 'allow':
            perm_list = []
            for perm in r[5:]:
                if perm == '{':
                    continue
                elif perm == '}':
                    break
                else:
                    perm_list.append(perm)
                    if perm == r[5]:
                        break

            cond_list = []
            if rule_is_cond is True:
                cond_list = rule[rule.index('[') + 1:rule.index(']')].strip()

            parsed_rule = dict(type=r[0], scontext=r[1], tcontext=r[2],
                               permlist=perm_list, condlist=cond_list)
            parsed_rule['class'] = r[4]
        elif r[0] == 'type_transition':
            new_context = r[5]
            if new_context.endswith(';'):
                new_context = new_context[:-1]

            parsed_rule = dict(type=r[0], scontext=r[1], tcontext=r[2],
                               newcontext=new_context)
            parsed_rule['class'] = r[4]
            if len(r) == 7:
                new_filename = r[6][:-1]
                parsed_rule['newfilename'] = new_filename
        else:
            return None

        return parsed_rule

    def type_list(self, type=None):
        try:
            return self.types[type]
        except Exception:
            return [type]

    def __init__(self, policy_path=None, use_conditionals=True,
                 active_processes=[]):
        self.policy_path = SELINUX_POLICY_PATH_DEFAULT
        if policy_path is not None:
            self.policy_path = policy_path
        self.attributes = {}
        self.types = {}

        self.reads = {}
        self.writes = {}

        # build mapping attribute -> types
        p = Popen(['seinfo', '-a', '-x', self.policy_path],
                  stdout=PIPE, stderr=PIPE).communicate()[0].splitlines()
        for l in p[1:]:
            r = l.split(' ')
            if len(r) == 4:
                attribute = r[3]
                self.types[attribute] = []
                continue
            elif len(r) == 7:
                self.types[attribute].append(r[6])

        # build mapping type -> attributes
        p = Popen(['seinfo', '-t', '-x', self.policy_path],
                  stdout=PIPE, stderr=PIPE).communicate()[0].splitlines()
        for l in p[1:]:
            r = l.split(' ')
            if len(r) == 4:
                type = r[3]
                self.attributes[type] = []
                continue
            elif len(r) == 7:
                self.attributes[type].append(r[6])

        conditional_opt = ''
        if use_conditionals is True:
            conditional_opt = 'C'

        # parse all 'allow' rules for 'file' class
        sesearch_args = ['sesearch', '-SA' + conditional_opt, '-c', 'file',
                         '-p', 'read,write', self.policy_path]
        result = Popen(sesearch_args, stdout=PIPE,
                       stderr=PIPE).communicate()[0].splitlines()

        for rule in result:
            parsed_rule = self.parse_rule(rule)
            if parsed_rule is None:
                continue
            for subj in self.type_list(parsed_rule['scontext']):
                if subj not in active_processes:
                    continue
                if 'read' in parsed_rule['permlist']:
                    if subj not in self.writes:
                        self.reads[subj] = set()
                    objs_read = self.type_list(parsed_rule['tcontext'])
                    self.reads[subj].update(objs_read)
                if 'write' in parsed_rule['permlist']:
                    if subj not in self.writes:
                        self.writes[subj] = set()
                    objs_written = self.type_list(parsed_rule['tcontext'])
                    self.writes[subj].update(objs_written)
