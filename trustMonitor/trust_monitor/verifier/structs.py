#!/usr/bin/env python
# -*- coding: utf-8 -*-

# structs.py: create data structures
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
import logging
from django.db import OperationalError

logger = logging.getLogger('verifier')

# template common fields
TEMPLATE_PCR_FIELD = 'pcr'
TEMPLATE_DIGEST_FIELD = 'template_digest'
TEMPLATE_FMT_FIELD = 'template_format'

# template fields
EVENTDIGEST_FIELD = 'd'
EVENTNAME_FIELD = 'n'
EVENTDIGEST_NG_FIELD = 'd-ng'
EVENTNAME_NG_FIELD = 'n-ng'
SIG_FIELD = 'sig'
SUBJ_CTX_FIELD = 'subj'
OBJ_CTX_FIELD = 'obj'
TARGET_SUBJ_CTX_FIELD = 'bprm-subj'
HOOK_ID_FIELD = 'hook-id'
HOOK_MASK_FIELD = 'hook-mask'
LASTACTION_FIELD = 'la'
LASTWRITE_FIELD = 'lw'


class IMATemplateDesc(object):
    def get_event_digest_sha1(self, data):
        if EVENTDIGEST_NG_FIELD in self.fields:
            d_split = (
                self.get_field_data(EVENTDIGEST_NG_FIELD, data).split(':'))
            if d_split[0] != 'sha1':
                raise Exception('Hash algorithm should be sha1, current: %s'
                                % d_split[0])
            return d_split[1]
        elif EVENTDIGEST_FIELD in self.fields:
            return self.get_field_data(EVENTDIGEST_FIELD, data)
        else:
            raise Exception('Digest field not found')

    def get_event_name(self, data):
        if EVENTNAME_NG_FIELD in self.fields:
            return self.get_field_data(EVENTNAME_NG_FIELD, data)
        elif EVENTNAME_FIELD in self.fields:
            return self.get_field_data(EVENTNAME_FIELD, data)
        else:
            raise Exception('Event name field not found')

    def get_field_data(self, field_id, data):
        idx = self.fields.index(field_id)
        return data[idx]

    def __init__(self, name, fmt):
        logger.debug('Init IMARecord')
        self.name = name
        self.fmt = fmt
        self.fields = fmt.split('|')


# template descriptors
defined_templates = [IMATemplateDesc('ima', 'd|n'),
                     IMATemplateDesc('ima-ng', 'd-ng|n-ng'),
                     IMATemplateDesc('ima-sig', 'd-ng|n-ng|sig')]

# hook id values
ima_hooks = ['', 'FILE_CHECK', 'MMAP_CHECK', 'BPRM_CHECK', 'MODULE_CHECK',
             'POST_SETATTR', 'RDWR_VIOLATION_CHECK']

# hook mask values
MAY_READ = 4
MAY_WRITE = 2
MAY_EXEC = 1


class GenericNode(object):
    def __init__(self, name='fake', severity_level='undefined'):
        self.name = name
        self.severity_level = severity_level

    def __repr__(self):
        return self.name


class IMARecord(object):
    records = []

    @classmethod
    def default_template(cls):
        # return the template name of boot_aggregate
        return cls.records[0].entry['template_name']

    @classmethod
    def default_template_contains_fields(cls, fields=[]):
        template_fields = cls.default_template().split('|')
        return len(set(fields) & set(template_fields)) == len(set(fields))

    def parse_entry(self):
        d = self.data.split(' ')

        self.entry = {}
        self.entry['pcr'] = d[0]
        self.entry['template_digest'] = d[1]
        self.entry['template_name'] = d[2]
        self.entry['id-docker'] = d[-1]
        found_templates = [desc for desc in defined_templates
                           if desc.name == self.entry['template_name']]
        if len(found_templates) > 0:
            template_desc = found_templates[0]
        else:
            template_desc = IMATemplateDesc('', self.entry['template_name'])

        self.entry['template_desc'] = template_desc
        self.entry['template_data'] = d[3:-1]
        self.entry['event_digest'] = (
            template_desc.get_event_digest_sha1(d[3:-1]))
        self.entry['event_name'] = template_desc.get_event_name(d[3:-1])

    def get_data(self, field_name):
        return self.entry['template_desc'].get_field_data(
            field_name,
            self.entry['template_data'])

    def __init__(self, data=None):
        logger.debug("Init IMARecord object")
        self.rank = len(IMARecord.records) + 2
        self.data = data.strip('\n')

        self.parse_entry()
        logger.debug("Parsed entry")

        if self.entry['event_name'] == 'boot_aggregate':
            return

        self.digest = Digest.get(self, None, False)

        logger.debug("Get digest")
        IMARecord.records.append(self)

        logger.debug("Append IMARecord")


class Digest(GenericNode):
    digests_dict = {}
    digests_query_done = False
    packages_query = set()
    packages_query_done = False

    @classmethod
    def get(cls, ima_record, event_name, fake=False):
        if fake:
            digest_key = event_name
        else:
            digest_key = ima_record.entry['event_digest']

        if digest_key in cls.digests_dict:
            digest_obj = cls.digests_dict[digest_key]
            if ima_record is not None and \
                    ima_record not in digest_obj.ima_records:
                digest_obj.ima_records.append(ima_record)
            return digest_obj

        return cls(ima_record, event_name, fake)

    @classmethod
    def execute_digests_query(cls, conn, distro, known_digests):
        if cls.digests_query_done:
            return
        # define known_digests.
        rows = list(set(cls.digests_dict.keys()) -
                    set(known_digests))
        distribution = [distro, 'EPEL7']
        logger.info(distribution)
        query_result = conn.multiget_query(rows, 'FilesToPackages', distro,
                                           True, False)
        logger.debug('Execute digests query')
        for digest_obj in cls.digests_dict.values():
            digest_string = digest_obj.digest_string
            if digest_string in known_digests:
                event_name = digest_obj.ima_records[0].entry['event_name']
                digest_obj.fullpath = event_name
                digest_obj.event_type = 'other'
                digest_obj.pkgs = {}
                continue

            if digest_string not in query_result:
                digest_obj.event_type = ''
                continue

            data = [query_result[digest_string][super_column]
                    for super_column in query_result[digest_string]
                    if super_column.startswith(tuple(distribution))]
            if len(data) == 0:
                logger.info('Digest %s (%s) not found for distro %s' %
                            (digest_string,
                             digest_obj.ima_records[0].entry['event_name'],
                             distribution))
                digest_obj.event_type = ''
                continue

            data = data[0]

            digest_obj.fullpath = data['fullpath']
            digest_obj.event_type = 'other'
            if 'libraries' in data:
                digest_obj.libraries = data['libraries'].split(',')
                if 'is_executable' in data:
                    digest_obj.event_type = 'exec'
                else:
                    digest_obj.event_type = 'lib'

            if 'lib_aliases' in data:
                digest_obj.lib_aliases = data['lib_aliases'].split(',')

            digest_obj.pkgs = {}
            pkg_data = [pkg_key[4:] for pkg_key in data.keys()
                        if pkg_key.startswith('pkg-')]
            for pkg_name in pkg_data:
                if pkg_name not in digest_obj.pkgs:
                    digest_obj.pkgs[pkg_name] = []
                digest_obj.pkgs[pkg_name].append(data['pkg-%s' % pkg_name])
                cls.packages_query.add('-'.join([pkg_name, distro]))

        cls.digests_query_done = True

    @classmethod
    def execute_packages_query(cls, conn, distro):
        if cls.packages_query_done:
            return

        query_result = conn.multiget_query(cls.packages_query,
                                           'PackagesHistory', distro,
                                           True, True)

        for digest_obj in Digest.digests_dict.values():
            if digest_obj.is_fake:
                continue
            if digest_obj.event_type == '':
                continue

            digest_obj.pkg_history = {}
            for pkg_name in digest_obj.pkgs:
                pkg_key = '-'.join([pkg_name, distro])

                if pkg_key not in query_result:
                    # log_info('Package history of %s not found' % pkg_name)
                    digest_obj.pkg_history[pkg_name] = None
                    continue

                digest_obj.pkg_history[pkg_name] = query_result[pkg_key]

        cls.packages_query_done = True

    def __init__(self, ima_record, event_name, fake):
        if fake:
            self.digest_string = event_name
        else:
            self.digest_string = ima_record.entry['event_digest']
            self.ima_records = []
            self.ima_records.append(ima_record)
        self.is_fake = fake

        Digest.digests_dict[self.digest_string] = self
        GenericNode.__init__(self, self.digest_string)


class Package(GenericNode):
    pkg_dict = {}

    @classmethod
    def get(cls, pkg_name=None, pkg_ver=None):
        try:
            return cls.pkg_dict[(pkg_name, pkg_ver)]
        except Exception:
            return cls(pkg_name, pkg_ver)

    def __init__(self, pkg_name=None, pkg_ver=None):
        self.pkg_name = pkg_name
        self.pkg_ver = pkg_ver
        Package.pkg_dict[(pkg_name, pkg_ver)] = self
        GenericNode.__init__(self, '-'.join([pkg_name, str(pkg_ver)]))


class Subject(GenericNode):
    subj_label_dict = {}

    @classmethod
    def get(cls, label=None, fake=False):
        if fake is True:
            label = 'unknown_reader-#%s' % (label)
        try:
            return cls.subj_label_dict[label]
        except Exception:
            return cls(label, fake)

    @classmethod
    def get_by_type(cls, label=None, fake=False):
        return [cls.subj_label_dict[key] for key in cls.subj_label_dict.keys()
                if key.split(':')[2] == label][0]

    def __init__(self, label=None, fake=False):
        self.label = label
        self.fake = fake
        Subject.subj_label_dict[label] = self
        GenericNode.__init__(self, 's-' + label, 'ok')


class Object(GenericNode):
    obj_label_dict = {}

    @classmethod
    def get(cls, label=None):
        try:
            return cls.obj_label_dict[label]
        except Exception:
            return cls(label)

    def __init__(self, label=None):
        self.label = label
        Object.obj_label_dict[label] = self
        GenericNode.__init__(self, 'o-' + label, 'ok')
