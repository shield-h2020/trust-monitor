#!/usr/bin/env python
# -*- coding: utf-8 -*-

# statistics.py: collect statistic data
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

import time


class Timer(object):
    start_time = 0
    last_get_time = 0
    current_time = 0

    @classmethod
    def start(self):
        Timer.start_time = time.time()
        Timer.current_time = Timer.start_time

    @classmethod
    def get_current(self):
        return str(round(time.time() - Timer.start_time, 5))

    @classmethod
    def get_elapsed(self):
        Timer.last_get_time = Timer.current_time
        Timer.current_time = time.time()
        return str(round(Timer.current_time - Timer.last_get_time, 5))

    def __del__(cls):
        print('Delete Timer object in statistics.py')
        cls.start_time = 0
        cls.last_get_time = 0
        cls.current_time = 0


class Statistics(object):

    global_stat = dict(time_parse_ima_list=0, time_exec_query=0,
                       time_build_graph=0, time_load_time_analysis=0,
                       time_run_time_analysis=0, time_total=0,
                       n_meas_code=0, n_meas_code_known=0,
                       n_meas_struct_data=0, n_meas_struct_data_known=0,
                       n_meas_unstruct_data=0, n_meas_violation=0,
                       n_tot_meas=0)

    @classmethod
    def inc_arch_stat(self, arch=None):
        Statistics.arch_stat[arch] += 1
        current_arch = Statistics.global_stat['distro_arch']
        if (arch != current_arch and
                Statistics.arch_stat[arch] >
                Statistics.arch_stat[current_arch]):
            Statistics.global_stat['distro_arch'] = arch

    @classmethod
    def inc_stat(self, stat_key=None, stat_value=None):
        Statistics.global_stat[stat_key] += 1

    @classmethod
    def dec_stat(self, stat_key=None, stat_value=None):
        Statistics.global_stat[stat_key] -= 1

    @classmethod
    def set_stat(self, stat_key=None, stat_value=None):
        Statistics.global_stat[stat_key] = stat_value

    @classmethod
    def get_stat(self, stat_key=None):
        return Statistics.global_stat[stat_key]

    @classmethod
    def start_timer(self):
        Timer.start()

    @classmethod
    def set_elapsed_time(self, stat_key=None):
        Statistics.global_stat[stat_key] = Timer.get_elapsed()

    @classmethod
    def set_current_time(self, stat_key=None):
        Statistics.global_stat[stat_key] = Timer.get_current()

    def __init__(self):
        return

    def __del__(cls):
        print('Delete Statistics object in statistics.py')
        cls.global_stat = dict(time_parse_ima_list=0, time_exec_query=0,
                               time_build_graph=0, time_load_time_analysis=0,
                               time_run_time_analysis=0, time_total=0,
                               n_meas_code=0, n_meas_code_known=0,
                               n_meas_struct_data=0,
                               n_meas_struct_data_known=0,
                               n_meas_unstruct_data=0, n_meas_violation=0,
                               n_tot_meas=0)
