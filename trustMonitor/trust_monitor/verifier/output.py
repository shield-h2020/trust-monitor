#!/usr/bin/env python
# -*- coding: utf-8 -*-

# output.py: display analyses results
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
from statistics import *
import sys
import os

fdout = None


def output_init(outfile=None):
    global fdout

    if outfile is None:
        fdout = sys.stdout
    else:
        try:
            fdout = open(outfile, 'ac')
        except Exception:
            pass
            # log_error('Unable to open file %s for writing' % (outfile))


def output_write(buf=None):
    if fdout is None:
        return

    try:
        fdout.write(buf)
        fdout.write('\n')
    except Exception:
        pass


class HTMLOutput(object):
    def __init__(self, outfile=None):
        output_init(outfile)

    def show_summary_table(self, statistics=None):
        output_write('<h3>Summary</h3>')
        buf = ("""<table class="zebra-striped">
               <tr><th COLSPAN="2"><b>Timings (seconds)</b></th>
               <th COLSPAN="2">
               <b>Statistics (distribution: %(distro)s, architecture:
               %(distro_arch)s)</b></th></tr>
               <tr><td>Parse IMA list</td><td>%(time_parse_ima_list)s</td
               <td>Total number of measurements</td><td>%(n_tot_measurements)s
               </td></tr>
               <tr><td>Execute first query</td><td>%(time_exec_first_query)s
               </td><td>Total number of queried measurements</td><td>
               %(n_queried_files)s</td></tr>
               <tr><td>Parse first query</td><td>%(time_parse_first_query)s
               </td><td> - Known files</td><td>%(n_queried_known_files)s</td>
               </tr>
               <tr><td>Execute second query</td><td>%(time_exec_second_query)s
               </td><td> - Unknown files (unique name)</td><td>
               %(n_queried_unknown_files)s (%(n_queried_unknown_files_unique)s)
               </td></tr>
               <tr><td>Parse second query</td><td>%(time_parse_second_query)s
               </td><td>    - Executable code</td><td>
               %(n_unknown_executable_code)s</td></tr>
               <tr><td>Build graph</td><td>%(time_build_graph)s</td>
               <td>    - Static data</td><td>%(n_unknown_static_data)s
               </td></tr>
               <tr><td>IVP check</td><td>%(time_ivp_check)s</td>
<td>    - Dynamic data (same digest of static data)</td><td>
%(n_found_digest_dynamic_data)s</td></tr>
<tr><td>Load-time analysis</td><td>%(time_load_time_analysis)s
</td><td>Total number of unqueried measurements</td><td>
%(n_tot_unqueried_measurements)s</td></tr>
<tr><td>Run-time analysis</td><td>%(time_run_time_analysis)s
</td><td> - Boot aggregate</td><td>%(n_boot_aggregate)s
</td></tr>
<tr><td>Process context change analysis</td><td>
%(time_process_context_change_analysis)s</td>
<td> - Violations</td><td>%(n_violations)s</td></tr>
<tr><td>IVP update</td><td>%(time_ivp_update)s</td>
<td> - Unqueried files (empty, newline)</td><td>
%(n_unqueried_files)s (%(n_empty_files)s, %(n_newline_files)s)
</td></tr>
<tr><td>Display results</td><td>%(time_display_results)s</td>
<td>Total number of packages</td><td>%(n_tot_packages)s
</td></tr>
<tr><td>Draw graph</td><td>%(time_draw_graph)s</td>
<td>Total number of files</td><td>%(n_tot_files)s</td></tr>
<tr><td>Total analysis time</td><td>%(time_total)s</td>
<td> - regular</td><td>%(n_reg_file)s</td></tr>
<tr><td></td><td></td><td> - directory</td>
<td>%(n_dir_file)s</td></tr>
               <tr><td></td><td></td><td> - symbolic link</td>
<td>%(n_lnk_file)s</td></tr>
<tr><td></td><td></td><td> - fifo</td>
<td>%(n_fifo_file)s</td></tr>
<tr><td></td><td></td><td> - UNIX socket</td>
<td>%(n_sock_file)s</td></tr>
<tr><td></td><td></td><td> - char device file</td>
<td>%(n_chr_file)s</td></tr>
               <tr><td></td><td></td><td> - block device file</td>
<td>%(n_blk_file)s</td></tr>
               <tr><td></td><td></td>
<td>Total number of digests checked with IVP</td>
<td>%(n_ivp_tot_digests_checked)s</td></tr>
               <tr><td></td><td></td><td> - Digests ok</td>
<td>%(n_ivp_digests_ok)s</td></tr>
<tr><td></td><td></td><td> - Digests not found</td>
<td>%(n_ivp_tot_digests_not_found)s</td></tr>
               <tr><td></td><td></td><td>    - Static data</td>
<td>%(n_ivp_digests_static_data_not_found)s</td></tr>
               <tr><td></td><td></td>
<td>    - Dynamic data (TCB, Target, Outside TCB, Conflicts)
</td><td>%(n_ivp_digests_dynamic_data_not_found)s
(%(n_ivp_bad_objs_tcb)s, %(n_ivp_bad_objs_target)s,
%(n_ivp_bad_objs_outside_tcb)s, %(n_ivp_bad_objs_conflicts)s)
</td></tr>
               <tr><td></td><td></td>
               <td>Total number of IVP records added to the database</td><td>
               %(n_ivp_tot_records_added)s</td></tr>
              <tr><td></td><td></td><td> - Static data</td><td>
              %(n_ivp_static_data_records_added)s</td></tr>
              <tr><td></td><td></td><td> - Dynamic data</td>
              <td>%(n_ivp_dynamic_data_records_added)s</td></tr>
              <tr><td></td><td></td>
              <td>Total number of IVP dynamic data records updated</td><td>
              %(n_ivp_dynamic_data_records_updated)s</td></tr>
              </table>
              <hr/>""") % Statistics.global_stat
        output_write(buf)

    def show_table_start(self):
        output_write('<h3>IMA measurements</h3>')
        output_write('''<table class="zebra-striped" id="ima-table">
<thead>
<tr>
<th class="header blue" width="60px"><b>Meas. #</b></th>
<th class="header green" width="220px"><b>Event name</b></th>
<th class="header yellow" width="80px"><b>Event type</b></th>
<th class="header orange" width="220px"><b>Packages (update type)
[ current, latest, latest critical ]</b></th>
<th class="header red"><b>Query status</b></th>
</tr>
</thead>
<tbody>''')

    def show_table_item(self, imarecord=None, displaymode=7):
        printrow = False
        if displaymode & 1 and imarecord.query_status != 'not-found':
            printrow = True
        if displaymode & 2 and imarecord.query_status == 'reconstructed':
            printrow = True
        if displaymode & 4 and imarecord.query_status == 'not-found':
            printrow = True
        if printrow is False:
            return

        event_type = ''
        packagesstring = ''
        if (imarecord.query_status != 'not-found' and
                imarecord.query_status != 'reconstructed'):
            event_type = imarecord.digest.event_type

            pkgs = imarecord.digest.pkgs
            for key in pkgs.keys():
                if len(packagesstring) > 0:
                    packagesstring += ' '
                packagesstring += ('%s (%s) / %s (%s) / %s (%s)' %
                                   (pkgs[key]['current'][0],
                                    pkgs[key]['current'][1],
                                    pkgs[key]['latest'][0],
                                    pkgs[key]['latest'][1],
                                    pkgs[key]['latestcritical'][0],
                                    pkgs[key]['latestcritical'][1]))

        buf = '<tr><td>' + \
            "<a href='#' rel='alternate' data-original-title='IMA original + \
            string' data-content='" + imarecord.record + "'>" + \
            str(imarecord.rank) + "</a>" + \
            "</td><td class='wrap'>" + \
            imarecord.template.get(ROW_EVENTNAME) + \
            "</td><td class='wrap'>" + event_type + \
            "</td><td class='wrap'>" + packagesstring + \
            "</td><td class='wrap'>" + imarecord.query_status + '</td></tr>'

        output_write(buf)

        def show_table_end(self):
            output_write('''	</tbody>
</table>
<hr/>''')

        def show_graph(self, outfile=None):
            if outfile is None:
                return

            imgfile = 'images/' + os.path.basename(outfile) + '.png'
            dotfile = 'images/' + os.path.basename(outfile) + '.dot'

            output_write(
                '<h3>Graph of IMA measurements (Click to download)</h3>')
            buf = ("""<table class="zebra-striped">
<tr><td COLSPAN="2"><a href="%(imgfile)s" target="_blank"> <img src=
"%(imgfile)s" alt="Graph of IMA measurements"/></a></td></tr>
<tr><td COLSPAN="2"><b>Legend:</b></td></tr>
<tr><td><b>Node color</b></td><td><b>Entry type</b></td></tr>
<tr>
<td>green</td>
<td>This entry has a known hash/file name and comes from a package not
affected by security alerts.</td>
</tr>
<tr>
<td>white</td>
<td>This entry comes from a "enhancement" package.</td>
</tr>
<tr>
<td>yellow</td>
<td>The entry digest is recognized, but the file name mismatches the one
in the package.</td>
</tr>
<tr>
<td>orange</td>
<td>The entry comes from a "bugfix" package.</td>
</tr>
<tr>
<td>violet</td>
<td>The entry digest is not found on the database.</td>
</tr>
<tr>
<td>red</td>
<td>This entry comes from a package affected by security alerts.</td>
</tr>
<tr>
<td>blue</td>
<td>The entry digest is not found on the database.</td>
</tr>
<tr>
<td>gray</td>
<td>Something gone wrong when searching the digest in the database.</td>
</tr>
<tr>
<td>cyan</td>
<td>This entry doesn't match any of the above types.</td>
</tr>""") % {'imgfile': imgfile}

            if os.path.exists(outfile + ".dot"):
                buf += """<tr><td COLSPAN="2"><a href="%s"><b>Download graph in
                       .dot format</b></td></tr>""" % (dotfile)

            output_write(buf)
            output_write("</table>")
