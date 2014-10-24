#!/usr/bin/python

# -*- coding: utf-8 -*-

# Copyright (C) 2009-2012:
#    Gabes Jean, naparuba@gmail.com
#    Gerhard Lausser, Gerhard.Lausser@consol.de
#    Gregory Starck, g.starck@gmail.com
#    Hartmut Goebel, h.goebel@goebel-consult.de
#    Thibault Cohen, thibault.cohen@savoirfairelinux.com
#
# This file is part of Shinken.
#
# Shinken is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Shinken is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Shinken.  If not, see <http://www.gnu.org/licenses/>.

"""
Collectd Plugin for Receiver or arbiter
"""

import os
import re
import time
import traceback
from itertools import izip

#############################################################################

from shinken.basemodule import BaseModule
from shinken.external_command import ExternalCommand
from shinken.log import logger

#############################################################################

from .collectd_parser import (
    CollectdException,
    DS_TYPE_COUNTER, DS_TYPE_GAUGE, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE
)
from .collectd_shinken_parser import (
    Data, Values, Notification,
    ShinkenCollectdReader
)

#############################################################################

properties = {
    'daemons': ['arbiter', 'receiver'],
    'type': 'collectd',
    'external': True,
    }

DEFAULT_PORT = 25826
DEFAULT_MULTICAST_IP = "239.192.74.66"
BUFFER_SIZE = 65536

#############################################################################

def get_instance(plugin):
    """ This function is called by the module manager
    to get an instance of this module
    """
    if hasattr(plugin, "multicast"):
        multicast = plugin.multicast.lower() in ("yes", "true", "1")
    else:
        multicast = False

    if hasattr(plugin, 'host'):
        host = plugin.host
    else:
        host = DEFAULT_MULTICAST_IP
        multicast = True

    if hasattr(plugin, 'port'):
        port = int(plugin.port)
    else:
        port = DEFAULT_PORT

    if hasattr(plugin, 'grouped_collectd_plugins'):
        grouped_collectd_plugins = [name.strip()
                                    for name in plugin.grouped_collectd_plugins.split(',')]
    else:
        grouped_collectd_plugins = []

    logger.info("[Collectd] Using host=%s port=%d multicast=%d" % (host, port, multicast))

    instance = Collectd_arbiter(plugin, host, port, multicast, grouped_collectd_plugins)
    return instance

#############################################################################

_ELEMENT_MAX_AGE_SEC = 3600

class Element(object):
    """ Element store service name and all perfdatas before send it in a external command """

    def __init__(self, host_name, sdesc, interval):
        self.host_name = host_name
        self.sdesc = sdesc
        self.perf_datas = {}
        # for the first time we'll wait 2*interval to be sure to get a complete data set :
        self.last_update = time.time() + interval
        self.interval = interval
        self.got_new_data = False

    def add_perf_data(self, mname, mvalues, mtime):
        """ Add perf datas to this element """
        if not mvalues:
            return

        res = []
        if mname not in self.perf_datas:
            for (dstype, newrawval) in mvalues:
                res.append((dstype, newrawval, newrawval, mtime))
        else:
            oldvalues = self.perf_datas[mname]
            for (olddstype, oldrawval, oldval, oldtime), (dstype, newrawval) in izip(oldvalues, mvalues):
                difftime = mtime - oldtime
                if difftime < 1:
                    continue
                if dstype in (DS_TYPE_COUNTER, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE):
                    res.append((dstype, newrawval, (newrawval - oldrawval) / float(difftime), mtime))
                elif dstype == DS_TYPE_GAUGE:
                    res.append((dstype, newrawval, newrawval, mtime))

        self.perf_datas[mname] = res
        self.got_new_data = bool(res)


    def get_command(self):
        """ Look if this element has data to be sent to Shinken.
        :return
            - None if element has no ready data.
            - The command to be sent otherwise. """
        if not self.got_new_data:
            return

        now = time.time()
        if now < self.last_update + self.interval:
            return

        pdata = ''
        for (k, v) in self.perf_datas.iteritems():
            for i, w in enumerate(v):
                if len(v) > 1:
                    pdata += '%s_%d=%s ' % (k, i, str(w[2]))
                else:
                    pdata += '%s=%s ' % (k, str(w[2]))

        self.last_update = now
        self.got_new_data = False
        # TODO: self.perf_datas.clear()  # should we or not ?
        return '[%d] PROCESS_SERVICE_OUTPUT;%s;%s;CollectD|%s' % (int(now), self.host_name, self.sdesc, pdata)

#############################################################################

class Collectd_arbiter(BaseModule):
    """ Main class for this collecitd module """

    def __init__(self, modconf, host, port, multicast, grouped_collectd_plugins=None):
        BaseModule.__init__(self, modconf)
        self.host = host
        self.port = port
        self.multicast = multicast
        if grouped_collectd_plugins is None:
            grouped_collectd_plugins = []
        self.elements = {}
        self.grouped_collectd_plugins = grouped_collectd_plugins

    # When you are in "external" mode, that is the main loop of your process
    def main(self):
        """ Plugin main loop """
        self.set_proctitle(self.name)
        self.set_exit_handler()

        elements = self.elements
        reader = ShinkenCollectdReader(self.host, self.port, self.multicast,
                                       grouped_collectd_plugins=self.grouped_collectd_plugins)

        try:
            while not self.interrupted:

                now = time.time()

                # Each second we are looking at sending old elements
                for name, elem in elements.items():
                    assert isinstance(elem, Element)
                    cmd = elem.get_command()
                    if cmd:
                        logger.info("[Collectd] Got %s" % cmd)
                        self.from_q.put(ExternalCommand(cmd))
                    else:
                        if elem.last_update < now - _ELEMENT_MAX_AGE_SEC:
                            del elements[name]
                            logger.info('%s not anymore updated for %s secs ; purged.' % (name, _ELEMENT_MAX_AGE_SEC))

                for item in reader.read():

                    assert isinstance(item, Data)
                    logger.debug("[Collectd] < %s", str(item))

                    if isinstance(item, Notification):
                        cmd = item.get_message_command()
                        if cmd is not None:
                            logger.info('-> %s', cmd)
                            self.from_q.put(ExternalCommand(cmd))

                    elif isinstance(item, Values):
                        name = item.get_name()
                        elem = elements.get(name, None)
                        if elem is None:
                            elem = Element(item.host,
                                           item.get_srv_desc(),
                                           item.interval)
                            elements[name] = elem
                        else:
                            assert isinstance(elem, Element)
                            if elem.interval != item.interval:
                                logger.info('%s : interval changed from %s to %s ; adapting..' % (
                                    name, elem.interval, item.interval))
                                # make sure interval is updated when it's changed by collectd client:
                                elem.interval = item.interval
                                # also reset last_update time so that we'll wait that before resending its data:
                                elem.last_update = time.time() + elem.interval
                                elem.perf_datas.clear()

                        # now we can add this perf data:
                        elem.add_perf_data(item.get_metric_name(), item, item.time)

        except Exception as err:
            logger.error("[Collectd] Unexpected error: %s ; %s" % (err, traceback.format_exc()))
        finally:
            reader.close()
