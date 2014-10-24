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

from shinken.basemodule import BaseModule
from shinken.external_command import ExternalCommand
from shinken.log import logger

from .collectd_parser import (
    DS_TYPE_COUNTER, DS_TYPE_GAUGE, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE,
    Data, Values, Notification,
    Reader
)


properties = {
    'daemons': ['arbiter', 'receiver'],
    'type': 'collectd',
    'external': True,
    }

DEFAULT_PORT = 25826
DEFAULT_MULTICAST_IP = "239.192.74.66"
BUFFER_SIZE = 65536


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



_severity_2_retcode = {
    Notification.OKAY:      0,
    Notification.FAILURE:   2,
    Notification.WARNING:   3,
}


class Element(object):
    """ Element store service name and all perfdatas before send it in a external command """
    def __init__(self, host_name, sdesc, interval):
        self.host_name = host_name
        self.sdesc = sdesc
        self.perf_datas = {}
        self.last_update = time.time()
        self.interval = interval
        self.got_new_data = False

    def add_perf_data(self, mname, mvalues, mtime):
        """ Add perf datas to the message to send to Shinken """
        if not mvalues:
            return

        r = []
        if mname not in self.perf_datas:
            for (dstype, newrawval) in mvalues:
                r.append((dstype, newrawval, newrawval, mtime))
        else:
            oldvalues = self.perf_datas[mname]

            for (olddstype, oldrawval, oldval, oldtime), (dstype, newrawval) in izip(oldvalues, mvalues):
                difftime = mtime - oldtime
                if difftime < 1:
                    continue
                if dstype == DS_TYPE_COUNTER or dstype == DS_TYPE_DERIVE or dstype == DS_TYPE_ABSOLUTE:
                    r.append((dstype, newrawval, (newrawval - oldrawval) / float(difftime), mtime))
                elif dstype == DS_TYPE_GAUGE:
                    r.append((dstype, newrawval, newrawval, mtime))

        self.perf_datas[mname] = r
        self.got_new_data = True

    def get_command(self):
        """ Prepare the external command for Shinken """
        if len(self.perf_datas) == 0:
            return None

        if not self.got_new_data:
            return None

        now = int(time.time())
        if now > self.last_update + self.interval:
            r = '[%d] PROCESS_SERVICE_OUTPUT;%s;%s;CollectD| ' % (now, self.host_name, self.sdesc)
            for (k, v) in self.perf_datas.iteritems():
                for i, w in enumerate(v):
                    if len(v) > 1:
                        r += '%s_%d=%s ' % (k, i, str(w[2]))
                    else:
                        r += '%s=%s ' % (k, str(w[2]))
            logger.debug('Updating: %s - %s ' % (self.host_name, self.sdesc))
#            self.perf_datas.clear()
            self.last_update = now
            self.got_new_data = False
            return r



class Collectd_arbiter(BaseModule):
    """ Main class for this collecitd module """
    def __init__(self, modconf, host, port, multicast, grouped_collectd_plugins=[]):
        BaseModule.__init__(self, modconf)
        self.host = host
        self.port = port
        self.multicast = multicast
        self.grouped_collectd_plugins = grouped_collectd_plugins
        self.elements = {}

    #########################################################################
    # helpers:

    def get_srv_desc(self, item):
        '''
        :param item: A collectd Values instance.
        :return: The Shinken service name related by this collectd stats item.
        '''
        assert isinstance(item, Data)
        res = item.plugin
        if item.plugin not in self.grouped_collectd_plugins:
            if item.plugininstance:
                res += '-' + item.plugininstance
        # Dirty fix for 1.4.X:
        return re.sub(r'[' + "`~!$%^&*\"|'<>?,()=" + ']+', '_', res)

    def get_metric_name(self, item):
        assert isinstance(item, Values)
        res = item.type
        if item.plugin in self.grouped_collectd_plugins:
            if item.plugininstance:
                res += '-' + item.plugininstance
        if item.typeinstance:
            res += '-' + item.typeinstance
        return res

    def get_name(self, item):
        return '%s;%s' % (item.host, self.get_srv_desc(item))

    def get_time(self, item):
        return item.time if item.time else item.timehr

    #-------------------------------------

    def get_notification_message_command(self, notif):
        assert isinstance(notif, Notification)
        now = int(time.time())
        retcode = _severity_2_retcode.get(notif.severity, 3)
        return '[%d] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s' % (
                now, notif.host, self.get_srv_desc(notif), retcode, notif.message)

    #########################################################################

    # When you are in "external" mode, that is the main loop of your process
    def main(self):
        """ Plugin main loop """
        self.set_proctitle(self.name)
        self.set_exit_handler()

        elements = self.elements
        try:
            collectdreader = Reader(self.host, self.port, self.multicast)
            while True:
                # Each second we are looking at sending old elements
                for elem in elements.values():
                    assert isinstance(elem, Element)
                    cmd = elem.get_command()
                    if cmd is not None:
                        logger.debug("[Collectd] Got %s" % cmd)
                        self.from_q.put(ExternalCommand(cmd))

                for item in collectdreader.read():
                    assert isinstance(item, Data)
                    logger.debug("[Collectd] %s" % (item))

                    if isinstance(item, Notification):
                        cmd = self.get_notification_message_command(item)
                        if cmd is not None:
                            self.from_q.put(ExternalCommand(cmd))

                    elif isinstance(item, Values):
                        name = self.get_name(item)
                        elem = elements.get(name, None)
                        if elem is None:
                            elem = Element(item.host,
                                           self.get_srv_desc(item),
                                           item.interval)
                            elements[name] = elem
                        elem.add_perf_data(self.get_metric_name(item),
                                           item,
                                           self.get_time(item))

        except Exception as err:
            logger.error("[Collectd] Unexpected error: %s ; %s", err, traceback.format_exc())
