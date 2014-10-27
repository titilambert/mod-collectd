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
import threading
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
    DS_TYPE_COUNTER, DS_TYPE_GAUGE, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE,
    DEFAULT_PORT, DEFAULT_IPv4_GROUP
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
        host = DEFAULT_IPv4_GROUP
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

class Element(object):
    """ Element store service name and all perfdatas before send it in a external command """

    def __init__(self, host_name, sdesc, interval, last_sent=None):
        self.host_name = host_name
        self.sdesc = sdesc
        self.perf_datas = {}
        # for the first time we'll wait 2*interval to be sure to get a complete data set :
        self.interval = interval
        if not last_sent:
            last_sent = time.time()
        self.last_sent = last_sent + interval

    def _last_update(self, _op=max):
        # mvalues[-1] is the metric last read value. [-2] is it's epoch time value.
        return _op(mvalues[-1][-1] for mvalues in self.perf_datas.values())

    @property
    def last_full_update(self):
        '''
        :return: The last "full" update time of this element. i.e. the metric mininum last update own time.
        '''
        return self._last_update(min)

    @property
    def send_ready(self):
        return ( self.perf_datas
                 and self.last_full_update > self.last_sent
                 and time.time() > self.last_sent + self.interval - 1)


    def __str__(self):
        return '%s.%s' % (self.host_name, self.sdesc)

    def add_perf_data(self, mname, mvalues, mtime):
        """ Add perf datas to this element.
        :param mname:   The metric name.
        :param mvalues: The metric read values.
        :param mtime:   The "epoch" time when the values were read.
        """
        if not mvalues:
            return

        res = []
        now = time.time()

        if mname not in self.perf_datas:
            logger.info('%s : New perfdata: %s : %s' % (self, mname, mvalues))
            for (dstype, newrawval) in mvalues:
                # we also retain the local time (`now´) more for convenience purpose.
                res.append((dstype, newrawval, newrawval, mtime, now))
        else:
            oldvalues = self.perf_datas[mname]
            for (olddstype, oldrawval, oldval, oldtime, oldnow), (dstype, newrawval) in izip(oldvalues, mvalues):
                difftime = mtime - oldtime
                if difftime < 1:
                    continue
                if dstype in (DS_TYPE_COUNTER, DS_TYPE_DERIVE, DS_TYPE_ABSOLUTE):
                    res.append((dstype, newrawval, (newrawval - oldrawval) / float(difftime), mtime, now))
                elif dstype == DS_TYPE_GAUGE:
                    res.append((dstype, newrawval, newrawval, mtime, now))

        if res:
           self.perf_datas[mname] = res


    def get_command(self):
        """ Look if this element has data to be sent to Shinken.
        :return
            - None if element has not all its perf data refreshed since last sent..
            - The command to be sent otherwise. """

        if not self.send_ready:
            return

        res = ''
        pdatas = self.perf_datas

        max_time = None

        for k in sorted(pdatas):
            v = pdatas[k]
            for i, w in enumerate(v):
                value_to_str = lambda v: '%f' % v if isinstance(w[2], float) else str
                if len(v) > 1:
                    res += '%s_%d=%s ' % (k, i, value_to_str(w[2]))
                else:
                    res += '%s=%s ' % (k, value_to_str(w[2]))
                if max_time is None or w[-2] > max_time:
                    max_time = w[-2]

        logger.info('%s;%s > %s pdatas' % (self.host_name, self.sdesc, len(pdatas)))

        d = dict((
            ('disk', 16),
            ('interface', 12),
            ('df', 12),
            ('cpu', 32),
            ('load', 1),
            ('processes', 7),
        ))
        check = d.get(self.sdesc, None)
        if check and len(pdatas) != check:
            logger.info('DAMN: %s.%s %s vs %s (%s)' % (self.host_name, self.sdesc, check, len(pdatas), res))

        now = time.time()
        self.last_sent = now

        return '[%d] PROCESS_SERVICE_OUTPUT;%s;%s;CollectD|%s' % (
                int(max_time), self.host_name, self.sdesc, res)

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
        self.lock = threading.Lock()
        #self.cond = threading.Condition()
        #self.send_ready = False


    def _read_collectd_packet(self, reader):
        elements = self.elements
        lock = self.lock

        #send_ready = False
        item_iterator = reader.interpret()
        while True:
            try:
                item = next(item_iterator)
            except StopIteration:
                break
            except CollectdException as err:
                logger.error('CollectdException: %s' % err)
                continue

            assert isinstance(item, Data)
            #logger.info("[Collectd] < %s" % item)

            if isinstance(item, Notification):
                cmd = item.get_message_command()
                if cmd is not None:
                    #logger.info('-> %s', cmd)
                    self.from_q.put(ExternalCommand(cmd))

            elif isinstance(item, Values):
                name = item.get_name()
                elem = elements.get(name, None)
                is_new = not bool(elem)
                if elem is None:
                    elem = Element(item.host,
                                   item.get_srv_desc(),
                                   item.interval)
                    logger.info('Created %s ; interval=%s' % (elem, elem.interval))
                else:
                    assert isinstance(elem, Element)
                    if elem.interval != item.interval:
                        logger.info('%s : interval changed from %s to %s ; adapting..' % (
                                    name, elem.interval, item.interval))
                        with lock:
                            # make sure interval is updated when it's changed by collectd client:
                            elem.interval = item.interval
                            # also reset last_update time so that we'll wait that before resending its data:
                            elem.last_sent = time.time() + item.interval
                            elem.perf_datas.clear()

                # now we can add this perf data:
                with lock:
                    elem.add_perf_data(item.get_metric_name(), item, item.time)
                    if is_new:
                        elements[name] = elem
                    if elem.send_ready:
                        send_ready = True
        #end for

        #if send_ready:
        #    with self.cond:
        #        self.send_ready = True
        #        self.cond.notify()


    def _read_collectd(self, reader):
        while not self.interrupted:
            self._read_collectd_packet(reader)


    # When you are in "external" mode, that is the main loop of your process
    def do_loop_turn(self):

        elements = self.elements
        lock = self.lock
        next_clean = time.time() + 15

        reader = ShinkenCollectdReader(self.host, self.port, self.multicast,
                                       grouped_collectd_plugins=self.grouped_collectd_plugins)
        try:
            collectd_reader_thread = threading.Thread(target=self._read_collectd, args=(reader,))
            collectd_reader_thread.start()

            while not self.interrupted:

                #with self.cond:
                #    if not self.send_ready:
                #        self.cond.wait(1)
                #    self.send_ready = False
                time.sleep(1)

                todel = []
                tosend = []

                with lock:
                    for name, elem in elements.iteritems():
                        assert isinstance(elem, Element)
                        cmd = elem.get_command()
                        if cmd:
                            tosend.append(cmd)

                # we could send those in one shot !
                for cmd in tosend:
                    self.from_q.put(ExternalCommand(cmd))

                now = time.time()
                if now > next_clean:
                    next_clean = now + 15
                    if not collectd_reader_thread.isAlive():
                        raise Exception('Collectd read thread unexpectedly died.. exiting.')
                    with lock:
                        for name, elem in elements.iteritems():
                            for pname, vvalues in elem.perf_datas.items():
                                if vvalues[0][-1] < now - 4*elem.interval:
                                    # this perf data has not been updated for more than 2 intervals
                                    # purge it.
                                    del elem.perf_datas[pname]
                                    logger.info('%s : purged %s' % (elem, pname))
                            if not elem.perf_datas:
                                todel.append(name)

                        for name in todel:
                            logger.info('%s : not anymore updated > purged.' % name)
                            del elements[name]

        except Exception as err:
            logger.error("[Collectd] Unexpected error: %s ; %s" % (err, traceback.format_exc()))
        finally:
            reader.close()
            collectd_reader_thread.join()
