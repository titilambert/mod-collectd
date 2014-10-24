
import re
import time


from shinken.log import logger


from .collectd_parser import (
    Reader, Values, Data, Notification
)



class Data(Data):

    def get_srv_desc(self):
        '''
        :param item: A collectd Data instance.
        :return: The Shinken service name related by this collectd stats item.
        '''
        res = self.plugin
        if self.plugin not in self.grouped_collectd_plugins:
            if self.plugininstance:
                res += '-' +self.plugininstance
        # Dirty fix for 1.4.X:
        return re.sub(r'[' + "`~!$%^&*\"|'<>?,()=" + ']+', '_', res)

    def get_metric_name(self):
        res = self.type
        if self.plugin in self.grouped_collectd_plugins:
            if self.plugininstance:
                res += '-' + self.plugininstance
        if self.typeinstance:
            res += '-' + self.typeinstance
        return res

    def get_name(self):
        return '%s;%s' % (self.host, self.get_srv_desc())

    def get_time(self):
        return self.time if self.time else self.timehr



class Notification(Notification):

    _severity_2_retcode = {
        Notification.OKAY:      0,
        Notification.FAILURE:   2,
        Notification.WARNING:   3,
    }

    def get_message_command(self):
        """ Return data severity (exit code) from collectd datas
        """
        now = int(time.time())
        retcode = self._severity_2_retcode.get(self.severity, 3)
        return '[%d] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s' % (
            now, self.host, self.get_srv_desc(), retcode, self.message)


class Values(Data, Values):
    pass



class Shinken_Collectd_Reader(Reader):

    def __init__(self, *a, **kw):
        self.grouped_collectd_plugins = kw.get('grouped_collectd_plugins', [])
        super(Shinken_Collectd_Reader, self).__init__(*a, **kw)


    def Values(self):
        return Values(grouped_collectd_plugins=self.grouped_collectd_plugins)

    def Notification(self):
        return Notification(grouped_collectd_plugins=self.grouped_collectd_plugins)


    def receive(self):
        """Receives a single raw collect network packet.
        """
        buf = super(Shinken_Collectd_Reader, self).receive()
        logger.info('Got packet %s bytes', len(buf))
        return buf
