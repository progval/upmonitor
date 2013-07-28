import smtplib
from email.mime.text import MIMEText

from upmonitor.i18n import _
from upmonitor.plugins import Plugin

class MailNotification(Plugin):
    def on_key_update(self, monitor_hostname, slave_hostname,
            key, old_timestamp, old_value, new_timestamp, new_value):
        assert old_timestamp is None or new_timestamp > old_timestamp
        if key == 'connected' and old_value != new_value:
            assert new_value in (True, False)
            if old_value is None:
                return
            notify_key = 'notify_up' if new_value else 'notify_down'
            if self.conf['hosts'][monitor_hostname]['monitor'][slave_hostname][notify_key] or \
                    (monitor_hostname == self.my_hostname and
                    self.conf['hosts'][self.my_hostname]['monitor'][slave_hostname][notify_key]):
                # TODO: Prevent other hosts from doing the same
                self.create_intent([monitor_hostname, slave_hostname,
                    new_timestamp, new_value])
            else:
                # This host will handle it itself
                return
    def on_approved_intent(self, id_, extra):
        (monitor_hostname, slave_hostname, timestamp, new_status) = id_
        variables = {
                'my_hostname': self.my_hostname,
                'monitor_hostname': monitor_hostname,
                'slave_hostname': slave_hostname,
                'up_or_down': _('up') if new_status else _('down'),
                }
        # TODO: This should be configurable on a per-host basis.
        smtp = smtplib.SMTP('localhost')
        for recipient in self.conf['contact']:
            self.log.info('Sending mail to %s for %s -> %s going %s' %
                    (recipient, monitor_hostname, slave_hostname,
                        'up' if new_status else 'down'))
            msg = MIMEText(_("Mail notification from %(my_hostname)s's "
                    "upmonitor:\n\n"
                    "connection from %(monitor_hostname)s to %(slave_hostname)s "
                    "just went %(up_or_down)s") % variables)
            msg['Subject'] = _('upmonitor: %(monitor_hostname)s -> '
                    '%(slave_hostname)s just went %(up_or_down)s') % variables
            msg['From'] = 'upmonitor'
            msg['To'] = recipient

            #smtp.send_message(msg)
        smtp.close()





Plugin = MailNotification

