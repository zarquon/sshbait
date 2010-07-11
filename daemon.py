#!/usr/bin/env python

# Initially based on the sshsimpleserver.py kindly published by:
# Twisted Matrix Laboratories - http://twistedmatrix.com

import base64
import datetime
import socket
import string
import sys
import random

from twisted.cred import portal, checkers, credentials
from twisted.conch import avatar, error
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh import factory, userauth, connection, common, keys, session, channel
from twisted.internet import reactor, protocol, defer
from twisted.python import log, failure, components
from zope.interface import implements

ARROW_KEYS = ('\x1b\x5b\x41', '\x1b\x5b\42', '\x1b\x5b\43', '\x1b\x5b\44') # UDRL

FAKE_PROMPT = 'root@area51:~# '

PUBLIC_KEY = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAGEArzJx8OYOnJmzf4tfBEvLi8DVPrJ3/c9k2I/Az64fxjHf9imyRJbixtQhlH9lfNjUIx+4LmrJH5QNRsFporcHDKOTwTTYLh5KmRpslkYHRivcJSkbh/C+BR3utDS555mV'

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIByAIBAAJhAK8ycfDmDpyZs3+LXwRLy4vA1T6yd/3PZNiPwM+uH8Yx3/YpskSW
4sbUIZR/ZXzY1CMfuC5qyR+UDUbBaaK3Bwyjk8E02C4eSpkabJZGB0Yr3CUpG4fw
vgUd7rQ0ueeZlQIBIwJgbh+1VZfr7WftK5lu7MHtqE1S1vPWZQYE3+VUn8yJADyb
Z4fsZaCrzW9lkIqXkE3GIY+ojdhZhkO1gbG0118sIgphwSWKRxK0mvh6ERxKqIt1
xJEJO74EykXZV4oNJ8sjAjEA3J9r2ZghVhGN6V8DnQrTk24Td0E8hU8AcP0FVP+8
PQm/g/aXf2QQkQT+omdHVEJrAjEAy0pL0EBH6EVS98evDCBtQw22OZT52qXlAwZ2
gyTriKFVoqjeEjt3SZKKqXHSApP/AjBLpF99zcJJZRq2abgYlf9lv1chkrWqDHUu
DZttmYJeEfiFBBavVYIF1dOlZT0G8jMCMBc7sOSZodFnAiryP+Qg9otSBjJ3bQML
pSTqy7c3a2AScC/YyOwkDaICHnnD3XyjMwIxALRzl0tQEKMXs6hH8ToUdlLROCrP
EhQ0wahUTCk1gKA4uPD6TMTChavbh4K63OvbKg==
-----END RSA PRIVATE KEY-----"""

def extract_command(buf):
    cmd = buf.strip().split(' ')[0]
    return ''.join([x for x in cmd if x in string.printable])

class RandomPassChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword)

    def __init__(self, pass_rate=0.1):
        self.pass_rate = pass_rate

    def requestAvatarId(self, credentials):
        log.msg('username="%s" password="%s"' % (credentials.username, credentials.password))
        if random.random() < self.pass_rate:
            return defer.succeed(credentials.username)
        else:
            return defer.fail(error.UnauthorizedLogin())

class PatchedSSHSession(session.SSHSession):
    def loseConnection(self):
        if getattr(self.client, 'transport', None) is not None:
            self.client.transport.loseConnection()
        channel.SSHChannel.loseConnection(self)

class SSHAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session': PatchedSSHSession})

class SSHRealm:
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], SSHAvatar(avatarId), lambda: None

class HoneypotProtocol(protocol.Protocol):
    """ A hilariously un-convincing fake terminal! """

    def __init__(self, *args, **kwargs):
        self.data_buffer = []

    def writePrompt(self):
        self.recordBuffer()
        self.visible_count = 0
        self.data_buffer = []
        self.transport.write('\r\n' + FAKE_PROMPT)

    def connectionMade(self):
        self.writePrompt()

    def recordBuffer(self):
        log.msg('b64 buffer command: "%s"' % base64.b64encode(''.join(self.data_buffer)))

    def disconnect(self):
        self.recordBuffer()
        self.transport.loseConnection()

    def dataReceived(self, data):
        self.data_buffer.append(data)

        if data in string.printable:
            self.visible_count += 1

        if data == '\x7f':
            if self.visible_count <= 0:
                return
            else:
                self.visible_count -= 1
        elif data == '\r':
            self.transport.write('\r\n')
            command = extract_command(''.join(self.data_buffer))
            if (command in ('logout', 'exit')):
                self.disconnect()
            self.transport.write('%s: command not found' % command)
            self.writePrompt()
            return
        elif data == '\x03': #^C
            self.transport.write('^C')
            self.writePrompt()
            return
        elif data == '\x04': #^D
            self.transport.write('logout\r\n')
            self.disconnect()
            return
        elif data in ARROW_KEYS:
            return

        self.transport.write(data)

class HoneypotSession:
    def __init__(self, *args, **kwargs):
        pass

    def getPty(self, *args, **kwargs):
        pass

    def execCommand(self, proto, cmd):
        log.msg('b64 argument command: "%s"' % base64.b64encode(cmd))
        proto.write('bash: %s: command not found\r\n' % extract_command(cmd))
        proto.processEnded()


    def openShell(self, trans):
        proto = HoneypotProtocol()
        proto.makeConnection(trans)
        trans.makeConnection(session.wrapProtocol(proto))

    def eofReceived(self):
        pass

    def closed(self):
        pass

class SimpleSSHFactory(factory.SSHFactory):
    publicKeys = {
        'ssh-rsa': keys.Key.fromString(data=PUBLIC_KEY)
    }
    privateKeys = {
        'ssh-rsa': keys.Key.fromString(data=PRIVATE_KEY)
    }
    services = {
        'ssh-userauth': userauth.SSHUserAuthServer,
        'ssh-connection': connection.SSHConnection
    }

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option('-p', '--port',
                      action='store',
                      dest='port',
                      help='TCP port (root required for < 1024)',
                      default=5022,
                      type='int')
    parser.add_option('-r', '--pass-rate',
                      action='store',
                      dest='passrate',
                      help='Chance (between 0 and 1.0) to allow an auth attempt to succeed',
                      default=0.5,
                      type='float')
    (options, args) = parser.parse_args(sys.argv)

    log.startLogging(sys.stdout)

    components.registerAdapter(HoneypotSession, SSHAvatar, session.ISession)
    portal = portal.Portal(SSHRealm())
    portal.registerChecker(RandomPassChecker(options.passrate))
    SimpleSSHFactory.portal = portal

    reactor.listenTCP(options.port, SimpleSSHFactory())
    reactor.run()

