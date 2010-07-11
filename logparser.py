#!/usr/bin/env python

import re
import socket
import struct
import sqlite3
import sys

CMD_TYPE_ARGUMENT = 0
CMD_TYPE_BUFFER = 1

db = None

class SessionLog(object):
    id_map = {}

    def __init__(self, date, ip, conn_id):
        self.conn_id = int(conn_id)
        ip = struct.unpack('L', socket.inet_aton(ip))[0]
        self.conn_rowid = self.log_open(date, ip)

    @classmethod
    def new(cls, date, ip, conn_id):
        newlog = SessionLog(date, ip, conn_id)
        cls.id_map[newlog.conn_id] = newlog

    @classmethod
    def get(cls, conn_id):
        conn_id = int(conn_id)
        return cls.id_map[conn_id]

    @classmethod
    def rebuild_tables(cls):
        db.execute('DROP TABLE IF EXISTS connection')
        db.execute('DROP TABLE IF EXISTS auth_attempt')
        db.execute('DROP TABLE IF EXISTS command_attempt')
        db.execute('''
            CREATE TABLE connection (
                date INTEGER,
                ip INTEGER
            )''')
        db.execute('''
            CREATE TABLE auth_attempt (
                date INTEGER,
                username TEXT,
                password TEXT,
                conn INTEGER,
                FOREIGN KEY(conn) REFERENCES connection(rowid)
                
            )''')
        db.execute('''
            CREATE TABLE command_attempt (
                date INTEGER,
                command TEXT,
                type INTEGER,
                conn INTEGER,
                FOREIGN KEY(conn) REFERENCES connection(rowid)
            )''')

    def log_open(self, date, ip):
        cursor = db.execute('INSERT INTO connection VALUES (?, ?)', (
                            unicode(date), ip))
        db.commit()
        return cursor.lastrowid

    def log_auth_attempt(self, date, username, password):
        db.execute('INSERT INTO auth_attempt VALUES (?, ?, ?, ?)', (
                    unicode(date), unicode(username), unicode(password), self.conn_rowid))
        db.commit()

    def log_command_attempt(self, date, command, cmd_type):
        db.execute('INSERT INTO command_attempt VALUES (?, ?, ?, ?)', (
                    unicode(date), unicode(command), cmd_type, self.conn_rowid))
        db.commit()


NEW_CONNECTION = re.compile(r'^(?P<date>.+) \[.+,(?P<conn_id>\d+),(?P<ip>\d+\.\d+\.\d+\.\d+)\] starting service ssh\-userauth$')
AUTH_ATTEMPT = re.compile(r'^(?P<date>.+) \[.+,(?P<conn_id>\d+),.+username="(?P<username>.*)" password="(?P<password>.*)"$')
ARG_COMMAND = re.compile(r'^(?P<date>.+) \[.+,(?P<conn_id>\d+),.+b64 argument command: "(?P<cmd>.*)"$')
BUFFER_COMMAND = re.compile(r'^(?P<date>.+?) \[.+,(?P<conn_id>\d+),.+b64 buffer command: "(?P<cmd>.*)"$')

def cb_new_connection(**kwargs):
    SessionLog.new(kwargs['date'], kwargs['ip'], kwargs['conn_id'])

def cb_auth_attempt(**kwargs):
    SessionLog.get(kwargs['conn_id']).log_auth_attempt(
        kwargs['date'], kwargs['username'], kwargs['password'])

def cb_arg_command(**kwargs):
    SessionLog.get(kwargs['conn_id']).log_command_attempt(
        kwargs['date'], kwargs['cmd'], CMD_TYPE_ARGUMENT)

def cb_buffer_command(**kwargs):
    SessionLog.get(kwargs['conn_id']).log_command_attempt(
        kwargs['date'], kwargs['cmd'], CMD_TYPE_BUFFER)

callbacks = {
    NEW_CONNECTION: cb_new_connection,
    AUTH_ATTEMPT: cb_auth_attempt,
    ARG_COMMAND: cb_arg_command,
    BUFFER_COMMAND: cb_buffer_command,
}

def parse_line(line):
    for regex in callbacks:
        try:
            gdict = regex.search(line).groupdict()
            return callbacks[regex](**gdict)
        except AttributeError:
            pass

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option('-d', '--database',
                      action='store',
                      dest='dbfile',
                      help='Path to SQLite database',
                      default='honeypot.sqlite')
    parser.add_option('-c', '--clear',
                      action='store_true',
                      dest='cleardb',
                      help='Clear and rebuild database',
                      default=False)
    (options, args) = parser.parse_args(sys.argv)

    db = sqlite3.connect(options.dbfile)

    if options.cleardb:
        SessionLog.rebuild_tables()

    while True:
        line = sys.stdin.readline()
        if len(line) == 0:
            break
        parse_line(line)

    db.close()

