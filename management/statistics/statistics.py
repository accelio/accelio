#!/usr/bin/env python

# Copyright (c) 2013 Mellanox Technologies (r). All rights reserved.
#
# This software is available to you under a choice of one of two licenses.
# You may choose to be licensed under the terms of the GNU General Public
# License (GPL) Version 2, available from the file COPYING in the main
# directory of this source tree, or the Mellanox Technologies (r) BSD license
# below:
#
#      - Redistribution and use in source and binary forms, with or without
#        modification, are permitted provided that the following conditions
#        are met:
#
#      - Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
#      - Neither the name of the Mellanox Technologies (r) nor the names of its
#        contributors may be used to endorse or promote products derived from
#        this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__author__ = "Shlomo Pongratz"
__copyright__ = "Copyright (c) 2013 Mellanox Technologies (r). All rights reserved."
__credits__ = ["Shlomo Pongratz"]
__license__ = "Dual BSD/GPL"
__version__ = "1.0"
__maintainer__ = "Eyal Salomon"
__email__ = ["shlomop@mellanox.com", "esalomon@mellanox.com"]
__status__ = "Development"

import os
import sys
import socket
import select
import time
import struct
from struct import Struct
import ctypes
from ctypes.util import find_library
import copy

class UnknownMessage(Exception):
    pass

class NoFormat(Exception):
    pass

NLMSG_ERROR = 2
NLMSG_MIN_TYPE = 0x10

# From <sys/timerfd.h>
TFD_CLOEXEC = 02000000
TFD_NONBLOCK = 04000

# From <linux/time.h>
CLOCK_REALTIME = 0
CLOCK_MONOTONIC = 1
CLOCK_PROCESS_CPUTIME_ID = 2
CLOCK_THREAD_CPUTIME_ID = 3
CLOCK_MONOTONIC_RAW = 4
CLOCK_REALTIME_COARSE = 5
CLOCK_MONOTONIC_COARSE = 6

XIO_STAT_TX_MSG = 0
XIO_STAT_RX_MSG = 1
XIO_STAT_TX_BYTES = 2
XIO_STAT_RX_BYTES = 3
XIO_STAT_DELAY = 4
XIO_STAT_APPDELAY = 5

XIO_NETLINK_MCAST_GRP_ID = 4

def align(l, alignto=4):
    return (l + alignto - 1) & ~(alignto - 1)


class Nlh(object):
    #struct nlmsghdr {
    #   __u32 nlmsg_len;    /* Length of message including header. */
    #   __u16 nlmsg_type;   /* Type of message content. */
    #   __u16 nlmsg_flags;  /* Additional flags. */
    #   __u32 nlmsg_seq;    /* Sequence number. */
    #   __u32 nlmsg_pid;    /* PID of the sending process. */
    #};
    nlmsghdr = Struct("IHHII")

    def __init__(self, nlmsg_len=0, nlmsg_type=0, nlmsg_flags=0, nlmsg_seq=-1, nlmsg_pid = 0):
        """Used for creating Netlink messages."""
        self.nlmsg_len   = nlmsg_len
        self.nlmsg_type  = nlmsg_type
        self.nlmsg_flags = nlmsg_flags
        self.nlmsg_seq   = nlmsg_seq
        self.nlmsg_pid   = nlmsg_pid

    @classmethod
    def unpack(cls, msg):
        """Unpack raw bytes into a Netlink message."""
        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = cls.nlmsghdr.unpack(msg[:cls.nlmsghdr.size])
        #This is the process pid set in the message itself
        return Nlh(nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid)

    def __len__(self):
        """Aligned length of service template message + attributes."""
        return align(self.nlmsghdr.size)

    def pack(self):
        return self.nlmsghdr.pack(len(self), self.nlmsg_type, self.nlmsg_flags, self.nlmsg_seq, self.nlmsg_pid)

class Payload(object):
    """Base class for Netlink message payloads_cls."""

    def __init__(self, pid, ttid):
        self.message = None
        self.pid  = pid
        self.ttid = ttid

    @classmethod
    def unpack(cls, msg, pid, ttid):
        print "Can't unpack base class Payload (%s)" % msg

    def report(self):
        return

    def header(self):
        return

    def set_message(self, message):
        self.message = message

    def get_message(self):
        return self.message

class Format(Payload):
    """Used for formating Statistics messages."""

    #Cycles' Hertz and initial timestamp
    formathdr = Struct("QQ")

    def __init__(self, pid, ttid, hertz, timestamp, fields, bases):
        super(Format, self).__init__(pid, ttid)
        self.hertz       = hertz
        self.f_hertz     = 1.0 * hertz
        self.fields      = ["PID", "TID"] + fields
        #For printing the header itself
        self.fmt      = '%11s'   * (len(fields) + 2)
        #for printing the stats
        self.stat_fmt = '%11u%11u' + '%10.3f%s' * len(fields)
        #For decoding the stats, extra Q for timestamp
        self.stathdr = Struct('Q' * (len(fields) + 1))
        self.bases = bases

    @staticmethod
    def guess_bases(fields):
        bases = []
        for i in range(len(fields)):
            if fields[i].lower().find("delay") != -1:
                bases.append(1)
            elif fields[i].lower().find("byte") != -1:
                bases.append(1024)
            else:
                bases.append(1000)
        return bases

    @classmethod
    def unpack(cls, msg, pid, ttid):
        """Unpack hertz, initial timestamp and formats."""

        hertz, timestamp = cls.formathdr.unpack(msg[:cls.formathdr.size])
        #Null termitated strings (except last)
        fields = msg[cls.formathdr.size:].split('\0')
        bases = cls.guess_bases(fields)
        #This is the process pid set in the message itself
        fmt = Format(pid, ttid, hertz, timestamp, fields, bases)
        Message.set_payload(Message.FORMAT, ttid, fmt)
        #Counters are reset to zero when format is requested
        stats = Statistics(pid, ttid, fmt, timestamp, [0] * len(fields))
        Message.set_payload(Message.STATS, ttid, stats)
        return fmt

    def report(self):
        if not self.message.tids_per_pid.has_key(self.pid):
            self.message.tids_per_pid[self.pid] = []
        self.message.tids_per_pid[self.pid].append(self.ttid)

    def header(self):
        #Pass CLI prompt"
        #print "number of threads %d" % len(self.message.tids_per_pid[self.pid])
        print self.fmt % tuple(self.fields)

class Statistics(Payload):
    """Used for creating Statistics messages."""

    symbols = []
    symbols.append(' ') #None
    symbols.append('K') #Kilo
    symbols.append('M') #Mega
    symbols.append('G') #Giga
    symbols.append('T') #Tera
    symbols.append('P') #Peta
    symbols.append('E') #Exa
    symbols.append('Z') #Zetta
    symbols.append('Y') #Yota
    nsymbols = []
    nsymbols.append('s') #Second
    nsymbols.append('m') #Mili
    nsymbols.append('u') #Micro
    nsymbols.append('n') #Nano
    nsymbols.append('p') #Pico
    nsymbols.append('f') #Femto
    nsymbols.append('a') #Atto
    nsymbols.append('z') #Zepto
    nsymbols.append('y') #Yocto

    cls_reported_seq = -1

    def __init__(self, pid, ttid, msg_format, timestamp, fields):
        """Used for creating Statistics messages."""
        super(Statistics, self).__init__(pid, ttid)
        self.msg_format = msg_format
        self.timestamp = timestamp
        self.fields = fields

    @classmethod
    def unpack(cls, msg, pid, ttid):
        """Unpack raw bytes into a Statistics."""
        msg_format = Message.get_payload(Message.FORMAT, ttid)
        if msg_format == None:
            raise NoFormat
        stathdr = msg_format.stathdr
        fields = list(stathdr.unpack(msg[:stathdr.size]))
        return Statistics(pid, ttid, msg_format, fields[0], fields[1:])

    def normelize(self, deltas, seconds, f_hertz):
        result = []
        for i in range(len(deltas)):
            index = 0
            base = self.msg_format.bases[i]
            value = deltas[i]
            if base == 1:
                value /= f_hertz
                #Time
                if value > 0:
                    while value < 1:
                        value *= 1000
                        index += 1
                symbol = self.nsymbols[index]
            else:
                value /= seconds
                while value >= base:
                    value /= base
                    index += 1

                if base == 1024:
                    symbol = self.symbols[index].upper()
                else:
                    symbol = self.symbols[index].lower()

            result.append(value)
            result.append(symbol)

        return result

    def report(self):
        if self.msg_format == None:
            print "Error no message format!!!!"
            return

        prev = Message.get_payload(Message.STATS, self.ttid)
        if prev == None:
            print "Error format should have created a default prev!!!!"
            return

        f_hertz = self.msg_format.f_hertz

        ts_duration = self.timestamp - prev.timestamp

        seconds = ts_duration / f_hertz
        if (seconds == 0):
            print "Null duration\n"
            return

        deltas = []
        # Wikipedia "minuend - subtrahend = difference"
        for (minuend, subtrahend) in zip(self.fields, prev.fields):
            deltas.append(minuend - subtrahend)

        #Delays are caluculated per message
        if deltas[XIO_STAT_RX_MSG] > 0:
            div1 = 1.0 * deltas[XIO_STAT_RX_MSG]
        else:
            div1 = 1.0

        if deltas[XIO_STAT_TX_MSG] > 0:
            div2 = 1.0 * deltas[XIO_STAT_TX_MSG]
        else:
            div2 = 1.0

        deltas[XIO_STAT_DELAY]    /= div1
        deltas[XIO_STAT_APPDELAY] /= div2

        ndeltas = self.normelize(deltas, seconds, f_hertz)

        #Print header only once per seq (MT)
        if Statistics.cls_reported_seq != self.message.nlh.nlmsg_seq:
            self.msg_format.header()
            Statistics.cls_reported_seq = self.message.nlh.nlmsg_seq

        print self.msg_format.stat_fmt % tuple([self.message.nlh.nlmsg_pid, self.ttid] + ndeltas)

        Message.set_payload(Message.STATS, self.ttid, self)

class Message(object):
    """Object representing the entire Netlink message."""
    FORMAT = NLMSG_MIN_TYPE
    STATS  = NLMSG_MIN_TYPE + 1

    #There are two types of payloads_cls
    payloads_cls = []
    for i in range(STATS + 1):
        payloads_cls.append(None)
    payloads_cls[FORMAT] = Format
    payloads_cls[STATS]  = Statistics

    #Per ttid payloads, field names and previous stat of tid for delta compute
    payloads = []
    for i in range(STATS + 1):
        payloads.append({})

    tids_per_pid = {}

    def __init__(self, nlh, ttid, payload=None):
        """Used for creating Netlink messages. RX path"""
        self.nlh     = nlh
        self.ttid    = ttid
        self.payload = payload

    @classmethod
    def new(cls, nlmsg_type, payload=None):
        nlh = Nlh(nlmsg_type=nlmsg_type)
        return Message(nlh, 0, payload)

    @classmethod
    def unpack(cls, msg, ttid):
        """Unpack raw bytes into a Netlink message. RX path"""
        nlh = Nlh.unpack(msg)

        if Message.payloads_cls[nlh.nlmsg_type] == None:
            print "Unknown msg type %d" % nlh.nlmsg_type
            raise "UnknownMessage"

        #nlmsg_len includes the nlh size itself
        pcls = Message.payloads_cls[nlh.nlmsg_type]
        try:
            payload = pcls.unpack(msg[len(nlh):nlh.nlmsg_len], nlh.nlmsg_pid, ttid)
        except Exception, e:
            print "Payload unpack failed"
            print type(e)
            print str(e)
            raise
        else:
            message = Message(nlh, ttid, payload)
            payload.set_message(message)

        return message

    def pack_header(self):
        return self.nlh.pack()

    def pack(self):
        return self.pack_header()

    def report(self):
        if self.payload == None:
            print "Nothing to report"
            return

        self.payload.report()

    @classmethod
    def set_payload(cls, nlmsg_type, ttid, payload):
        cls.payloads[nlmsg_type][ttid] = payload

    @classmethod
    def get_payload(cls, nlmsg_type, ttid):
        if cls.payloads[nlmsg_type].has_key(ttid):
            return cls.payloads[nlmsg_type][ttid]
        else:
            return None

class Connection(object):
    """
    Object representing Netlink socket connection to accelio.
    """
    # socket.NETLINK_GENERIC missing
    def __init__(self, loop, nlservice=16, groups=0):
        self.loop = loop
        # nlservice = Netlink IP service
        try:
            self.fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, nlservice)
        except socket.herror, msg:
            print msg
            sys.exit(0)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        self.fd.bind((os.getpid(), groups))
        self.pid, self.groups = self.fd.getsockname()
        self._seq = [0] * 32

    def send(self, msg, to, group):
        if isinstance(msg, Message):
            if msg.nlh.nlmsg_seq == -1:
                msg.nlh.nlmsg_seq = self.seq(group)
            msg.nlh.nlmsg_pid = self.pid
            msg = msg.pack()
        self.fd.sendto(msg, (to, group))

    def recv(self):
        contents, (nlpid, nlgrps) = self.fd.recvfrom(16384)
        #This is the thread pid (nl socket source address)
        try:
            resp = Message.unpack(contents, nlpid)
        except UnknownMessage:
            raise
        except NoFormat:
            #print "Send UC to %d" % nlpid
            #Can't use this message need to solicit UC request
            msg = Message.new(Message.FORMAT)
            #Send UC message to sender of the statistics
            self.send(msg, nlpid, 0)
            raise
        except:
            raise
        else:
            return resp

    def seq(self, group):
        self._seq[group] += 1
        return self._seq[group]

    def fileno(self):
        return self.fd.fileno()

    def callback(self):
        try:
            resp = self.recv()
        except UnknownMessage:
            print "UnknownMessage"
        except NoFormat:
            print "NoFormat"
        except Exception, e:
            print "Unknown error on netlink receive"
            print type(e)
            print str(e)
        else:
            resp.report()
        finally:
            self.loop.callback_done(self.fileno())

class Cli(object):
    """Handles user interaction."""

    def __init__(self, loop, fd=sys.stdin):
        self.loop = loop
        self.fd = fd

    def recv(self):
        line = self.fd.readline()
        if line.find("exit") != -1:
            self.send("exiting!!")
            sys.exit(0)

    def callback(self):
        self.recv()
        self.loop.callback_done(self.fileno())

    def send(self, line):
        print line

    def prompt(self):
        sys.stderr.write("\n>")

    def fileno(self):
        return self.fd.fileno()

class timespec(ctypes.Structure):
    """
    A struct that is passed in to all blowfish operations.
    struct timespec {
        time_t tv_sec;                /* Seconds */
        long   tv_nsec;               /* Nanoseconds */
    };
    """
    _fields_ = [ ("tv_sec",  ctypes.c_long),\
                 ("tv_nsec", ctypes.c_long) ]

    def __str__(self):
        return '{ tv_sec : %s, tv_nsec : %s }' %( self.tv_sec, self.tv_nsec )

class itimerspec(ctypes.Structure):
    '''
    A struct for the timers.
    struct itimerspec {
        struct timespec it_interval;  /* Interval for periodic timer */
        struct timespec it_value;     /* Initial expiration */
    };
    '''
    _fields_ = [ ('it_interval', timespec ),\
                 ('it_value', timespec) ]

    def __str__(self):
        return '{ it_interval : %s, it_value : %s }' %( self.it_interval, self.it_value )

class Timer(object):
    def __init__(self, loop, interval=10):
        self.loop = loop
        self.interval = interval
        self.fd = libc.timerfd_create(ctypes.c_int(CLOCK_MONOTONIC),
                                      ctypes.c_int(TFD_NONBLOCK | TFD_CLOEXEC))
        if self.fd < 0:
            print "timerfd creation failed"
            return None

    def do_arm(self, interval):
            if interval != self.interval:
                self.inerval = interval
            new_value = itimerspec()
            old_value = itimerspec()
            new_value.it_value.tv_sec = interval
            rval = libc.timerfd_settime( self.fd, 0,
                                        ctypes.byref(new_value),
                                        ctypes.byref(old_value) )
    def arm(self):
        self.do_arm(self.interval)

    def rearm(self):
        self.do_arm(self.interval)

    def disarm(self):
        self.do_arm(0)

    def fileno(self):
        return self.fd

    def callback(self):
        self.rearm()
        self.loop.callback_done(self.fileno())


class Loop(object):
    def __init__(self):
        self.state = 0
        self.cli   = Cli(self)
        self.timer = Timer(self)
        self.conn  = Connection(self)
        self.fd_cb = {}
        self.done_cb = {}
        self.fd_cb[self.cli.fileno()] = self.cli
        self.fd_cb[self.conn.fileno()] = self.conn
        self.fd_cb[self.timer.fileno()] = self.timer
        self.done_cb[self.cli.fileno()] = self.cli_done
        self.done_cb[self.conn.fileno()] = self.conn_done
        self.done_cb[self.timer.fileno()] = self.timer_done
        self.formats = {}

        self.epoll = select.epoll()
        for fd in self.fd_cb.keys():
            self.epoll.register(fd, select.EPOLLIN)
        #Send first message requesting counters' name
        msg = Message.new(Message.FORMAT)
        #Send MC message
        self.conn.send(msg, 0, XIO_NETLINK_MCAST_GRP_ID)

    def cli_done(self):
        self.cli.prompt()

    def conn_done(self):
        self.cli.prompt()

    def timer_done(self):
        #Send periodic message requesting for counters
        msg = Message.new(Message.STATS)
        #Send MC message
        self.conn.send(msg, 0, XIO_NETLINK_MCAST_GRP_ID)

    def callback_done(self, fileno):
        if fileno in self.done_cb:
            self.done_cb[fileno]()
        else:
            print fileno, ' callback_done not registered!'

    def run(self):
        self.cli.prompt()
        self.timer.arm()
        while True:
            events = self.epoll.poll(1) # Timeout 1 second
            #print 'Polling %d events' % len(events)
            for fileno, event in events:
                if fileno in self.fd_cb:
                    obj = self.fd_cb[fileno]
                    obj.callback()
                else:
                    print fileno, ' callback not registered!'

if __name__ == '__main__':

    #need timerfd, no python binding yet
    try:
        libc_name = find_library("c")
    except Exception, e:
        print "Can't find libc check path environment argument"
        print type(e)
        print str(e)
        sys.exit(0)
    else:
        print "Found %s" % libc_name

    try:
        libc = ctypes.cdll.LoadLibrary(libc_name)
    except Exception, e:
        print "Can't load libc"
        print type(e)
        print str(e)
        sys.exit(0)
    else:
        print "Sucessfuly loaded %s" % libc_name

    loop = Loop()
    loop.run()
