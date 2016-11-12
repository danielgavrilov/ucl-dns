#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

from custom.message import Message

# timeout in seconds to wait for reply
TIMEOUT = 5

# maximum time in seconds for a recursive DNS query
MAX_QUERY_TIME = 5

# max retries if a server is not responsive
MAX_RETRIES = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

# default DNS port
DNS_PORT = 53

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)

# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure;
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."),
            OrderedDict([(DomainName(ROOTNS_DN),
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))])

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

# generates a random ID for header (0-65535)
def rand_id():
  return randint(0, (1 << 16) - 1)

# determines whether the first domain name is the same as OR a child of the second
def is_part_of(child, parent):
  while child != None:
    if child == parent:
      return True
    child = child.parent()
  return False

# returns the first item in a list that satisfies the predicate
def find(fn, array):
  for i in array:
    if fn(i):
      return i
  return None

def ask_server(domain, dns_ip, retries=MAX_RETRIES):

  id = rand_id()
  message = Message(question=QE(dn=domain))
  message.generate_header(id,
                          Header.OPCODE_QUERY,
                          Header.RCODE_NOERR)
  message_data = message.pack()

  print "\nQuery to %s:" % dns_ip
  print message

  cs.sendto(message_data, (dns_ip, DNS_PORT))
  response_data, address = cs.recvfrom(512)
  response = Message.fromData(response_data)

  print "\nResponse:"
  print response

  # discard packets received with mismatching id
  if d.header._id != id:
    logger.log(DEBUG2, "Ignored packet with mismatching id.")
  # discard packets which are not responses
  elif d.header._qr == 0:
    logger.log(DEBUG2, "Ignored packet which is not a response.")
  # discard packets which have an altered question compared to the query
  elif d.question._dn != domain or d.question._type != QE.TYPE_A:
    logger.log(DEBUG2, "Ignored packet which has altered question.")
  else:
    return response

# def mul_query(domain, dns_ips, begin=None):
#   if begin is None: begin = time()
#   for dns_ip in dns_ips:
#     response = query(domain, dns_ip)
#     if response.is_successful_response():
#       return response
#   return None

def query(domain, dns_ip, begin=None):

  if begin is None: begin = time()

  retries = 0

  while True:

    if time() > (begin + MAX_QUERY_TIME):
      logger.log(DEBUG2, "Exceeded maximum query time.")
      break

    if retries > MAX_RETRIES:
      logger.log(DEBUG2, "Excedded maximum retries.")
      break

    try:

      id = rand_id()
      message = Message(question=QE(dn=domain))
      message.generate_header(id,
                              Header.OPCODE_QUERY,
                              Header.RCODE_NOERR)
      message = message.pack()

      print "\nQuery to %s:" % dns_ip
      print Message.fromData(message)

      cs.sendto(message, (dns_ip, DNS_PORT))
      data, address = cs.recvfrom(512)
      retries = 0
      d = Message.fromData(data)

      # discard packets received with mismatching id
      if d.header._id != id:
        logger.log(DEBUG2, "Ignored packet with mismatching id.")
        continue

      # discard packets which are not responses
      if d.header._qr == 0:
        logger.log(DEBUG2, "Ignored packet which is not a response.")
        continue

      print "\nResponse:"
      print Message.fromData(data)

      answer_records = filter(lambda x: domain == x._dn, d.answers)
      ns_records = filter(lambda x: is_part_of(domain, x._dn), d.nameservers)
      additional_a_records = filter(lambda x: isinstance(x, RR_A), d.additional)

      for answer in answer_records:
        if isinstance(answer, RR_A):
          return d
        elif isinstance(answer, RR_CNAME):
          return query(answer._cname, ROOTNS_IN_ADDR, begin)

      for ns in ns_records:

        a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, additional_a_records)

        if not a_records_for_ns:
          dns_query = query(ns._nsdn, ROOTNS_IN_ADDR, begin)
          a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, dns_query.answers)

        for a_record in a_records_for_ns:
          new_dns_ip = inet_ntoa(a_record._addr)
          q = query(domain, new_dns_ip, begin)
          # if successfully resolved, return result
          # otherwise, keep iterating thourgh nameservers
          if q.is_successful_response():
            return q

    except timeout:
      retries += 1
      logger.log(DEBUG2, "server timed out: " + ip)

  return None

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (data, address) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("client provided no data")
    continue

  reply = ""
  d = Message.fromData(data)

  print d
  question = d.question

  if not question:
    continue

  q = query(question._dn, ROOTNS_IN_ADDR)

  if q:
    message = Message(question=question, answers=q.answers)
    message.generate_header(d.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_NOERR,
                            qr=True)
    reply = message.pack()
  else:
    message = Message(question=quesiton)
    message.generate_header(d.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_SRVFAIL,
                            qr=True)
    reply = message.pack()

  logger.log(DEBUG2, "our reply in full:")
  logger.log(DEBUG2, hexdump(reply))

  ss.sendto(reply, address)
