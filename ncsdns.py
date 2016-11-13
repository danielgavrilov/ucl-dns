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

def update_cnamecache(cname_records, ref_time):
  for record in cname_records:
    domain, cname, ttl = record._dn, record._cname, record._ttl
    new_entry = CnameCacheEntry(cname,
                                expiration=ttl + ref_time,
                                authoritative=True)

    if domain not in cnamecache or \
       cnamecache[domain]._expiration < new_entry._expiration:
      cnamecache[domain] = new_entry

def get_cnamecache(domain, ref_time):
  results = []
  if domain in cnamecache:
    entry = cnamecache[domain]
    if entry._expiration > ref_time:
      results.append(RR_CNAME(domain, entry._expiration - ref_time, cname))
    else:
      del cnamecache[domain]
  return results

def update_acache(a_records, ref_time):
  for record in a_records:
    domain, ttl = record._dn, record._ttl
    addr = InetAddr.fromNetwork(record._addr)
    new_entry = CacheEntry(expiration=ttl + ref_time,
                           authoritative=True)

    if domain not in acache:
      acache[domain] = ACacheEntry(dict([(addr, new_entry)]))
    elif addr not in acache[domain]._dict or \
         acache[domain]._dict[addr]._expiration < new_entry._expiration:
      acache[domain]._dict[addr] = new_entry

def get_acache(a_records, ref_time):
  results = []
  if domain in acache:
    for addr, entry in acache[domain]._dict.iteritems():
      if entry._expiration > ref_time:
        results.append(RR_A(domain, entry._expiration - ref_time, addr))
      else:
        del acache[domain]._dict[addr]
  return results

def update_nscache(ns_records, ref_time):
  for record in ns_records:
    domain, nsdn, ttl = record._dn, record._nsdn, record._ttl
    new_entry = CacheEntry(expiration=ttl + ref_time,
                           authoritative=True)

    if domain not in nscache:
      nscache[domain] = OrderedDict([(nsdn, new_entry)])
    elif nsdn not in nscache[domain] or \
         nscache[domain][nsdn]._expiration < new_entry._expiration:
      nscache[domain][nsdn] = new_entry

def get_nscache(domain, ref_time):
  results = []
  while len(results) == 0:
    if domain in nscache:
      for nsdn, entry in nscache[domain].iteritems():
        if entry._expiration > ref_time:
          results.append(RR_NS(domain, entry._expiration - ref_time, nsdn))
        else:
          del nscache[domain][nsdn]
    domain = domain.parent()
  return results

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

def ask_server(domain, dns_ip):

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
  if response.header._id != id:
    logger.log(DEBUG2, "Ignored packet with mismatching id.")
  # discard packets which are not responses
  elif response.header._qr == 0:
    logger.log(DEBUG2, "Ignored packet which is not a response.")
  # discard packets which have an altered question compared to the query
  elif response.question._dn != domain or response.question._type != QE.TYPE_A:
    logger.log(DEBUG2, "Ignored packet which has altered question.")
  else:
    return response

def replace_dn(domain, lst):
  def replace_single(rr):
    rr_copy = copy(rr)
    rr_copy._dn = domain
    return rr_copy
  return map(replace_single, lst)

def query(domain, dns_ip=ROOTNS_IN_ADDR, begin=None, result=None):

  if begin is None: begin = time()
  if result is None: result = { "answers": [], "nameservers": [], "additional": [] }

  retries = 0

  while True:

    if time() > (begin + MAX_QUERY_TIME):
      logger.log(DEBUG2, "Exceeded maximum query time.")
      break

    if retries > MAX_RETRIES:
      logger.log(DEBUG2, "Excedded maximum retries.")
      break

    try:

      d = ask_server(domain, dns_ip)

      if d is None:
        retries -= 1
        continue

      retries = 0

      answer_records =       filter(lambda x: domain == x._dn, d.answers)
      answer_a_records =     filter(lambda x: isinstance(x, RR_A), answer_records)
      answer_cname_records = filter(lambda x: isinstance(x, RR_CNAME), answer_records)
      ns_records =           filter(lambda x: isinstance(x, RR_NS) and is_part_of(domain, x._dn), d.nameservers)
      additional_a_records = filter(lambda x: isinstance(x, RR_A), d.additional)

      update_acache(additional_a_records + answer_a_records, ref_time=begin)
      update_cnamecache(answer_cname_records, ref_time=begin)
      update_nscache(ns_records, ref_time=begin)

      pp.pprint(acache)
      pp.pprint(cnamecache)
      pp.pprint(nscache)

      if answer_a_records:
        result['answers'] += answer_a_records
        return Message(answers=answer_a_records,
                       nameservers=ns_records,
                       additional=d.additional)

      if answer_cname_records:
        result['answers'] += answer_cname_records
        for record in answer_cname_records:
          q = query(record._cname, ROOTNS_IN_ADDR, begin)
          if q:
            return q

      for ns in ns_records:

        a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, additional_a_records)

        if not a_records_for_ns:
          dns_query = query(ns._nsdn, ROOTNS_IN_ADDR, begin)
          if dns_query:
            a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, dns_query.answers)

        result['nameservers'] += a_records_for_ns

        for a_record in a_records_for_ns:
          new_dns_ip = inet_ntoa(a_record._addr)
          q = query(domain, new_dns_ip, begin)
          # if successfully resolved, return result
          # otherwise, keep iterating thourgh nameservers
          if q:
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

  q = query(question._dn)

  if q:
    message = Message(question=question,
                      answers=q.answers,
                      nameservers=q.nameservers,
                      additional=q.additional)
    message.generate_header(d.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_NOERR,
                            qr=True)
    reply = message.pack()
  else:
    message = Message(question=question)
    message.generate_header(d.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_SRVFAIL,
                            qr=True)
    reply = message.pack()

  logger.log(DEBUG2, "our reply in full:")
  logger.log(DEBUG2, hexdump(reply))

  ss.sendto(reply, address)
