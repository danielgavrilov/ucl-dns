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
MAX_QUERY_TIME = 60

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

# Updates nscache with the given NS records.
# Does not overwrite entries with greater TTL.
def update_nscache(ns_records, ref_time):
  for record in ns_records:
    domain, nsdn, ttl = record._dn, record._nsdn, record._ttl
    if ttl == 0: continue # do not cache records with 0 TTL
    new_entry = CacheEntry(expiration=ttl + long(ref_time),
                           authoritative=True)
    if domain not in nscache:
      nscache[domain] = OrderedDict([(nsdn, new_entry)])
    elif nsdn not in nscache[domain] or \
         nscache[domain][nsdn]._expiration < new_entry._expiration:
      nscache[domain][nsdn] = new_entry

# Returns the NS records in nscache matching the given domain (and have
# not expired). The returned records have an adjusted TTL according to
# the elapsed time since they were inserted.
def get_nscache(domain, ref_time):
  results = []
  while len(results) == 0:
    if domain in nscache:
      for nsdn, entry in nscache[domain].iteritems():
        if entry._expiration > ref_time:
          results.append(
            RR_NS(domain, entry._expiration - long(ref_time), nsdn))
    domain = domain.parent()
  return results

# Updates acache with the given A records.
# Does not overwrite entries with greater TTL.
def update_acache(a_records, ref_time):
  for record in a_records:
    domain, ttl = record._dn, record._ttl
    addr = InetAddr.fromNetwork(record._addr)
    if ttl == 0: continue # do not cache records with 0 TTL
    new_entry = CacheEntry(expiration=ttl + long(ref_time),
                           authoritative=True)

    if domain not in acache:
      acache[domain] = ACacheEntry(dict([(addr, new_entry)]))
    elif addr not in acache[domain]._dict or \
         acache[domain]._dict[addr]._expiration < new_entry._expiration:
      acache[domain]._dict[addr] = new_entry

# Returns the A records in acache matching the given domain (and have
# not expired). The returned records have an adjusted TTL according to
# the elapsed time since they were inserted.
def get_acache(domain, ref_time):
  results = []
  if domain in acache:
    for addr, entry in acache[domain]._dict.iteritems():
      if entry._expiration > ref_time:
        results.append(
          RR_A(domain, entry._expiration - long(ref_time), addr.toNetwork()))
  return results

# Updates cnamecache with the given CNAME records.
# Does not overwrite entries with greater TTL.
def update_cnamecache(cname_records, ref_time):
  for record in cname_records:
    domain, cname, ttl = record._dn, record._cname, record._ttl
    if ttl == 0: continue # do not cache records with 0 TTL
    new_entry = CnameCacheEntry(cname,
                                expiration=ttl + long(ref_time),
                                authoritative=True)

    if domain not in cnamecache or \
       cnamecache[domain]._expiration < new_entry._expiration:
      cnamecache[domain] = new_entry

# Returns the CNAME records in cnamecache matching the given domain (and have
# not expired). The returned records have an adjusted TTL according to
# the elapsed time since they were inserted.
def get_cnamecache(domain, ref_time):
  results = []
  if domain in cnamecache:
    entry = cnamecache[domain]
    if entry._expiration > ref_time:
      results.append(
        RR_CNAME(domain, entry._expiration - long(ref_time), entry._cname))
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

# Returns a random 16-bit ID for DNS message header (0-65535)
def rand_id():
  return randint(0, (1 << 16) - 1) # 1 << 16 == 2**16

# Determines whether the first domain name is the same as OR
# a child of the second.
def is_subdomain_of(child, parent):
  while child != None:
    if child == parent:
      return True
    child = child.parent()
  return False

# For a given domain, it returns a dictionary of:
# - the cached A and CNAME records as "answers"
# - the NS records as "nameservers"
def get_cache(domain, ref_time):
  answers = get_acache(domain, ref_time) + get_cnamecache(domain, ref_time)
  nameservers = get_nscache(domain, ref_time)
  return {
    "answers": answers,
    "nameservers": nameservers
  }

# Given an RR (A, CNAME or NS), it returns a tuple of 3 items that uniquely TODO
# Used to identify duplicate records.
def tuple_from_record(record):
  last = None
  if hasattr(record, "_addr"):
    last = record._addr
  elif hasattr(record, "_nsdn"):
    last = record._nsdn
  elif hasattr(record, "_cname"):
    last = record._cname
  return (record._type, record._dn, last)

# Given a list of records (A, CNAME or NS), it removes duplicates, keeping the
# ones with the highest TTL.
def discard_dup_records(records):
  # sorting by descending TTL ensures that any duplicates occurring will be of
  # lower or equal TTL.
  records = sorted(records, key=lambda x: x._ttl, reverse=True)
  seen = set()
  results = []
  for record in records:
    t = tuple_from_record(record)
    if t not in seen:
      results.append(record)
      seen.add(t)
  return results

# Given a domain and a list of NS records, it returns the highest qualified NS
# records for the domain.
def get_highest_qualified(domain, ns_records):
  results = []
  while len(results) == 0 and domain != DomainName("."):
    results += filter(lambda x: x._dn == domain, ns_records)
    domain = domain.parent()
  return discard_dup_records(results)

def get_glue_records(ns_records, a_records, ref_time):
  results = []
  for ns in ns_records:
    glue_records = filter(lambda x: ns._nsdn == x._dn, a_records) \
                 + get_acache(ns._nsdn, ref_time)
    results += glue_records
  return discard_dup_records(results)

def get_glued(ns_records, a_records):
  results = []
  for ns in ns_records:
    glue_records = filter(lambda x: ns._nsdn == x._dn, a_records)
    results.append((ns, glue_records))
  return sorted(results, key=lambda x: len(x[1]), reverse=True)

def dict_append(dst, src):
  for key, lst in src.iteritems():
    dst[key] += lst
  return dst

def ask_server(domain, dns_ip):

  id = rand_id()
  message = Message(question=QE(dn=domain))
  message.generate_header(id,
                          Header.OPCODE_QUERY,
                          Header.RCODE_NOERR)
  message_data = message.pack()

  print "\n=============================================================================\n"

  print "QUERY TO %s:\n" % dns_ip
  print message

  cs.sendto(message_data, (dns_ip, DNS_PORT))
  response_data, address = cs.recvfrom(512)

  response = None

  # In case message cannot be parsed
  try:
    response = Message.fromData(response_data)
    str(response)
  except:
    logger.log(DEBUG2, "Ignored corrupted message.")
    return None

  print "\nRESPONSE:\n"
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

def resolver(domain, begin=None, answers=None, nameservers=None, additional=None, aggregate=None):

  if begin is None: begin = time()
  if answers is None: answers = []
  if nameservers is None: nameservers = []
  if additional is None: additional = []

  cache = get_cache(domain, ref_time=begin)

  answers = discard_dup_records(answers + cache["answers"])
  nameservers = discard_dup_records(nameservers + cache["nameservers"])
  additional = get_glue_records(nameservers, additional, ref_time=begin)

  if aggregate is None:
    aggregate = {
      "answers": answers,
      "nameservers": nameservers,
      "additional": additional
    }
  else:
    dict_append(aggregate, { "answers": answers,
                             "nameservers": nameservers,
                             "additional": additional })

  answer_a_records =     filter(lambda x: isinstance(x, RR_A), answers)
  answer_cname_records = filter(lambda x: isinstance(x, RR_CNAME), answers)

  if answer_a_records:
    aggregate_answers = discard_dup_records(aggregate["answers"])
    highest_qualified = get_highest_qualified(domain, aggregate["nameservers"])
    glue_records = get_glue_records(highest_qualified, additional, ref_time=begin)
    return {
      "answers": aggregate_answers,
      "nameservers": highest_qualified,
      "additional": glue_records
    }

  if answer_cname_records:
    for record in answer_cname_records:
      q = resolver(record._cname, begin=begin)
      if q:
        q["answers"] = [record] + q["answers"]
        return q

  for ns, a_records_for_ns in get_glued(nameservers, additional):

    if not a_records_for_ns:
      dns_query = resolver(ns._nsdn, begin=begin)
      if dns_query:
        a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, dns_query["answers"])

    dns_ips = map(lambda x: inet_ntoa(x._addr), a_records_for_ns)
    q = query(domain, begin=begin, dns_ips=dns_ips)
    # if successfully resolved, return result
    # otherwise, keep iterating thourgh nameservers
    if q:
      dict_append(aggregate, q)
      return resolver(domain, begin=begin,
                              answers=q["answers"],
                              nameservers=q["nameservers"],
                              additional=q["additional"],
                              aggregate=aggregate)

class ExceededMaxQueryTime(Exception):
  pass

class ExceededMaxRetries(Exception):
  pass

def query(domain, begin, dns_ips=[], aggregate=None):

  retries = 0
  ith_dns_ip = 0
  done = False

  while True:
    if retries > MAX_RETRIES:
      raise ExceededMaxRetries
    if time() > (begin + MAX_QUERY_TIME):
      raise ExceededMaxQueryTime
    try:
      print ith_dns_ip
      dns_ip = dns_ips[ith_dns_ip]
      response = ask_server(domain, dns_ip)
      if response is None:
        retries += 1
        ith_dns_ip = (ith_dns_ip + 1) % len(dns_ips)
      else:
        retries = 0
        break
    except timeout:
      retries += 1

  answer_records =       filter(lambda x: domain == x._dn, response.answers)
  answer_a_records =     filter(lambda x: isinstance(x, RR_A), answer_records)
  answer_cname_records = filter(lambda x: isinstance(x, RR_CNAME), answer_records)
  ns_records =           filter(lambda x: isinstance(x, RR_NS) and is_subdomain_of(domain, x._dn), response.nameservers)
  additional_a_records = filter(lambda x: isinstance(x, RR_A), response.additional)

  update_acache(answer_a_records + additional_a_records, ref_time=begin)
  update_cnamecache(answer_cname_records, ref_time=begin)
  update_nscache(ns_records, ref_time=begin)

  return {
    "answers": answer_records,
    "nameservers": ns_records,
    "additional": additional_a_records
  }

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (data, address) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("Client provided no data.")
    continue

  reply = ""
  d = Message.fromData(data)
  question = d.question

  if not question:
    log.error("Client provided no question.")
    continue

  try:
    q = resolver(question._dn)
  except ExceededMaxQueryTime:
    q = None
    log.error("Exceeded maximum query time.")
  except ExceededMaxRetries:
    q = None
    log.error("Exceeded maximum retries.")

  if q:
    message = Message(question=question, **q)
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
