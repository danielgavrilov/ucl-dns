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

# Timeout in seconds to wait for reply from server.
TIMEOUT = 2

# Maximum time in seconds for a recursive DNS query.
MAX_QUERY_TIME = 10

# Maximum retries if a server is not responsive.
MAX_RETRIES = 5

# Domain name and internet address of a root name server.
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

# Default DNS port.
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

def update_nscache(ns_records, ref_time):
  """
  Updates nscache with the given NS records.
  Does not overwrite entries with greater TTL.
  """
  for record in ns_records:
    domain, nsdn, ttl = record._dn, record._nsdn, record._ttl
    new_entry = CacheEntry(expiration=ttl + long(ref_time),
                           authoritative=True)
    if domain not in nscache:
      nscache[domain] = OrderedDict([(nsdn, new_entry)])
    elif nsdn not in nscache[domain] or \
         nscache[domain][nsdn]._expiration < new_entry._expiration:
      nscache[domain][nsdn] = new_entry

def get_nscache(domain, ref_time):
  """
  Returns the NS records in nscache matching the given domain (and have
  not expired). The returned records have an adjusted TTL according to
  the elapsed time since they were inserted.
  """
  results = []
  while len(results) == 0:
    if domain in nscache:
      for nsdn, entry in nscache[domain].iteritems():
        if entry._expiration > ref_time:
          results.append(
            RR_NS(domain, entry._expiration - long(ref_time), nsdn))
    domain = domain.parent()
  return results

def update_acache(a_records, ref_time):
  """
  Updates acache with the given A records.
  Does not overwrite entries with greater TTL.
  """
  for record in a_records:
    domain, ttl = record._dn, record._ttl
    addr = InetAddr.fromNetwork(record._addr)
    new_entry = CacheEntry(expiration=ttl + long(ref_time),
                           authoritative=True)

    if domain not in acache:
      acache[domain] = ACacheEntry(dict([(addr, new_entry)]))
    elif addr not in acache[domain]._dict or \
         acache[domain]._dict[addr]._expiration < new_entry._expiration:
      acache[domain]._dict[addr] = new_entry

def get_acache(domain, ref_time):
  """
  Returns the A records in acache matching the given domain (and have
  not expired). The returned records have an adjusted TTL according to
  the elapsed time since they were inserted.
  """
  results = []
  if domain in acache:
    for addr, entry in acache[domain]._dict.iteritems():
      if entry._expiration > ref_time:
        results.append(
          RR_A(domain, entry._expiration - long(ref_time), addr.toNetwork()))
  return results

def update_cnamecache(cname_records, ref_time):
  """
  Updates cnamecache with the given CNAME records.
  Does not overwrite entries with greater TTL.
  """
  for record in cname_records:
    domain, cname, ttl = record._dn, record._cname, record._ttl
    new_entry = CnameCacheEntry(cname,
                                expiration=ttl + long(ref_time),
                                authoritative=True)

    if domain not in cnamecache or \
       cnamecache[domain]._expiration < new_entry._expiration:
      cnamecache[domain] = new_entry

def get_cnamecache(domain, ref_time):
  """
  Returns the CNAME records in cnamecache matching the given domain (and have
  not expired). The returned records have an adjusted TTL according to
  the elapsed time since they were inserted.
  """
  results = []
  if domain in cnamecache:
    entry = cnamecache[domain]
    if entry._expiration > ref_time:
      results.append(
        RR_CNAME(domain, entry._expiration - long(ref_time), entry._cname))
  return results

def check_port(option, opt_str, value, parser):
  """Parse the command line and assign us an ephemeral port to listen on:"""
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

class Message:
  """Helper class for constructing a message"""

  def __str__(self):
    return "\n\n".join([repr(self.header),
      "QUESTION:\n" + pp.pformat(self.questions),
      "ANSWER:\n" + pp.pformat(self.answers),
      "AUTHORITY:\n" + pp.pformat(self.nameservers),
      "ADDITIONAL:\n" + pp.pformat(self.additional)])

  def __repr__(self):
    return str(self)

  def __init__(self, header=None, question=None, questions=[], answers=[], nameservers=[], additional=[]):
    self.header = header
    self.questions = [question] if question else questions
    self.answers = answers
    self.nameservers = nameservers
    self.additional = additional

  @property
  def question(self):
    return self.questions[0] if self.questions else None

  def generate_header(self, *args, **kwargs):
    if "qdcount" not in kwargs: kwargs["qdcount"] = len(self.questions)
    if "ancount" not in kwargs: kwargs["ancount"] = len(self.answers)
    if "nscount" not in kwargs: kwargs["nscount"] = len(self.nameservers)
    if "arcount" not in kwargs: kwargs["arcount"] = len(self.additional)
    self.header = Header(*args, **kwargs)
    return self.header

  def pack(self):
    items = [self.header] + self.questions + self.answers + self.nameservers + self.additional
    return "".join(map(lambda x: x.pack(), items))

  @staticmethod
  def parse_qds(data, offset, n):
    qds = []
    for i in range(n):
      qd = QE.fromData(data, offset)
      offset += len(qd)
      qds.append(qd)
    return (qds, offset)

  @staticmethod
  def parse_rrs(data, offset, n):
    rrs = []
    for i in range(n):
      (rr, length) = RR.fromData(data, offset)
      offset += length
      rrs.append(rr)
    return (rrs, offset)

  @staticmethod
  def fromData(data, offset=0):

    header = Header.fromData(data)
    offset += len(header)

    (questions, offset) = Message.parse_qds(data, offset, header._qdcount)

    rrs = {}

    for field in ["an", "ns", "ar"]:
      (rrs[field], offset) = \
        Message.parse_rrs(data, offset, getattr(header, "_" + field + "count"))

    return Message(header=header,
                   questions=questions,
                   answers=rrs["an"],
                   nameservers=rrs["ns"],
                   additional=rrs["ar"])

# Returns a random 16-bit ID for DNS message header (0-65535)
def rand_id():
  return randint(0, (1 << 16) - 1) # 1 << 16 == 2**16

def is_subdomain_of(child, parent):
  """
  Determines whether the first domain name is the same as OR
  a child of the second.
  """
  while child != None:
    if child == parent:
      return True
    child = child.parent()
  return False

def get_cache(domain, ref_time):
  """
  For a given domain and a time, it returns a tuple of:
  - the cached A and CNAME records for the domain
  - the cached NS records for the domain
  The time is specified in seconds since "the beginning of the world".
  """
  answers = get_acache(domain, ref_time) + get_cnamecache(domain, ref_time)
  nameservers = get_nscache(domain, ref_time)
  additional = get_glue_records(nameservers, ref_time)
  return (answers, nameservers, additional)

def tuple_from_record(record):
  """
  Given an RR (A, CNAME or NS), it returns a tuple of 3 items that is used to
  detect duplicate records.
  """
  last = None
  if hasattr(record, "_addr"):
    last = record._addr
  elif hasattr(record, "_nsdn"):
    last = record._nsdn
  elif hasattr(record, "_cname"):
    last = record._cname
  return (record._type, record._dn, last)

def discard_dup_records(records):
  """
  Given a list of records (A, CNAME or NS), it removes duplicates, keeping the
  ones with the highest TTL.
  """
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

def get_glue_records(ns_records, ref_time):
  """
  Given a list of NS records, another of A records and the time, it returns a
  list of glue records for the NS records. The time is specified in seconds
  since "the beginning of the world" and is used for querying the cache for A records.
  """
  results = []
  for ns in ns_records:
    results += get_acache(ns._nsdn, ref_time)
  return discard_dup_records(results)

def get_glued(ns_records, a_records):
  """
  Given a list of NS records and another of A records, it returns a list of
  tuples (ns_record, [a_records]), associating each NS record with its glue A records.
  """
  results = []
  for ns in ns_records:
    glue_records = filter(lambda x: ns._nsdn == x._dn, a_records)
    results.append((ns, glue_records))
  return sorted(results, key=lambda x: len(x[1]), reverse=True)

# Custom error classes

class DNSNameError(Exception):
  pass

class DNSExceededMaxQueryTime(Exception):
  pass

class DNSExceededMaxRetries(Exception):
  pass

def send_question(domain, dns_ip):
  """
  Sends a single A record "question" to the given dns_ip.
  If it fails for whateher reason, it immediately gives up and returns `None`,
  otherwise, it returns the message as a `Message` object.
  """

  id = rand_id()
  message = Message(question=QE(dn=domain))
  message.generate_header(id,
                          Header.OPCODE_QUERY,
                          Header.RCODE_NOERR)
  message_data = message.pack()

  print "\n=============================================================================\n"
  print "QUERY TO %s for domain %s" % (dns_ip, str(domain))

  cs.sendto(message_data, (dns_ip, DNS_PORT))
  response_data, address = cs.recvfrom(512)

  response = None

  # detect corrupt messages where the message cannot be parsed
  try:
    response = Message.fromData(response_data)
    str(response)
  except:
    logger.log(DEBUG2, "Ignored corrupted message.")
    return None

  print "\nRESPONSE:\n"
  print response

  # discard messages received with mismatching id
  if response.header._id != id:
    logger.log(DEBUG2, "Ignored packet with mismatching id.")
  # discard messages which are not responses
  elif response.header._qr == 0:
    logger.log(DEBUG2, "Ignored packet which is not a response.")
  # discard messages which have an altered question compared to the query
  elif response.question._dn != domain or response.question._type != QE.TYPE_A:
    logger.log(DEBUG2, "Ignored packet which has altered question.")
  elif response.header._rcode == Header.RCODE_NAMEERR:
    raise DNSNameError
  else:
    return response

def query(domain, begin, dns_ips):
  """
  Given a domain, reference start time (`begin`, in seconds) and a list of
  DNS server IPs, it returns the result as a dictionary of lists of "answer",
  "authority" and "additional" records.

  It automatically retries in case of message errors and raises exceptions when
  exceeding the maximum retries or maximum query time.
  It also automatically updates the cache with A and NS records.
  """

  retries = 0 # keeps track how many times a request has been retried
  ith_dns_ip = 0 # keeps track of the index of the current ip from dns_ips

  while True:
    if retries > MAX_RETRIES:
      raise DNSExceededMaxRetries
    if time() > (begin + MAX_QUERY_TIME):
      raise DNSExceededMaxQueryTime
    try:
      dns_ip = dns_ips[ith_dns_ip]
      response = send_question(domain, dns_ip)
      if response is None:
        retries += 1
        ith_dns_ip = (ith_dns_ip + 1) % len(dns_ips)
      else:
        retries = 0
        break
    except timeout:
      retries += 1
    except DNSNameError:
      return None

  answer_records =       filter(lambda x: domain == x._dn, response.answers)
  answer_a_records =     filter(lambda x: isinstance(x, RR_A), answer_records)
  answer_cname_records = filter(lambda x: isinstance(x, RR_CNAME), answer_records)
  ns_records =           filter(lambda x: isinstance(x, RR_NS) and is_subdomain_of(domain, x._dn), response.nameservers)
  additional_a_records = filter(lambda x: isinstance(x, RR_A), response.additional)

  # TODO: vulnerable to cache poisoning, implement bailiwick checking?

  update_acache(answer_a_records + additional_a_records, ref_time=begin)
  update_cnamecache(answer_cname_records, ref_time=begin)
  update_nscache(ns_records, ref_time=begin)

  return {
    "answers": answer_records,
    "nameservers": ns_records,
    "additional": additional_a_records
  }

def resolve(domain, begin=None):
  """
  Given a domain name, it tries to resolve it using all the wonderful DNS
  servers of the Internet and returns a dict of answers, authoritative
  nameservers and additional "glue" records for the nameservers.

  The optional keywords are passed around for recursive calls.
  """

  # keep the reference start timestamp to query the cache.
  if begin is None: begin = time()

  answers, nameservers, additional = get_cache(domain, ref_time=begin)

  answer_a_records =     filter(lambda x: isinstance(x, RR_A), answers)
  answer_cname_records = filter(lambda x: isinstance(x, RR_CNAME), answers)

  if answer_a_records:
    return {
      "answers": answers,
      "nameservers": nameservers,
      "additional": additional
    }

  if answer_cname_records:
    for record in answer_cname_records:
      q = resolve(record._cname, begin=begin)
      if q:
        # add the CNAME to the answers
        q["answers"] = [record] + q["answers"]
        return q

  for ns, a_records_for_ns in get_glued(nameservers, additional):

    # if we have no A records for a NS domain, try to resolve it
    if not a_records_for_ns:
      dns_query = resolve(ns._nsdn, begin=begin)
      if dns_query:
        a_records_for_ns = filter(lambda x: x._dn == ns._nsdn, dns_query["answers"])

    # extract all the IPs of nameservers we have
    dns_ips = map(lambda x: inet_ntoa(x._addr), a_records_for_ns)
    if dns_ips:
      q = query(domain, begin=begin, dns_ips=dns_ips)
      # if successfully resolved, return result
      # otherwise, keep iterating thourgh nameservers
      if q:
        return resolve(domain, begin=begin)

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while True:

  (query_data, address) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes

  if not query_data:
    logger.log(DEBUG2, "Client provided no data.")
    continue

  query_msg = Message.fromData(query_data)
  question = query_msg.question

  if not question:
    logger.log(DEBUG2, "Client provided no question.")
    continue

  result = None

  try:
    result = resolve(question._dn)
  except DNSExceededMaxQueryTime:
    logger.log(DEBUG2, "Exceeded maximum query time.")
  except DNSExceededMaxRetries:
    logger.log(DEBUG2, "Exceeded maximum retries.")

  response_data = ""

  if result:
    response = Message(question=question, **result)
    response.generate_header(query_msg.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_NOERR,
                            qr=True)
  else:
    response = Message(question=question)
    response.generate_header(query_msg.header._id,
                            Header.OPCODE_QUERY,
                            Header.RCODE_SRVFAIL,
                            qr=True)

  response_data = response.pack()

  logger.log(DEBUG2, "our response_data in full:")
  logger.log(DEBUG2, hexdump(response_data))

  ss.sendto(response_data, address)
