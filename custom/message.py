import pprint

from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

pp = pprint.PrettyPrinter(indent=2)

class Message:

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

  def is_successful_response(self):
    return len(self.answers) > 0 and \
           self.header._qr == 1 and \
           self.header.rcode == Header.RCODE_NOERR

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
