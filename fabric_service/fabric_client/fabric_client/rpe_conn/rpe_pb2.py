# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: rpe.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\trpe.proto\x12\x03rpe\"+\n\x08Response\x12\x0e\n\x06status\x18\x01 \x01(\x05\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\"2\n\x13RPEVerificationInfo\x12\x1b\n\x13rpeVerificationInfo\x18\x01 \x01(\t\".\n\x11RequiredRPENumber\x12\x19\n\x11requiredRPENumber\x18\x01 \x01(\x05\":\n\rRpeIdAndQuote\x12\r\n\x05rpeId\x18\x01 \x01(\t\x12\x1a\n\x12\x62\x61se64EncodedQuote\x18\x02 \x01(\t\"\x16\n\x05RpeId\x12\r\n\x05rpeId\x18\x01 \x01(\t\"?\n\x12VerificationResult\x12\r\n\x05rpeId\x18\x01 \x01(\t\x12\x1a\n\x12verificationResult\x18\x02 \x01(\t\"\x18\n\x06RpeIds\x12\x0e\n\x06rpeIds\x18\x01 \x01(\t\"\'\n\x06\x43\x45Info\x12\r\n\x05jobId\x18\x01 \x01(\t\x12\x0e\n\x06\x63\x65Info\x18\x02 \x01(\t\"\x18\n\x06JobIds\x12\x0e\n\x06jobIds\x18\x01 \x01(\t2\xc1\x03\n\nRpeService\x12\x44\n\x17SendRPEVerificationInfo\x12\x18.rpe.RPEVerificationInfo\x1a\r.rpe.Response\"\x00\x12\x34\n\tQueryRPEs\x12\x16.rpe.RequiredRPENumber\x1a\r.rpe.Response\"\x00\x12\x30\n\tSendQuote\x12\x12.rpe.RpeIdAndQuote\x1a\r.rpe.Response\"\x00\x12)\n\nQueryQuote\x12\n.rpe.RpeId\x1a\r.rpe.Response\"\x00\x12\x42\n\x16SendVerificationResult\x12\x17.rpe.VerificationResult\x1a\r.rpe.Response\"\x00\x12<\n\x1cQueryVerificationFinalResult\x12\x0b.rpe.RpeIds\x1a\r.rpe.Response\"\x00\x12*\n\nSendCEInfo\x12\x0b.rpe.CEInfo\x1a\r.rpe.Response\"\x00\x12,\n\x0cQueryCEsInfo\x12\x0b.rpe.JobIds\x1a\r.rpe.Response\"\x00\x62\x06proto3')



_RESPONSE = DESCRIPTOR.message_types_by_name['Response']
_RPEVERIFICATIONINFO = DESCRIPTOR.message_types_by_name['RPEVerificationInfo']
_REQUIREDRPENUMBER = DESCRIPTOR.message_types_by_name['RequiredRPENumber']
_RPEIDANDQUOTE = DESCRIPTOR.message_types_by_name['RpeIdAndQuote']
_RPEID = DESCRIPTOR.message_types_by_name['RpeId']
_VERIFICATIONRESULT = DESCRIPTOR.message_types_by_name['VerificationResult']
_RPEIDS = DESCRIPTOR.message_types_by_name['RpeIds']
_CEINFO = DESCRIPTOR.message_types_by_name['CEInfo']
_JOBIDS = DESCRIPTOR.message_types_by_name['JobIds']
Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.Response)
  })
_sym_db.RegisterMessage(Response)

RPEVerificationInfo = _reflection.GeneratedProtocolMessageType('RPEVerificationInfo', (_message.Message,), {
  'DESCRIPTOR' : _RPEVERIFICATIONINFO,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.RPEVerificationInfo)
  })
_sym_db.RegisterMessage(RPEVerificationInfo)

RequiredRPENumber = _reflection.GeneratedProtocolMessageType('RequiredRPENumber', (_message.Message,), {
  'DESCRIPTOR' : _REQUIREDRPENUMBER,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.RequiredRPENumber)
  })
_sym_db.RegisterMessage(RequiredRPENumber)

RpeIdAndQuote = _reflection.GeneratedProtocolMessageType('RpeIdAndQuote', (_message.Message,), {
  'DESCRIPTOR' : _RPEIDANDQUOTE,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.RpeIdAndQuote)
  })
_sym_db.RegisterMessage(RpeIdAndQuote)

RpeId = _reflection.GeneratedProtocolMessageType('RpeId', (_message.Message,), {
  'DESCRIPTOR' : _RPEID,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.RpeId)
  })
_sym_db.RegisterMessage(RpeId)

VerificationResult = _reflection.GeneratedProtocolMessageType('VerificationResult', (_message.Message,), {
  'DESCRIPTOR' : _VERIFICATIONRESULT,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.VerificationResult)
  })
_sym_db.RegisterMessage(VerificationResult)

RpeIds = _reflection.GeneratedProtocolMessageType('RpeIds', (_message.Message,), {
  'DESCRIPTOR' : _RPEIDS,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.RpeIds)
  })
_sym_db.RegisterMessage(RpeIds)

CEInfo = _reflection.GeneratedProtocolMessageType('CEInfo', (_message.Message,), {
  'DESCRIPTOR' : _CEINFO,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.CEInfo)
  })
_sym_db.RegisterMessage(CEInfo)

JobIds = _reflection.GeneratedProtocolMessageType('JobIds', (_message.Message,), {
  'DESCRIPTOR' : _JOBIDS,
  '__module__' : 'rpe_pb2'
  # @@protoc_insertion_point(class_scope:rpe.JobIds)
  })
_sym_db.RegisterMessage(JobIds)

_RPESERVICE = DESCRIPTOR.services_by_name['RpeService']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _RESPONSE._serialized_start=18
  _RESPONSE._serialized_end=61
  _RPEVERIFICATIONINFO._serialized_start=63
  _RPEVERIFICATIONINFO._serialized_end=113
  _REQUIREDRPENUMBER._serialized_start=115
  _REQUIREDRPENUMBER._serialized_end=161
  _RPEIDANDQUOTE._serialized_start=163
  _RPEIDANDQUOTE._serialized_end=221
  _RPEID._serialized_start=223
  _RPEID._serialized_end=245
  _VERIFICATIONRESULT._serialized_start=247
  _VERIFICATIONRESULT._serialized_end=310
  _RPEIDS._serialized_start=312
  _RPEIDS._serialized_end=336
  _CEINFO._serialized_start=338
  _CEINFO._serialized_end=377
  _JOBIDS._serialized_start=379
  _JOBIDS._serialized_end=403
  _RPESERVICE._serialized_start=406
  _RPESERVICE._serialized_end=855
# @@protoc_insertion_point(module_scope)