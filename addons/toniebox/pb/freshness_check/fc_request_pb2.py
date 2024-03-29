# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: toniebox.pb.freshness-check.fc-request.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='toniebox.pb.freshness-check.fc-request.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n,toniebox.pb.freshness-check.fc-request.proto\"?\n\x1aTonieFreshnessCheckRequest\x12!\n\x0btonie_infos\x18\x01 \x03(\x0b\x32\x0c.TonieFCInfo\",\n\x0bTonieFCInfo\x12\x0b\n\x03uid\x18\x01 \x02(\x06\x12\x10\n\x08\x61udio_id\x18\x02 \x02(\x07'
)




_TONIEFRESHNESSCHECKREQUEST = _descriptor.Descriptor(
  name='TonieFreshnessCheckRequest',
  full_name='TonieFreshnessCheckRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tonie_infos', full_name='TonieFreshnessCheckRequest.tonie_infos', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=48,
  serialized_end=111,
)


_TONIEFCINFO = _descriptor.Descriptor(
  name='TonieFCInfo',
  full_name='TonieFCInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='uid', full_name='TonieFCInfo.uid', index=0,
      number=1, type=6, cpp_type=4, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='audio_id', full_name='TonieFCInfo.audio_id', index=1,
      number=2, type=7, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=113,
  serialized_end=157,
)

_TONIEFRESHNESSCHECKREQUEST.fields_by_name['tonie_infos'].message_type = _TONIEFCINFO
DESCRIPTOR.message_types_by_name['TonieFreshnessCheckRequest'] = _TONIEFRESHNESSCHECKREQUEST
DESCRIPTOR.message_types_by_name['TonieFCInfo'] = _TONIEFCINFO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TonieFreshnessCheckRequest = _reflection.GeneratedProtocolMessageType('TonieFreshnessCheckRequest', (_message.Message,), {
  'DESCRIPTOR' : _TONIEFRESHNESSCHECKREQUEST,
  '__module__' : 'toniebox.pb.freshness_check.fc_request_pb2'
  # @@protoc_insertion_point(class_scope:TonieFreshnessCheckRequest)
  })
_sym_db.RegisterMessage(TonieFreshnessCheckRequest)

TonieFCInfo = _reflection.GeneratedProtocolMessageType('TonieFCInfo', (_message.Message,), {
  'DESCRIPTOR' : _TONIEFCINFO,
  '__module__' : 'toniebox.pb.freshness_check.fc_request_pb2'
  # @@protoc_insertion_point(class_scope:TonieFCInfo)
  })
_sym_db.RegisterMessage(TonieFCInfo)


# @@protoc_insertion_point(module_scope)
