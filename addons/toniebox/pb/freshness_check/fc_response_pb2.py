# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: toniebox.pb.freshness-check.fc-response.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='toniebox.pb.freshness-check.fc-response.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n-toniebox.pb.freshness-check.fc-response.proto\"\xa3\x01\n\x1bTonieFreshnessCheckResponse\x12\x14\n\x0ctonie_marked\x18\x01 \x03(\x06\x12\x0e\n\x06\x66ield2\x18\x02 \x02(\x05\x12\x0e\n\x06\x66ield3\x18\x03 \x02(\x05\x12\x0e\n\x06\x66ield4\x18\x04 \x02(\x05\x12\x0e\n\x06\x66ield5\x18\x05 \x02(\x05\x12\x0e\n\x06\x66ield6\x18\x06 \x02(\x05\x12\x0e\n\x06\x66ield7\x18\x07 \x02(\x05\x12\x0e\n\x06\x66ield8\x18\x08 \x02(\x05'
)




_TONIEFRESHNESSCHECKRESPONSE = _descriptor.Descriptor(
  name='TonieFreshnessCheckResponse',
  full_name='TonieFreshnessCheckResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='tonie_marked', full_name='TonieFreshnessCheckResponse.tonie_marked', index=0,
      number=1, type=6, cpp_type=4, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='field2', full_name='TonieFreshnessCheckResponse.field2', index=1,
      number=2, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='max_vol_spk', full_name='TonieFreshnessCheckResponse.max_vol_spk', index=2,
      number=3, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='slap_en', full_name='TonieFreshnessCheckResponse.slap_en', index=3,
      number=4, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='slap_dir', full_name='TonieFreshnessCheckResponse.slap_dir', index=4,
      number=5, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='field6', full_name='TonieFreshnessCheckResponse.field6', index=5,
      number=6, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='max_vol_hdp', full_name='TonieFreshnessCheckResponse.max_vol_hdp', index=6,
      number=7, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='led', full_name='TonieFreshnessCheckResponse.led', index=7,
      number=8, type=5, cpp_type=1, label=2,
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
  serialized_start=50,
  serialized_end=213,
)

DESCRIPTOR.message_types_by_name['TonieFreshnessCheckResponse'] = _TONIEFRESHNESSCHECKRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TonieFreshnessCheckResponse = _reflection.GeneratedProtocolMessageType('TonieFreshnessCheckResponse', (_message.Message,), {
  'DESCRIPTOR' : _TONIEFRESHNESSCHECKRESPONSE,
  '__module__' : 'toniebox.pb.freshness_check.fc_response_pb2'
  # @@protoc_insertion_point(class_scope:TonieFreshnessCheckResponse)
  })
_sym_db.RegisterMessage(TonieFreshnessCheckResponse)


# @@protoc_insertion_point(module_scope)
