# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: authentication.proto
# Protobuf Python Version: 5.27.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    27,
    2,
    '',
    'authentication.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14\x61uthentication.proto\"2\n\x04User\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x0c\n\x04name\x18\x03 \x01(\t\"A\n\rSignUpRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x10\n\x08password\x18\x02 \x01(\t\x12\x0c\n\x04name\x18\x03 \x01(\t\"%\n\x0eSignUpResponse\x12\x13\n\x04user\x18\x01 \x01(\x0b\x32\x05.User\"2\n\x0cLoginRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x10\n\x08password\x18\x02 \x01(\t\":\n\rLoginResponse\x12\x13\n\x04user\x18\x01 \x01(\x0b\x32\x05.User\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x02 \x01(\t2n\n\x15\x41uthenticationService\x12+\n\x06SignUp\x12\x0e.SignUpRequest\x1a\x0f.SignUpResponse\"\x00\x12(\n\x05Login\x12\r.LoginRequest\x1a\x0e.LoginResponse\"\x00\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'authentication_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_USER']._serialized_start=24
  _globals['_USER']._serialized_end=74
  _globals['_SIGNUPREQUEST']._serialized_start=76
  _globals['_SIGNUPREQUEST']._serialized_end=141
  _globals['_SIGNUPRESPONSE']._serialized_start=143
  _globals['_SIGNUPRESPONSE']._serialized_end=180
  _globals['_LOGINREQUEST']._serialized_start=182
  _globals['_LOGINREQUEST']._serialized_end=232
  _globals['_LOGINRESPONSE']._serialized_start=234
  _globals['_LOGINRESPONSE']._serialized_end=292
  _globals['_AUTHENTICATIONSERVICE']._serialized_start=294
  _globals['_AUTHENTICATIONSERVICE']._serialized_end=404
# @@protoc_insertion_point(module_scope)
