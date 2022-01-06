// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_REQUEST_CODES_H_
#define MUMBA_COMMON_REQUEST_CODES_H_

#include <string>

#include "base/uuid.h"
#include "core/shared/common/content_export.h"

enum class BodyEncoding {
 BINARY = 0,
 ASCII = 1,
 UNDEFINED = 999
};

enum class ResultStatus {
 UNHANDLED = -29,
 WORKSPACE_NOT_FOUND = -28,
 METHOD_NOT_FOUND = -27,
 API_NOT_FOUND = -26,
 MULTIPLE_OBJECTS = -25,
 ROUTE_NOT_FOUND = -24,
 NOT_IMPLEMENTED = -23,
 INVALID_OBJECT = -22,
 PARSE_ERROR = -21,
 INVALID_INPUT_PARAMS = -20,
 DELETE_ALL_ERROR = -19,
 INVALID_BLOB_READ_OFFSET = -18,
 BLOB_NOT_FOUND = -17,
 BLOB_CREATE_ERROR = -16,
 BLOB_WRITE_ERROR = -15,
 BLOB_READ_ERROR = -14,
 MALFORMED_HEADER = -13,
 BAD_HEADER_VERSION = -12,
 INVALID_UUID = -11,
 DATASET_NOT_FOUND = - 10,
 IPC_FILE_READ_ERROR = -9,	
 INVALID_IPC_FILEHANDLE = -8,	
 INVALID_URL = -7,
 SHELL_ALREADY_EXISTS = -6,
 SHELL_ALREADY_LOADED = -5,
 SHELL_NOT_LOADED = -4,
 SHELL_NOT_FOUND = -3,
 INVALID_REQUEST = -2,	
 kERROR = -1,
 OK = 0,
 CONTINUE = 2,
 UNDEFINED = 999
};

std::string CONTENT_EXPORT ResultStatusString(ResultStatus status);
bool CONTENT_EXPORT ResultStatusIsError(ResultStatus status);

enum class RequestOpcode : int {
  kCAT,
  kHEAD,
  kQUERY,
  kGET,
  kPUT,
  kDELETE,
  kLAUNCH,
  kEXECUTE,
  kMODCREATE,
  kMODDROP,
  kTAG,
  kBUILD,
  kSTART,
  kSTOP,
  kCREATE,
  kDROP,
  kSHUTDOWN,
  kSTATUS,
  kSTATE,
  kINIT,
  kINSTALL,
  kGENERATE,
  kPACK,
  kRPCCALL,
  kBLOCK,
  kLIST,
  kNONE
};

struct CONTENT_EXPORT RequestInfo {
  RequestOpcode op;
  int request_id;
  base::UUID session_id;

  static RequestInfo Invalid() {
    return RequestInfo{RequestOpcode::kNONE};
  }

  RequestInfo(): op(RequestOpcode::kNONE), request_id(-1), session_id() {}
  RequestInfo(RequestOpcode op): op(op), request_id(-1), session_id() {}
  RequestInfo(RequestOpcode op, int req): op(op), request_id(req) {}
  RequestInfo(RequestOpcode op, int req, const base::UUID& session):  op(op), request_id(req), session_id(session) {}
};

#endif