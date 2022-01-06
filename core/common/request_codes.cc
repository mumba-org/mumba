// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/request_codes.h"

std::string ResultStatusString(ResultStatus status) {
	switch (status) {
		case ResultStatus::UNHANDLED:
			return "unhandled. handled by no one. internal logic error.";
 		case ResultStatus::WORKSPACE_NOT_FOUND:
			return "workspace not found";
		case ResultStatus::METHOD_NOT_FOUND:
		 return "method not found";
 		case ResultStatus::API_NOT_FOUND:
		 return "api not found";	
		case ResultStatus::MULTIPLE_OBJECTS:
		 return "multiple objects";
		case ResultStatus::ROUTE_NOT_FOUND:
		 return "route not found";
		case ResultStatus::INVALID_INPUT_PARAMS:
			return "invalid input parameters";
		case ResultStatus::DELETE_ALL_ERROR:
			return "delete all";
		case ResultStatus::INVALID_BLOB_READ_OFFSET:
			return "invalid read offset";
 		case ResultStatus::BLOB_NOT_FOUND:
 			return "blob not found";
 		case ResultStatus::BLOB_CREATE_ERROR:
 			return "blob creation error";
 		case ResultStatus::BLOB_WRITE_ERROR:
 			return "write error";
 		case ResultStatus::BLOB_READ_ERROR:
 			return "read error";
 		case ResultStatus::MALFORMED_HEADER:
 			return "malformed header";
 		case ResultStatus::BAD_HEADER_VERSION:
 			return "bad header version";
 		case ResultStatus::INVALID_UUID:
 			return "invalid uuid";
 		case ResultStatus::DATASET_NOT_FOUND:
 			return "dataset not found";
 		case ResultStatus::IPC_FILE_READ_ERROR:
 			return "file read error: ipc file";
 		case ResultStatus::INVALID_IPC_FILEHANDLE:
 			return "invalid file handle: ipc file";
 		case ResultStatus::INVALID_URL:
 			return "invalid url";
 		case ResultStatus::SHELL_ALREADY_EXISTS:
 			return "shell already exists";
 		case ResultStatus::SHELL_ALREADY_LOADED:
 			return "shell already loaded";
 		case ResultStatus::SHELL_NOT_LOADED:
 			return "shell not loaded";
 		case ResultStatus::SHELL_NOT_FOUND:
 			return "shell not found";
 		case ResultStatus::INVALID_REQUEST:
 			return "invalid request";
 		case ResultStatus::kERROR:
 			return "generic error";
 		case ResultStatus::OK:
 			return "ok";
 		case ResultStatus::CONTINUE:
 			return "continue";
 		case ResultStatus::UNDEFINED:
 			return "undefined";
		default:
		 return std::string();
	}
}

bool ResultStatusIsError(ResultStatus status) {
	return static_cast<int>(status) < 0;
}