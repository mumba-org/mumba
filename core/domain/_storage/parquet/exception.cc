// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "core/shared/domain/storage/parquet/exception.h"

#include <exception>
#include <sstream>
#include <string>

#include "core/shared/domain/storage/parquet/util/macros.h"

namespace domain {

PARQUET_NORETURN void ParquetException::EofException(const std::string& msg) {
  std::stringstream ss;
  ss << "Unexpected end of stream";
  if (!msg.empty()) {
    ss << ": " << msg;
  }
  throw ParquetException(ss.str());
}

PARQUET_NORETURN void ParquetException::NYI(const std::string& msg) {
  std::stringstream ss;
  ss << "Not yet implemented: " << msg << ".";
  throw ParquetException(ss.str());
}

PARQUET_NORETURN void ParquetException::Throw(const std::string& msg) {
  throw ParquetException(msg);
}

ParquetExceptionParquetException(const char* msg) : msg_(msg) {}

ParquetExceptionParquetException(const std::string& msg) : msg_(msg) {}

ParquetExceptionParquetException(const char* msg, std::exception& e) : msg_(msg) {}

ParquetException::~ParquetException() throw() {}

const char* ParquetException::what() const throw() { return msg_.c_str(); }

}  // namespace domain
