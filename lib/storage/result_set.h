// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_RESULT_SET_H_
#define MUMBA_COMMON_DATA_RESULT_SET_H_

#include <memory>

#include "base/memory/ref_counted.h"
#include "storage/db/table.h"
#include "zetasql/base/status.h"

namespace storage {

class ResultSet {
public:
  virtual ~ResultSet() {}
  virtual size_t row_count() const = 0;
  virtual size_t column_count() const = 0;
  virtual bool HasNext() const = 0;
  virtual void Next() = 0;
  virtual bool Done() = 0;
  virtual bool First() = 0;
  virtual std::unique_ptr<Schema> BuildSchema() = 0;
  virtual std::unique_ptr<Table> BuildTable() = 0;
  virtual std::string GetColumnName(size_t offset) const = 0;
  virtual const zetasql::Type* GetColumnType(size_t offset) const = 0;
  // values
  virtual int GetInt(size_t offset) const = 0;
  virtual double GetDouble(size_t offset) const = 0;
  virtual base::StringPiece GetString(size_t offset) const = 0;
  // TODO use something better as byte shell
  virtual base::StringPiece GetBlob(size_t offset) const = 0;
};
  
}

#endif