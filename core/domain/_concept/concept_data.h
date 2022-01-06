// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_CONCEPT_CONCEPT_DATA_H_
#define MUMBA_DOMAIN_CONCEPT_CONCEPT_DATA_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "data/array.h"
#include "data/builder.h"
#include "data/type.h"
#include "data/table.h"
#include "data/table_builder.h"
#include "data/record_batch.h"

namespace domain {

class ConceptData {
public:
  ConceptData(std::shared_ptr<data::Schema> schema);
  ~ConceptData();

  std::shared_ptr<data::Schema> schema() const {
    return schema_;
  }

  std::shared_ptr<data::RecordBatch> Scan(size_t max_rows = -1) const;
  void AddRows(const std::vector<std::shared_ptr<data::Array>>& rows, size_t row_count = -1);
  void RemoveRow(int64_t row_id);

private:
  
  std::shared_ptr<data::Schema> schema_;

  // TODO: what about data from Parquet or Blobs in Cache?
  // how to deal with them?
  //std::shared_ptr<Table> table_;

  std::unique_ptr<data::RecordBatchBuilder> builder_;

  DISALLOW_COPY_AND_ASSIGN(ConceptData);
};

}

#endif