// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/concept/concept_data.h"

namespace domain {

ConceptData::ConceptData(std::shared_ptr<data::Schema> schema): 
  schema_(schema) {

}

ConceptData::~ConceptData() {

}

std::shared_ptr<data::RecordBatch> ConceptData::Scan(size_t max_rows) const {
  return {};
}

void ConceptData::AddRows(const std::vector<std::shared_ptr<data::Array>>& rows, size_t row_count) {
  
}

void ConceptData::RemoveRow(int64_t row_id) {

}

}