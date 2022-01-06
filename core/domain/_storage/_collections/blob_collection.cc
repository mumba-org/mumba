// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/collections/blob_collection.h"

#include "data/builder.h"

namespace domain {

BlobCollection::BlobCollection(): 
  Collection(
    "blob",
    ::shell::schema({
      field("id", utf8()), 
      field("name", utf8())
    })) {

}

BlobCollection::~BlobCollection() {

}

size_t BlobCollection::count() const {
  return 2;
}

std::shared_ptr<RecordBatch> BlobCollection::Scan() {
  StringBuilder builder;
  std::vector<std::shared_ptr<Array>> columns;
  const char* id_rows[] = {
    "dg04nfu7",
    "34mn834b"
  };
  const char* name_rows[] = {
    "hello",
    "world"
  };

  int row_count = 2;

  auto self_schema = schema();

  // columns
  for (int i = 0; i < self_schema->num_fields(); i++) {
    std::shared_ptr<Array> column;
    // rows
    for (int x = 0; x < row_count; x++) {
      if (i == 0) {
        Status s = builder.Append(id_rows[x], strlen(id_rows[x]));
        if (!s.ok())
          break;
      } else if (i == 1) {
        Status s = builder.Append(name_rows[x], strlen(name_rows[x]));
        if (!s.ok())
          break;
      }
    }
    Status s = builder.Finish(&column);
    if (s.ok()) {
      columns.push_back(column);
    }
  }

  return RecordBatch::Make(self_schema, row_count, std::move(columns));
}

}