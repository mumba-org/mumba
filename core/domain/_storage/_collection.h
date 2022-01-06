// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_COLLECTION_H_
#define MUMBA_DOMAIN_NAMESPACE_COLLECTION_H_

#include "core/shared/domain/storage/object.h"

namespace domain {

class Collection : public Object {
public:
  Collection(std::string oid, std::string oname, std::shared_ptr<data::Schema> schema);
  Collection(std::string oname, std::shared_ptr<data::Schema> schema);
  ~Collection() override;
  
  virtual size_t count() const;
  virtual std::shared_ptr<RecordBatch> Scan();

private:

  DISALLOW_COPY_AND_ASSIGN(Collection);
};

}


#endif