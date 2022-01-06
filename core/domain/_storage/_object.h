// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_OBJECT_H_
#define MUMBA_DOMAIN_NAMESPACE_OBJECT_H_

#include "base/macros.h"
#include "data/table.h"

namespace domain {

class Object {
public:
  virtual ~Object();
  
  // "xyz5f"
  const std::string& oid() const {
    return oid_;
  }
  // "concept"
  const std::string& oname() const {
    return oname_;
  }

  std::shared_ptr<data::Schema> schema() const {
    return schema_;
  }

  // TODO: how to interact? Scan() here ?
  //       how to plug with a graph or graph node?
protected:
  Object(std::string oid, std::string oname, std::shared_ptr<data::Schema> schema);
  Object(std::string oname, std::shared_ptr<data::Schema> schema);
  
private:
  
  std::string oid_;

  std::string oname_;

  std::shared_ptr<data::Schema> schema_;

  DISALLOW_COPY_AND_ASSIGN(Object);
};

}

#endif