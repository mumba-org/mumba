// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/object.h"

#include "core/domain/id_generator.h"

namespace domain {

Object::Object(std::string oid, std::string oname, std::shared_ptr<data::Schema> schema): 
  oid_(std::move(oid)),
  oname_(std::move(oname)),
  schema_(schema) {

}

Object::Object(std::string oname, std::shared_ptr<data::Schema> schema): 
  oid_(GenerateRandomUniqueID()),
  oname_(std::move(oname)),
  schema_(schema) {

}

Object::~Object() {

}

}