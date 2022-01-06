// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_LIBRARY_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_LIBRARY_H_

#include "core/domain/execution/library.h"

namespace domain {

class V8Library : public Library {
public:
  V8Library(const std::string& name);
  ~V8Library() override;

  const std::string& name() const override {
    return name_;
  }

  Type type() const override {
    return Library::kV8;
  }

private:
  
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(V8Library);
};

}

#endif