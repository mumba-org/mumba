// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_LIBRARY_H_
#define MUMBA_DOMAIN_EXECUTION_LIBRARY_H_

#include <string>

#include "base/macros.h"
#include "core/domain/execution/function.h"

namespace domain {
class Namespace;

class Library {
public:
  enum Type {
    kNative,
    kV8
  };
  static Library* LoadLibraryFromName(Namespace* namespace, const std::string& name, Type type);

  virtual ~Library() {}

  virtual const std::string& name() const = 0;
  virtual Type type() const = 0;
};

}

#endif