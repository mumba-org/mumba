// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_FUNCTION_H_
#define MUMBA_DOMAIN_EXECUTION_FUNCTION_H_

#include <string>
#include <inttypes.h>

#include "base/bind.h"
#include "core/domain/execution/callable.h"

namespace domain {

enum FunctionType {
  kNativeFunc,
  kV8Func
};

template <typename Functor>
class Function {
public:
  virtual ~Function() {}
  virtual const std::string& name() const = 0;
  virtual FunctionType type() const = 0;
};


typedef Function<void()> VoidFunction;

}

#endif