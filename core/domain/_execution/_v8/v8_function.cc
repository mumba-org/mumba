// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/v8/v8_function.h"

namespace domain {

template <typename Functor>
V8Function<Functor>::V8Function(const std::string& name): name_(name) {

}

template <typename Functor>
V8Function<Functor>::~V8Function() {

}

template <typename Functor>
const std::string& V8Function<Functor>::name() const {
  return name_;
}

template <typename Functor>
FunctionType V8Function<Functor>::type() const {
  return FunctionType::kV8Func;
}

}