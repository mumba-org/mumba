// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_V8_V8_FUNCTION_H_
#define MUMBA_DOMAIN_EXECUTION_V8_V8_FUNCTION_H_

#include "base/macros.h"
#include "core/domain/execution/function.h"

namespace domain {

template <typename Functor>
class V8Function : public Function<Functor> {
public:
  V8Function(const std::string& name);
  ~V8Function() override;

  const std::string& name() const override;
  FunctionType type() const override;

  template <typename... Args>
  inline Callable<base::MakeUnboundRunType<Functor, Args...>>
  Bind(Functor&& functor, Args&&... args) {
    return {};
  }

private:
  
  std::string name_;
  
  DISALLOW_COPY_AND_ASSIGN(V8Function);
};

}

#endif