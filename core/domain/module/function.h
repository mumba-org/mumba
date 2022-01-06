// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DOMAIN_ENGINE_FUNCTION_H_
#define DOMAIN_ENGINE_FUNCTION_H_

#include <string>

#include "base/macros.h"
#include "base/bind.h"
#include "core/domain/module/code_entry.h"
#include "core/domain/module/callable.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace domain {

// TODO adapt a v8 Function in here
// and use it to call.. instead of going straight
// for a native library kind of payload

// for native libs, we will embed the native payload
// in the v8 function and use it as the generic abstraction
// anyway

template <typename Functor>
class Function {
public:
  Function(CodeEntry* entry):
   entry_(entry){}
  
  ~Function() {}

  const std::string& name() const {
    return entry_->name;
  }

  Address entry() { 
    return entry_->entry; 
  }
  
  const google::protobuf::MethodDescriptor* method_descriptor() const {
    return method_descriptor_;
  }
  
  template <typename... Args>
  inline Callable<base::MakeUnboundRunType<Functor, Args...>>
  Bind(Args&&... args) {
    // This block checks if each |args| matches to the corresponding params of the
    // target function. This check does not affect the behavior of Bind, but its
    // error message should be more readable.
    using Helper = base::internal::BindTypeHelper<Functor, Args...>;
    using FunctorTraits = typename Helper::FunctorTraits;
    using BoundArgsList = typename Helper::BoundArgsList;
    using UnwrappedArgsList =
        base::internal::MakeUnwrappedTypeList<true, FunctorTraits::is_method,
                                        Args&&...>;
    using BoundParamsList = typename Helper::BoundParamsList;
    static_assert(base::internal::AssertBindArgsValidity<
                      std::make_index_sequence<Helper::num_bounds>, BoundArgsList,
                      UnwrappedArgsList, BoundParamsList>::ok,
                  "The bound args need to be convertible to the target params.");

    using BindState = base::internal::MakeBindStateType<Functor, Args...>;
    using UnboundRunType = base::MakeUnboundRunType<Functor, Args...>;
    using Invoker = base::internal::Invoker<BindState, UnboundRunType>;
    using CallbackType = Callable<UnboundRunType>;

    // Store the invoke func into PolymorphicInvoke before casting it to
    // InvokeFuncStorage, so that we can ensure its type matches to
    // PolymorphicInvoke, to which CallbackType will cast back.
    using PolymorphicInvoke = typename CallbackType::PolymorphicInvoke;
    PolymorphicInvoke invoke_func = &Invoker::RunOnce;

    using InvokeFuncStorage = base::internal::BindStateBase::InvokeFuncStorage;
    return CallbackType(new BindState(
        reinterpret_cast<InvokeFuncStorage>(invoke_func),
        std::forward<Functor>(*reinterpret_cast<Functor *>(entry_->entry)),
        std::forward<Args>(args)...));
  }

private:
  const google::protobuf::MethodDescriptor* method_descriptor_;
  
  CodeEntry* entry_; 
  
  DISALLOW_COPY_AND_ASSIGN(Function);
};

}

#endif