// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_NATIVE_NATIVE_FUNCTION_H_
#define MUMBA_DOMAIN_EXECUTION_NATIVE_NATIVE_FUNCTION_H_

#include "core/domain/execution/function.h"

// use the V8 variation here
#include "base/macros.h"

namespace domain {

struct NativeFunctionEntry {
  std::string name;
  void* fn_ptr = nullptr;
};

// TODO: Criar um código "bootstrap" V8
//       que seria chamado no lugar da função C
//       mas que embarca/envelopa a função C

// Podemos usar isso pra por exemplo tornar 
// esse método visível para V8 e o ambiente JS/WASM
template <typename Functor>
class NativeFunction : public Function<Functor> {
public:
  NativeFunction(NativeFunctionEntry* entry):
   entry_(entry){}
  
  ~NativeFunction() override {}

  const std::string& name() const override {
    return entry_->name;
  }
  
  FunctionType type() const override {
    return FunctionType::kNativeFunc;
  }


  void* function_ptr() { 
    return entry_->fn_ptr; 
  }

  // TODO: we need a way to call this
  // by using templates

  // template <typename... Args>
  // inline Callable<base::MakeUnboundRunType<Functor, Args...>>
  // get(Args&&... args) {
  //   return get(reinterpret_cast<Functor *>(fn_ptr_), std::forward<Args>(args)...);
  // }

  template <typename... Args>
  inline Callable<base::MakeUnboundRunType<Functor, Args...>>
  Bind(Args&&... args) {
    // static_assert(!internal::IsOnceCallback<std::decay_t<Functor>>() ||
    //                 (std::is_rvalue_reference<Functor&&>() &&
    //                  !std::is_const<std::remove_reference_t<Functor>>()),
    //             "BindOnce requires non-const rvalue for OnceCallback binding."
    //             " I.e.: base::BindOnce(std::move(callback)).");

    // // This block checks if each |args| matches to the corresponding params of the
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
        std::forward<Functor>(*reinterpret_cast<Functor *>(entry_->fn_ptr)),
        std::forward<Args>(args)...));
  }

private:
  NativeFunctionEntry* entry_; 
  //DISALLOW_COPY_AND_ASSIGN(NativeFunction);
};

typedef NativeFunction<void()> NativeVoidFunction;

}

#endif