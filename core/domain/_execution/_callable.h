// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_CALLABLE_H_
#define MUMBA_DOMAIN_EXECUTION_CALLABLE_H_

#include "base/callback_forward.h"
#include "base/callback_internal.h"

namespace domain {

template <typename Signature>
class Callable;

// Syntactic sugar to make Callable<void()> easier to declare since it
// will be used in a lot of APIs with delayed execution.
using CallableClosure = Callable<void()>;

template <typename R, typename... Args>
class Callable<R(Args...)> : public base::internal::CallbackBase {
 public:
  using RunType = R(Args...);
  using PolymorphicInvoke = R (*)(base::internal::BindStateBase*,
                                  base::internal::PassingTraitsType<Args>...);

  constexpr Callable() = default;

  explicit Callable(base::internal::BindStateBase* bind_state)
      : base::internal::CallbackBase(bind_state) {}

  Callable(const Callable&) = delete;
  Callable& operator=(const Callable&) = delete;

  Callable(Callable&&) = default;
  Callable& operator=(Callable&&) = default;

  Callable(base::OnceCallback<RunType> other)
      : base::internal::CallbackBase(std::move(other)) {}

  Callable(base::RepeatingCallback<RunType> other)
      : base::internal::CallbackBase(std::move(other)) {}

  Callable& operator=(base::OnceCallback<RunType> other) {
    static_cast<base::internal::CallbackBase&>(*this) = std::move(other);
    return *this;
  }

  Callable& operator=(base::RepeatingCallback<RunType> other) {
    static_cast<base::internal::CallbackBase&>(*this) = std::move(other);
    return *this;
  }

  bool Equals(const Callable& other) const { return EqualsInternal(other); }

  R Call(Args... args) const & {
    static_assert(!sizeof(*this),
                  "Callable::Call() may only be invoked on a non-const "
                  "rvalue, i.e. std::move(callback).Call().");
    //NOTREACHED();
  }

  R Call(Args... args) && {
    // Move the callback instance into a local variable before the invocation,
    // that ensures the internal state is cleared after the invocation.
    // It's not safe to touch |this| after the invocation, since running the
    // bound function may destroy |this|.
    Callable cb = std::move(*this);
    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(cb.polymorphic_invoke());
    return f(cb.bind_state_.get(), std::forward<Args>(args)...);
  }
};

}

#endif