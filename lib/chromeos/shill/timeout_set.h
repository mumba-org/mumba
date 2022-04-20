// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TIMEOUT_SET_H_
#define SHILL_TIMEOUT_SET_H_

#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/threading/thread_task_runner_handle.h>
#include <base/time/time.h>

namespace shill {

// Class representing a set of elements, in which each element has its own
// lifetime. When the lifetime of an element has expired the element will be
// removed from the set. Users may also provide a callback in order to be
// informed if any element in the set has timed out.
//
// This class uses base::TimeTicks to represent times, resulting in a notion of
// time that never decreases, but may not increase in cases such as the computer
// being suspended. Thus elements cannot be expected to be removed exactly when
// their lifetime is expired, but they are guaranteed not to be removed prior to
// the expiration of their lifetime.
template <typename T>
class TimeoutSet {
 public:
  struct TimeElement {
    T element;
    base::TimeTicks deathtime;

    bool operator<(const TimeElement& rhs) const {
      // Since std::make_heap makes a max heap, define ordering such that the
      // greatest elements expire first.
      return deathtime >= rhs.deathtime;
    }
  };
  using const_iterator = typename std::vector<TimeElement>::const_iterator;

  virtual ~TimeoutSet() { Clear(); }

  // Set the callback used to inform clients that some elements have timed out.
  void SetInformCallback(
      base::RepeatingCallback<void(std::vector<T>)> inform_callback) {
    inform_callback_ = std::move(inform_callback);
  }

  // Insert an element into the list with the specified lifetime. If the element
  // already exists, its lifetime will be updated. TimeDelta::Max() may be used
  // to indicate an infinite lifetime.
  //
  // This method currently runs in time linear to the number of elements in the
  // set, as duplicates are checked for prior to insertion.
  void Insert(T element, base::TimeDelta lifetime) {
    // Check for existing element.
    for (auto iter = elements_.begin(); iter != elements_.end(); ++iter) {
      if (iter->element == element) {
        elements_.erase(iter);
        std::make_heap(elements_.begin(), elements_.end());
        break;
      }
    }
    // Perform element insertion.
    base::TimeTicks deathtime =
        lifetime.is_max() ? base::TimeTicks::Max() : TimeNow() + lifetime;
    elements_.push_back({std::move(element), deathtime});
    std::push_heap(elements_.begin(), elements_.end());

    SetUpTimeoutTask();
  }

  // Remove all elements and cancel any pending timeout.
  void Clear() {
    elements_.clear();
    timeout_callback_.Cancel();
  }

  inline bool IsEmpty() const { return elements_.empty(); }

  // Call |apply_func| on each element that hasn't timed out.
  void Apply(
      const base::RepeatingCallback<void(const T& element)>& apply_func) {
    for (const auto& elem : elements_) {
      apply_func.Run(elem.element);
    }
  }

  const_iterator begin() const { return elements_.cbegin(); }
  const_iterator end() const { return elements_.cend(); }
  const_iterator cbegin() const { return elements_.cbegin(); }
  const_iterator cend() const { return elements_.cend(); }

 private:
  template <typename U>
  friend class TimeoutSetTest;

  virtual base::TimeTicks TimeNow() const { return base::TimeTicks::Now(); }

  void OnTimeout() {
    std::vector<T> removed_elements;
    // Invalidate all elements that have timed out.
    while (!elements_.empty() && elements_[0].deathtime <= TimeNow()) {
      removed_elements.push_back(std::move(elements_[0].element));
      std::pop_heap(elements_.begin(), elements_.end());
      elements_.pop_back();
    }
    SetUpTimeoutTask();

    if (!inform_callback_.is_null()) {
      inform_callback_.Run(std::move(removed_elements));
    }
  }

  void SetUpTimeoutTask() {
    if (elements_.empty() || elements_[0].deathtime.is_max()) {
      return;
    }

    base::TimeDelta shortest_lifetime = elements_[0].deathtime - TimeNow();
    base::TimeDelta delay = std::max(shortest_lifetime, base::TimeDelta());
    timeout_callback_.Reset(
        base::BindOnce(&TimeoutSet::OnTimeout, base::Unretained(this)));
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, timeout_callback_.callback(), delay);
  }

  std::vector<TimeElement> elements_;

  // Executes when an element times out. Calls OnTimeout.
  base::CancelableOnceClosure timeout_callback_;
  // Called at the end of OnTimeout to inform user of timeout.
  base::RepeatingCallback<void(std::vector<T>)> inform_callback_;
};

}  // namespace shill

#endif  // SHILL_TIMEOUT_SET_H_
