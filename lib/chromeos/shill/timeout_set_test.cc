// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/timeout_set.h"

#include <algorithm>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/logging.h"
#include "shill/net/ip_address.h"

using testing::_;
using testing::AtLeast;
using testing::Test;

namespace shill {

// Expect that the provided elements are the exact elements that timeout.
// This macro will generally be called after calling IncrementTime, and must be
// called within a TYPED_TEST.
#define EXPECT_TIMEOUT(...)                                                    \
  do {                                                                         \
    std::vector<TypeParam> expected_elements{__VA_ARGS__};                     \
    std::sort(expected_elements.begin(), expected_elements.end());             \
    this->SimulateTimeout();                                                   \
    std::sort(this->timeout_elements_.begin(), this->timeout_elements_.end()); \
    EXPECT_EQ(expected_elements, this->timeout_elements_);                     \
  } while (0)

template <typename T>
struct TestData {
  static_assert(
      std::is_arithmetic<T>::value,
      "TestData needs a template specialization for non-arithmetic types.");

  TestData() {
    data.push_back(1);
    data.push_back(2);
    data.push_back(3);
    data.push_back(4);
  }

  std::vector<T> data;
};

template <>
struct TestData<IPAddress> {
  TestData() {
    data.push_back(IPAddress("1.1.1.1"));
    data.push_back(IPAddress("2.2.2.2"));
    data.push_back(IPAddress("3.3.3.3"));
    data.push_back(IPAddress("4.4.4.4"));
  }

  std::vector<IPAddress> data;
};

template <typename T>
class TimeoutSetTest : public Test {
 public:
  TimeoutSetTest() : current_time_(0), elements_(&current_time_) {
    elements_.SetInformCallback(
        base::Bind(&TimeoutSetTest::OnTimeout, base::Unretained(this)));
  }

 protected:
  class TestTimeoutSet : public TimeoutSet<T> {
   public:
    explicit TestTimeoutSet(const int64_t* current_time)
        : TimeoutSet<T>(), current_time_(current_time) {}

   private:
    base::TimeTicks TimeNow() const override {
      return base::TimeTicks::FromInternalValue(*current_time_);
    }

    const int64_t* current_time_;
  };

  void IncrementTime(int64_t amount_ms) { current_time_ += amount_ms * 1000; }
  // Acts as though a timeout event occurred. EXPECT_TIMEOUT should generally be
  // used instead of this.
  void SimulateTimeout() { elements_.OnTimeout(); }
  void OnTimeout(std::vector<T> timeout_elements) {
    timeout_elements_ = std::move(timeout_elements);
  }

  int64_t current_time_;
  TestData<T> data_;
  TestTimeoutSet elements_;
  std::vector<T> timeout_elements_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
};

typedef ::testing::Types<char, int, float, IPAddress> TestTypes;
TYPED_TEST_SUITE(TimeoutSetTest, TestTypes);

TYPED_TEST(TimeoutSetTest, EmptyInsertion) {
  EXPECT_TRUE(this->elements_.IsEmpty());

  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));
  EXPECT_FALSE(this->elements_.IsEmpty());
  EXPECT_TRUE(
      std::equal(this->elements_.cbegin(), this->elements_.cend(),
                 this->data_.data.cbegin(),
                 [](const auto& a, const auto& b) { return a.element == b; }));
}

TYPED_TEST(TimeoutSetTest, SingleTimeout) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0]);

  EXPECT_TRUE(this->elements_.IsEmpty());
  EXPECT_EQ(this->elements_.cbegin(), this->elements_.cend());
}

TYPED_TEST(TimeoutSetTest, MultipleSequentialTimeouts) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));
  this->elements_.Insert(this->data_.data[1], base::Milliseconds(20));

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0]);

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[1]);

  EXPECT_TRUE(this->elements_.IsEmpty());
}

TYPED_TEST(TimeoutSetTest, MultipleSequentialTimeoutsWithInfiniteLifetime) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));
  this->elements_.Insert(this->data_.data[1], base::Milliseconds(20));
  this->elements_.Insert(this->data_.data[2], base::TimeDelta::Max());

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0]);

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[1]);

  EXPECT_FALSE(this->elements_.IsEmpty());

  // Check that element with infinite lifetime is still around after an
  // arbitrary amount of time.
  this->IncrementTime(1000);
  EXPECT_TIMEOUT();
  EXPECT_FALSE(this->elements_.IsEmpty());
}

// Single timeout has multiple elements expiring.
TYPED_TEST(TimeoutSetTest, MultiTimeout) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));
  this->elements_.Insert(this->data_.data[1], base::Milliseconds(10));

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0], this->data_.data[1]);
  EXPECT_TRUE(this->elements_.IsEmpty());
}

// Single timeout has multiple elements expiring.
TYPED_TEST(TimeoutSetTest, MultiTimeoutWithInfiniteLifetime) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(10));
  this->elements_.Insert(this->data_.data[1], base::Milliseconds(10));
  this->elements_.Insert(this->data_.data[2], base::TimeDelta::Max());
  this->elements_.Insert(this->data_.data[3], base::TimeDelta::Max());

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0], this->data_.data[1]);
  EXPECT_FALSE(this->elements_.IsEmpty());

  // Check that elements with infinite lifetime are still around after an
  // arbitrary amount of time.
  this->IncrementTime(1000);
  EXPECT_TIMEOUT();
  EXPECT_FALSE(this->elements_.IsEmpty());
}

TYPED_TEST(TimeoutSetTest, InsertResetTimeout) {
  this->elements_.Insert(this->data_.data[0], base::Milliseconds(20));
  this->elements_.Insert(this->data_.data[1], base::Milliseconds(10));

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[1]);

  this->IncrementTime(10);
  EXPECT_TIMEOUT(this->data_.data[0]);

  EXPECT_TRUE(this->elements_.IsEmpty());
}

}  // namespace shill
