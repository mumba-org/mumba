// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CONTAINERS_SPAN_H_
#define BASE_CONTAINERS_SPAN_H_

#include <stddef.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <type_traits>
#include <utility>

#include "base/logging.h"
#include "base/stl_util.h"

namespace base {

template <typename T>
class span;

namespace internal {

template <typename T>
struct IsSpanImpl : std::false_type {};

template <typename T>
struct IsSpanImpl<span<T>> : std::true_type {};

template <typename T>
using IsSpan = IsSpanImpl<std::decay_t<T>>;

template <typename T>
struct IsStdArrayImpl : std::false_type {};

template <typename T, size_t N>
struct IsStdArrayImpl<std::array<T, N>> : std::true_type {};

template <typename T>
using IsStdArray = IsStdArrayImpl<std::decay_t<T>>;

template <typename T>
using IsCArray = std::is_array<std::remove_reference_t<T>>;

template <typename From, typename To>
using IsLegalSpanConversion = std::is_convertible<From (*)[], To (*)[]>;

template <typename Container, typename T>
using ContainerHasConvertibleData = IsLegalSpanConversion<
    std::remove_pointer_t<decltype(base::data(std::declval<Container>()))>,
    T>;

template <typename Container>
using ContainerHasIntegralSize =
    std::is_integral<decltype(base::size(std::declval<Container>()))>;

template <typename From, typename To>
using EnableIfLegalSpanConversion =
    std::enable_if_t<IsLegalSpanConversion<From, To>::value>;

// SFINAE check if Array can be converted to a span<T>.
template <typename Array, typename T>
using EnableIfSpanCompatibleArray =
    std::enable_if_t<ContainerHasConvertibleData<Array, T>::value>;

// SFINAE check if Container can be converted to a span<T>.
template <typename Container, typename T>
using EnableIfSpanCompatibleContainer =
    std::enable_if_t<!internal::IsSpan<Container>::value &&
                     !internal::IsStdArray<Container>::value &&
                     !internal::IsCArray<Container>::value &&
                     ContainerHasConvertibleData<Container, T>::value &&
                     ContainerHasIntegralSize<Container>::value>;

}  // namespace internal

// A span is a value type that represents an array of elements of type T. Since
// it only consists of a pointer to memory with an associated size, it is very
// light-weight. It is cheap to construct, copy, move and use spans, so that
// users are encouraged to use it as a pass-by-value parameter. A span does not
// own the underlying memory, so care must be taken to ensure that a span does
// not outlive the backing store.
//
// span is somewhat analogous to StringPiece, but with arbitrary element types,
// allowing mutation if T is non-const.
//
// span is implicitly convertible from C++ arrays, as well as most [1]
// container-like types that provide a data() and size() method (such as
// std::vector<T>). A mutable span<T> can also be implicitly converted to an
// immutable span<const T>.
//
// Consider using a span for functions that take a data pointer and size
// parameter: it allows the function to still act on an array-like type, while
// allowing the caller code to be a bit more concise.
//
// For read-only data access pass a span<const T>: the caller can supply either
// a span<const T> or a span<T>, while the callee will have a read-only view.
// For read-write access a mutable span<T> is required.
//
// Without span:
//   Read-Only:
//     // std::string HexEncode(const uint8_t* data, size_t size);
//     std::vector<uint8_t> data_buffer = GenerateData();
//     std::string r = HexEncode(data_buffer.data(), data_buffer.size());
//
//  Mutable:
//     // ssize_t SafeSNPrintf(char* buf, size_t N, const char* fmt, Args...);
//     char str_buffer[100];
//     SafeSNPrintf(str_buffer, sizeof(str_buffer), "Pi ~= %lf", 3.14);
//
// With span:
//   Read-Only:
//     // std::string HexEncode(base::span<const uint8_t> data);
//     std::vector<uint8_t> data_buffer = GenerateData();
//     std::string r = HexEncode(data_buffer);
//
//  Mutable:
//     // ssize_t SafeSNPrintf(base::span<char>, const char* fmt, Args...);
//     char str_buffer[100];
//     SafeSNPrintf(str_buffer, "Pi ~= %lf", 3.14);
//
// Spans with "const" and pointers
// -------------------------------
//
// Const and pointers can get confusing. Here are vectors of pointers and their
// corresponding spans:
//
//   const std::vector<int*>        =>  base::span<int* const>
//   std::vector<const int*>        =>  base::span<const int*>
//   const std::vector<const int*>  =>  base::span<const int* const>
//
// Differences from the working group proposal
// -------------------------------------------
//
// https://wg21.link/P0122 is the latest working group proposal, Chromium
// currently implements R7. The biggest difference is span does not support a
// static extent template parameter. Other differences are documented in
// subsections below.
//
// Differences from [views.constants]:
// - no dynamic_extent constant
//
// Differences from [span.objectrep]:
// - as_bytes() and as_writable_bytes() return spans of uint8_t instead of
//   std::byte
//
// Differences in constants and types:
// - no index_type type alias
// - no different_type type alias
// - no extent constant
//
// Differences from [span.sub]:
// - no templated first()
// - no templated last()
// - no templated subspan()
// - using size_t instead of ptrdiff_t for indexing
//
// Differences from [span.obs]:
// - using size_t instead of ptrdiff_t to represent size()
//
// Differences from [span.elem]:
// - using size_t instead of ptrdiff_t for indexing

// [span], class template span
template <typename T>
class span {
 public:
  using element_type = T;
  using value_type = std::remove_cv_t<T>;
  using pointer = T*;
  using reference = T&;
  using iterator = T*;
  using const_iterator = const T*;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  // [span.cons], span constructors, copy, assignment, and destructor
  constexpr span() noexcept : data_(nullptr), size_(0) {}
  constexpr span(T* data, size_t size) noexcept : data_(data), size_(size) {}
  // Artificially templatized to break ambiguity for span(ptr, 0).
  template <typename = void>
  constexpr span(T* begin, T* end)
      : data_(begin), size_(std::distance(begin, end)) {
    CHECK_LE(begin, end);
  }
  template <size_t N,
            typename = internal::EnableIfSpanCompatibleArray<T (&)[N], T>>
  constexpr span(T (&array)[N]) noexcept : span(base::data(array), N) {}

  template <
      size_t N,
      typename =
          internal::EnableIfSpanCompatibleArray<std::array<value_type, N>&, T>>
  constexpr span(std::array<value_type, N>& array) noexcept
      : span(base::data(array), N) {}
  template <size_t N,
            typename = internal::EnableIfSpanCompatibleArray<
                const std::array<value_type, N>&,
                T>>
  constexpr span(const std::array<value_type, N>& array) noexcept
      : span(base::data(array), N) {}
  // Conversion from a container that provides |T* data()| and |integral_type
  // size()|.
  template <typename Container,
            typename = internal::EnableIfSpanCompatibleContainer<Container&, T>>
  constexpr span(Container& container)
      : span(base::data(container), base::size(container)) {}
  template <
      typename Container,
      typename = internal::EnableIfSpanCompatibleContainer<const Container&, T>>
  span(const Container& container)
      : span(base::data(container), base::size(container)) {}
  constexpr span(const span& other) noexcept = default;
  // Conversions from spans of compatible types: this allows a span<T> to be
  // seamlessly used as a span<const T>, but not the other way around.
  template <typename U, typename = internal::EnableIfLegalSpanConversion<U, T>>
  constexpr span(const span<U>& other) : span(other.data(), other.size()) {}
  constexpr span& operator=(const span& other) noexcept = default;
  ~span() noexcept = default;

  // [span.sub], span subviews
  constexpr span first(size_t count) const {
    CHECK(count <= size_);
    return span(data_, count);
  }

  constexpr span last(size_t count) const {
    CHECK(count <= size_);
    return span(data_ + (size_ - count), count);
  }

  constexpr span subspan(size_t pos, size_t count = -1) const {
    constexpr auto npos = static_cast<size_t>(-1);
    CHECK(pos <= size_);
    CHECK(count == npos || count <= size_ - pos);
    return span(data_ + pos, count == npos ? size_ - pos : count);
  }

  // [span.obs], span observers
  constexpr size_t size() const noexcept { return size_; }
  constexpr size_t size_bytes() const noexcept { return size() * sizeof(T); }
  constexpr bool empty() const noexcept { return size_ == 0; }

  // [span.elem], span element access
  constexpr T& operator[](size_t index) const noexcept {
    CHECK(index < size_);
    return data_[index];
  }
  constexpr T& operator()(size_t index) const noexcept {
    CHECK(index < size_);
    return data_[index];
  }
  constexpr T* data() const noexcept { return data_; }

  // [span.iter], span iterator support
  constexpr iterator begin() const noexcept { return data_; }
  constexpr iterator end() const noexcept { return data_ + size_; }

  constexpr const_iterator cbegin() const noexcept { return begin(); }
  constexpr const_iterator cend() const noexcept { return end(); }

  constexpr reverse_iterator rbegin() const noexcept {
    return reverse_iterator(end());
  }
  constexpr reverse_iterator rend() const noexcept {
    return reverse_iterator(begin());
  }

  constexpr const_reverse_iterator crbegin() const noexcept {
    return const_reverse_iterator(cend());
  }
  constexpr const_reverse_iterator crend() const noexcept {
    return const_reverse_iterator(cbegin());
  }

 private:
  T* data_;
  size_t size_;
};

// [span.comparison], span comparison operators
// Relational operators. Equality is a element-wise comparison.
template <typename T, typename U>
constexpr bool operator==(span<T> lhs, span<U> rhs) noexcept {
  return std::equal(lhs.cbegin(), lhs.cend(), rhs.cbegin(), rhs.cend());
}

template <typename T, typename U>
constexpr bool operator!=(span<T> lhs, span<U> rhs) noexcept {
  return !(lhs == rhs);
}

template <typename T, typename U>
constexpr bool operator<(span<T> lhs, span<U> rhs) noexcept {
  return std::lexicographical_compare(lhs.cbegin(), lhs.cend(), rhs.cbegin(),
                                      rhs.cend());
}

template <typename T, typename U>
constexpr bool operator<=(span<T> lhs, span<U> rhs) noexcept {
  return !(rhs < lhs);
}

template <typename T, typename U>
constexpr bool operator>(span<T> lhs, span<U> rhs) noexcept {
  return rhs < lhs;
}

template <typename T, typename U>
constexpr bool operator>=(span<T> lhs, span<U> rhs) noexcept {
  return !(lhs < rhs);
}

// [span.objectrep], views of object representation
template <typename T>
span<const uint8_t> as_bytes(span<T> s) noexcept {
  return {reinterpret_cast<const uint8_t*>(s.data()), s.size_bytes()};
}

template <typename T, typename = std::enable_if_t<!std::is_const<T>::value>>
span<uint8_t> as_writable_bytes(span<T> s) noexcept {
  return {reinterpret_cast<uint8_t*>(s.data()), s.size_bytes()};
}

// Type-deducing helpers for constructing a span.
template <typename T>
constexpr span<T> make_span(T* data, size_t size) noexcept {
  return span<T>(data, size);
}

template <typename T>
constexpr span<T> make_span(T* begin, T* end) {
  return span<T>(begin, end);
}

template <typename T, size_t N>
constexpr span<T> make_span(T (&array)[N]) noexcept {
  return span<T>(array);
}

template <typename T, size_t N>
constexpr span<T> make_span(std::array<T, N>& array) noexcept {
  return span<T>(array);
}

template <typename T, size_t N>
constexpr span<const T> make_span(const std::array<T, N>& array) noexcept {
  return span<const T>(array);
}

template <typename Container,
          typename T = typename Container::value_type,
          typename = internal::EnableIfSpanCompatibleContainer<Container&, T>>
constexpr span<T> make_span(Container& container) {
  return span<T>(container);
}

template <
    typename Container,
    typename T = const typename Container::value_type,
    typename = internal::EnableIfSpanCompatibleContainer<const Container&, T>>
constexpr span<T> make_span(const Container& container) {
  return span<T>(container);
}

template <typename T>
constexpr span<T> make_span(span<T> span) noexcept {
  return span;
}

}  // namespace base

#endif  // BASE_CONTAINERS_SPAN_H_
