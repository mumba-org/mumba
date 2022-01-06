/*******************************************************************************
* Copyright 2020-2021 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#include "primitive_cache.hpp"
#include "c_types_map.hpp"
#include "primitive.hpp"
#include "primitive_desc.hpp"
#include "rw_mutex.hpp"
#include "z_magic.hpp"

#if DNNL_CPU_RUNTIME != DNNL_RUNTIME_NONE
#include "cpu/platform.hpp"
#else
#include <chrono>
#endif

#include <algorithm>
#include <unordered_map>

namespace dnnl {
namespace impl {

namespace {

size_t get_timestamp() {
#if DNNL_CPU_RUNTIME != DNNL_RUNTIME_NONE
    return cpu::platform::get_timestamp();
#else
    return std::chrono::steady_clock::now().time_since_epoch().count();
#endif
}

} // namespace

primitive_cache_t &primitive_cache() {
#ifndef DNNL_DISABLE_PRIMITIVE_CACHE
    static const int capacity
            = getenv_int("DNNL_PRIMITIVE_CACHE_CAPACITY", 1024);
#else
    static const int capacity = 0;
#endif
    static lru_primitive_cache_t cache(capacity);
    return cache;
}

// Undocumented API, for testing only
status_t get_primitive_cache_size(int *size) {
    if (size == nullptr) return dnnl::impl::status::invalid_arguments;
    *size = 0;
#ifndef DNNL_DISABLE_PRIMITIVE_CACHE
    *size = primitive_cache().get_size();
#endif
    return dnnl::impl::status::success;
}

bool is_pd_in_cache(const primitive_desc_iface_t *pd_iface) {
    const auto *pd = pd_iface->impl().get();
    const auto *engine = pd_iface->engine();
    primitive_hashing::key_t key(pd, engine);
    return bool(primitive_cache().get_pd(key));
}

bool is_primitive_in_cache(const primitive_iface_t *p_iface) {
    return is_pd_in_cache(p_iface->pd());
}

status_t lru_primitive_cache_t::set_capacity(int capacity) {
    utils::lock_write_t lock_w(rw_mutex());
    capacity_ = (size_t)capacity;
    // Check if number of entries exceeds the new capacity
    if (cache_mapper_.size() > capacity_) {
        // Evict excess entries
        size_t n_excess_entries = cache_mapper_.size() - capacity_;
        evict(n_excess_entries);
    }
    return status::success;
}

int lru_primitive_cache_t::get_capacity() const {
    utils::lock_read_t lock_r(rw_mutex());
    return (int)capacity_;
}

// For undocumented API
int lru_primitive_cache_t::get_size() const {
    utils::lock_read_t lock_r(rw_mutex());
    return (int)cache_mapper_.size();
}

lru_primitive_cache_t::value_t lru_primitive_cache_t::get_or_add(
        const key_t &key, const value_t &value) {
    // 1. Section with shared access (read lock)
    lock_read();
    // Check if the cache is enabled.
    if (capacity_ == 0) {
        unlock_read();
        return value_t();
    }
    // Check if the requested entry is present in the cache (likely cache_hit)
    auto e = get(key);
    if (e.valid()) {
        unlock_read();
        return e;
    }

    unlock_read();

    // 2. Section with exclusive access (write lock).
    // In a multithreaded scenario, in the context of one thread the cache
    // may have changed by another thread between releasing the read lock and
    // acquiring the write lock (a.k.a. ABA problem), therefore additional
    // checks have to be performed for correctness.
    // Double check the capacity due to possible race condition
    lock_write();
    if (capacity_ == 0) {
        unlock_write();
        return value_t();
    }

    // Double check if the requested entry is present in the cache (unlikely
    // cache_hit).
    e = get(key);
    if (!e.valid()) {
        // If the entry is missing in the cache then add it (cache_miss)
        add(key, value);
    }
    unlock_write();
    return e;
}

void lru_primitive_cache_t::add(const key_t &key, const value_t &value) {
    // std::list::size() method has linear complexity. Check the primitive cache
    // size using std::unordered_map::size();
    if (cache_mapper_.size() == capacity_) {
        // Evict the least recently used entry
        evict(1);
    }

    size_t timestamp = get_timestamp();

    auto res = cache_mapper_.emplace(std::piecewise_construct,
            std::forward_as_tuple(key),
            std::forward_as_tuple(value, timestamp));
    MAYBE_UNUSED(res);
    assert(res.second);
}

lru_primitive_cache_t::value_t lru_primitive_cache_t::get(const key_t &key) {
    auto it = cache_mapper_.find(key);
    if (it == cache_mapper_.end()) return value_t();

    size_t timestamp = get_timestamp();
    it->second.timestamp_.store(timestamp);
    // Return the entry
    return it->second.value_;
}

std::shared_ptr<primitive_desc_t> lru_primitive_cache_t::get_pd(
        const key_t &key) {
    lock_read();
    auto e = get(key);
    unlock_read();

    if (e.valid()) return e.get().primitive->pd();
    return nullptr;
}

void lru_primitive_cache_t::remove_if_invalidated(const key_t &key) {
    lock_write();
    auto it = cache_mapper_.find(key);
    if (it == cache_mapper_.end()) {
        // The entry has been already evicted at this point
        unlock_write();
        return;
    }

    const auto &value = it->second.value_;
    if (value.get().primitive) {
        // If the entry is not invalidated
        unlock_write();
        return;
    }

    // Remove the invalidated entry
    cache_mapper_.erase(it);
    unlock_write();
}

void lru_primitive_cache_t::update_entry(
        const key_t &key, const primitive_desc_t *pd) {
    utils::lock_write_t lock_w(rw_mutex());
    auto it = cache_mapper_.find(key);

    // There is nothing to do in two cases:
    // 1. The requested entry is not in the cache because it has been evicted
    //    by another thread
    // 2. After the requested entry had been evicted it was inserted again
    //    by another thread
    if (it == cache_mapper_.end() || it->first.thread_id() != key.thread_id())
        return;

    const auto *op_desc = pd->op_desc();
    const auto *attr = pd->attr();

    // Update key in cache_mapper_
    it->first.op_desc_ = op_desc;
    it->first.attr_ = attr;
}

// Evicts n the least recently used entries
void lru_primitive_cache_t::evict(size_t n) {
    if (n == capacity_) {
        cache_mapper_.clear();
        return;
    }

    for (size_t e = 0; e < n; e++) {
        // Find the smallest timestamp
        // TODO: revisit the eviction algorithm due to O(n) complexity, E.g.
        // maybe evict multiple entries at once.
        auto it = std::min_element(cache_mapper_.begin(), cache_mapper_.end(),
                [&](const decltype(cache_mapper_)::value_type &left,
                        const decltype(cache_mapper_)::value_type &right) {
                    // By default, load() and operator T use sequentially
                    // consistent memory ordering, which enforces writing the
                    // timestamps into registers in the same exact order they
                    // are read from the CPU cache line. Since eviction is
                    // performed under a write lock, this order is not
                    // important, therefore we can safely use the weakest memory
                    // ordering (relaxed). This brings about a few microseconds
                    // performance improvement for default primitive cache
                    // capacity.
                    return left.second.timestamp_.load(
                                   std::memory_order_relaxed)
                            < right.second.timestamp_.load(
                                    std::memory_order_relaxed);
                });
        auto res = cache_mapper_.erase(it->first);
        MAYBE_UNUSED(res);
        assert(res);
    }
}

} // namespace impl
} // namespace dnnl

// API
dnnl::impl::status_t dnnl_get_primitive_cache_capacity(int *capacity) {
    if (capacity == nullptr) return dnnl::impl::status::invalid_arguments;
    *capacity = 0;
#ifndef DNNL_DISABLE_PRIMITIVE_CACHE
    *capacity = dnnl::impl::primitive_cache().get_capacity();
#endif
    return dnnl::impl::status::success;
}

dnnl::impl::status_t dnnl_set_primitive_cache_capacity(int capacity) {
    if (capacity < 0) return dnnl::impl::status::invalid_arguments;
#ifndef DNNL_DISABLE_PRIMITIVE_CACHE
    return dnnl::impl::primitive_cache().set_capacity(capacity);
#endif
    return dnnl::impl::status::success;
}
