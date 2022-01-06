// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_APPLICATION_PAGE_MANAGER_H_
#define MUMBA_CORE_HOST_APPLICATION_PAGE_MANAGER_H_

#include <unordered_map>
#include <string>

#include "base/macros.h"
#include "base/hash.h"
#include "base/atomic_sequence_num.h"
#include "core/host/application/entry_node.h"

namespace std {

template <>
struct hash<pair<string, string>>
    : public unary_function<pair<string, string>, size_t>
{
    size_t operator()(pair<string, string> value) const _NOEXCEPT {
      uint32_t a = base::PersistentHash(value.first.data(), value.first.size());
      uint32_t b = base::PersistentHash(value.second.data(), value.second.size());
      // NOTE: see if we really need to "rehash" giving the two ints are not really
      //       values but hashes.. maybe just or'ing both with a giving mask is enough?
      // anyway, at least this will garantee this hash is ok.
      // TODO: check if this estravaganza isnt too computationally expensive
      //       for such a vain endeavor (using a tuple of strings as a secondary index)
      return base::HashInts(a, b);
    }
};  

}

namespace host {

class EntryManager {
public:
  typedef std::string Scheme;
  typedef std::string Path;
  typedef std::pair<Scheme, Path> Address; 
  typedef std::unordered_map<Address, int> EntriesIndex;
  typedef std::unordered_map<int, std::unique_ptr<EntryNode>> Entries;
  
  EntryManager();
  ~EntryManager();

  void AddEntry(const Scheme& scheme, const Path& path, std::unique_ptr<EntryNode> entry);
  void RemoveEntry(const Scheme& scheme, const Path& path);
  EntryNode* LookupEntry(const Scheme& scheme, const Path& path);
  std::vector<EntryNode*> GetEntryListForScheme(const Scheme& scheme);
  
  // avoid exposing these because they are not thread safe

  // const Entries& entries() const {
  //   return entries_;
  // }

  // Entries& entries() {
  //   return entries_;
  // }

private:
  base::AtomicSequenceNumber entry_id_gen_;
  base::Lock lock_;
  EntriesIndex index_;
  Entries entries_;

  DISALLOW_COPY_AND_ASSIGN(EntryManager);
};

}

#endif