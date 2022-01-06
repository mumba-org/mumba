// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_MERKLE_TREE_
#define MUMBA_STORAGE_MERKLE_TREE_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"

namespace storage {
class SecureHash;
class MerkleTree;
class FileSet;
/*
 * Note: the problem here might be this a in-memory structure
 * and depending on the number of the open entries, this might
 * be too much to hold on memory
 * 
 * So maybe we should design something where we have each
 * node filling 4k/8k/16k blocks (for 16k we can have 512 sha256 hashes on each block)
 * and have a 'CacheAddress' pointing to the 'next' MerkleBlock on disk.
 * 
 * Also, maybe thats not a problem giving we are using StringPiece, and the 'BlockFiles'
 * are mmaped anyway, so we are pointing straight to the mmaped memory region for the
 * file contents and there are no copies or duplicated content on memory (so its a non-issue).
 */

extern size_t kHashSize;

class MerkleTreeNode {
public:
  MerkleTreeNode();
  MerkleTreeNode(uint64_t level);
  ~MerkleTreeNode();
  
  /*
   * is considered valid if:
   *   if is being calculated and Update()/Final() were called
   *   if is recovered from store with a valid hash
   */
  bool valid() const {
    return valid_;
  }

  char* hash() const {
    return hash_;
  }

  uint64_t level() const {
    return level_;
  }

  bool is_root() const {
    return level_ == 0;
  }

  bool is_zero() const;
  size_t sibling_offset() const;
  size_t parent_offset() const;

  bool Init(void* digest_buffer, bool computed = false);
  bool Init(const void* digest_buffer, bool computed = false);
  bool Update(const void* data, size_t len);
  bool Update(const MerkleTreeNode& other);
  bool Update(MerkleTreeNode* other);
  void Clear();
  bool Finish();

private:
  friend class MerkleTree;
  MerkleTreeNode(uint64_t level, void* digest_buffer);
  
  bool valid_;
  bool initialized_;
  uint64_t level_;
  //base::StringPiece hash_;
  char* hash_;
  std::unique_ptr<SecureHash> hasher_;

  DISALLOW_COPY_AND_ASSIGN(MerkleTreeNode);
};

class MerkleTree {
public:
  static size_t GetTreeLength(size_t data_size);

  static std::unique_ptr<MerkleTree> Create(size_t data_size);
  static std::unique_ptr<MerkleTree> Create(FileSet* fileset);
  static std::unique_ptr<MerkleTree> CreateAndBuild(const void* input_data, size_t input_size);
  static std::unique_ptr<MerkleTree> CreateAndBuild(FileSet* fileset);
  static std::unique_ptr<MerkleTree> Load(const void* input_digests, size_t input_len);
  //static std::unique_ptr<MerkleTree> LoadNodes(const void* input_digests, size_t nodes);

  MerkleTree(size_t block_count);
  ~MerkleTree();

  size_t node_count() const {
    return node_count_;
  }

  size_t block_count() const {
    return block_count_;
  }

  size_t leaf_count() const {
    return leaf_count_;
  }

  size_t block_offset() const {
    return block_offset_;
  }

  size_t first_leaf_offset() const {
    return first_leaf_;
  }

  bool is_dirty() const {
    return is_dirty_;
  }

  const MerkleTreeNode* first_leaf() const {
    return nodes_[first_leaf_].get();
  }

  const MerkleTreeNode* node(size_t index) const {
    return nodes_[index].get();
  }

  bool digest_buffer_changed() const {
    return digest_buffer_realloc_;
  }

  // is valid if all its nodes are valid
  bool valid() const;

  //net::IOBuffer* digest_buffer() const { 
  //  return io_buffer_.get();
  //}
  bool Encode(char* buf);
  bool Decode(const char* buf, size_t len);

  bool NodeIsSet(size_t index) const;

  size_t digest_size() const {
    return nodes_.size() * kHashSize;
  }

  size_t digest_allocated_size() const {
    return digest_allocated_size_;
  }

  std::string root_hash() const;

  void Init();

  bool AddLeaf(const void* input_data, size_t input_size);
  bool AddLeaf(int64_t offset, const void* input_data, size_t input_size);
  bool UpdateLeaf(int64_t offset, const void* input_data, size_t input_size);

  bool Build(const void* input_data, size_t input_len);
  bool Build(FileSet* fileset);
  bool Build();
  bool Rebuild();

  // verify all
  bool Verify(const void* data, size_t data_len);
  
  // verify only a block
  bool VerifyBlock(size_t block_offset, const void* data);

  bool VerifyBlocks(size_t start_offset, size_t end_offset, const void* data, size_t data_len);
  
  void Print();

private:

  net::IOBuffer* digest_buffer() const { 
    return io_buffer_.get();
  }

  bool LoadInternal(const void* input_digests, size_t data_len);
  bool ShouldGrow(size_t new_offset) const {
    // we dont use node count because grow factor is 10 units ahead
    size_t allocated_items = digest_allocated_size_ / kHashSize;
    return new_offset >= allocated_items;
  }
  void GrowDigestBuffer(size_t node_realloc_offset);
  void DigestBufferChanged();

  MerkleTreeNode* root_;

  char* digest_buffer_;
  char* digest_last_pos_;
  scoped_refptr<net::WrappedIOBuffer> io_buffer_;

  std::vector<std::unique_ptr<MerkleTreeNode>> nodes_;

  size_t block_count_;
  size_t leaf_count_;
  size_t node_count_;
  size_t first_leaf_;
  size_t digest_allocated_size_;
  size_t block_offset_;
  size_t node_realloc_offset_;
  size_t old_first_leaf_;

  bool valid_;
  bool is_dirty_;
  bool digest_buffer_realloc_;
 
  DISALLOW_COPY_AND_ASSIGN(MerkleTree);
};

}

#endif
