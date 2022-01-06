// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/merkle_tree.h"

#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "storage/hash.h"
#include "storage/file_set.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace storage {

size_t kHashSize = SHA_DIGEST_LENGTH;


namespace {

constexpr size_t kBlockSize = 65536;
constexpr SecureHash::Algorithm kDefaultHasher = SecureHash::SHA1;
constexpr char kZeroFilledSha1[SHA_DIGEST_LENGTH] = {0,0,0,0,0,0,0,0,0,0,
                                             0,0,0,0,0,0,0,0,0,0};

size_t GetBlockCount(size_t len) {
  return (len + kBlockSize - 1) / kBlockSize;
}

size_t GetMerkleParent(size_t tree_node) {
  // node 0 doesn't have a parent
  DCHECK(tree_node > 0);
  return (tree_node - 1) / 2;
}

size_t GetMerkleSibling(size_t tree_node) {
  // node 0 doesn't have a sibling
  DCHECK(tree_node > 0);
  // even numbers have their sibling to the left
  // odd numbers have their sibling to the right
  return tree_node + ((tree_node&1)?1:-1);
}

size_t GetMerkleNodeCount(size_t leafs) {
  DCHECK(leafs > 0);
  return (leafs << 1) - 1;
}

size_t GetMerkleLeafCount(size_t pieces) {
  DCHECK(pieces > 0);
  // round up to nearest 2 exponent
  size_t ret = 1;
  while (pieces > ret) ret <<= 1;
  return ret;
}
  

}

MerkleTreeNode::MerkleTreeNode(): 
  valid_(false),
  initialized_(false),
  level_(std::numeric_limits<uint64_t>::max()),
  hash_(0) {

}

MerkleTreeNode::MerkleTreeNode(uint64_t level): 
  valid_(false),
  initialized_(false),
  level_(level),
  hash_(0) {

}

MerkleTreeNode::MerkleTreeNode(uint64_t level, void* digest_buffer):
  valid_(true),
  initialized_(true),
  level_(level), 
  hash_(reinterpret_cast<char *>(digest_buffer)){

}

MerkleTreeNode::~MerkleTreeNode() {

}

size_t MerkleTreeNode::sibling_offset() const {
  DCHECK(level_ != 0);
  return GetMerkleSibling(level_);
}

size_t MerkleTreeNode::parent_offset() const {
  DCHECK(level_ != 0);
  return GetMerkleParent(level_);
}

bool MerkleTreeNode::is_zero() const {
  return initialized_ && memcmp(hash_, kZeroFilledSha1, kHashSize) == 0;
}

bool MerkleTreeNode::Init(void* digest_buffer, bool computed) {
  hash_ = reinterpret_cast<char *>(digest_buffer);
  hasher_ = SecureHash::Create(kDefaultHasher);
  initialized_ = true;
  if (computed) 
    valid_ = true;
  return true;
}

bool MerkleTreeNode::Init(const void* digest_buffer, bool computed) {
  return Init(const_cast<void*>(digest_buffer), computed);
}

bool MerkleTreeNode::Update(const void* data, size_t len) {
  DCHECK(initialized_);
  hasher_->Update(data, len);
  return true;
}

bool MerkleTreeNode::Update(const MerkleTreeNode& other) {
  DCHECK(initialized_ && other.initialized_);
  hasher_->Update(other.hash_, kHashSize);
  return true;
}

bool MerkleTreeNode::Update(MerkleTreeNode* other) {
  DCHECK(initialized_ && other->initialized_);
  hasher_->Update(other->hash_, kHashSize);
  return true;
}

void MerkleTreeNode::Clear() {
  memset(hash_, 0, kHashSize);
}

bool MerkleTreeNode::Finish() {
  DCHECK(initialized_);
  hasher_->Finish(hash_);
  hasher_.reset();
  valid_ = true;
  return true;
}

// static 
size_t MerkleTree::GetTreeLength(size_t data_size) {
  const size_t num_blocks = GetBlockCount(data_size);
  const size_t num_leafs = GetMerkleLeafCount(num_blocks);
	return GetMerkleNodeCount(num_leafs);  
}

// static 

std::unique_ptr<MerkleTree> MerkleTree::Create(size_t data_len) {
  const size_t block_count = GetBlockCount(data_len);
  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(block_count);
  result->Init();
  return result;
}

// static 
std::unique_ptr<MerkleTree> MerkleTree::Create(FileSet* fileset) {
  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(fileset->GetTotalBlockCount());
  result->Init();
  return result;
}

// static 
std::unique_ptr<MerkleTree> MerkleTree::CreateAndBuild(const void* input_data, size_t input_size) {
  const size_t block_count = GetBlockCount(input_size);
  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(block_count);
  result->Init();
  if (!result->Build(input_data, input_size)) {
    return {};
  }
  return result;
}

// static 
std::unique_ptr<MerkleTree> MerkleTree::CreateAndBuild(FileSet* fileset) {
  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(fileset->GetTotalBlockCount());
  result->Init();
  if (!result->Build(fileset)) {
    return {};
  }
  return result;
}

// static 
std::unique_ptr<MerkleTree> MerkleTree::Load(const void* input_digests, size_t input_len) {
  const size_t block_count = GetBlockCount(input_len);
  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(block_count);
  result->Init();
  if (!result->LoadInternal(input_digests, input_len)) {
    return {};
  }
  return result;
}

// static 
//std::unique_ptr<MerkleTree> MerkleTree::LoadNodes(const void* input_digests, size_t nodes) {
//  std::unique_ptr<MerkleTree> result = std::make_unique<MerkleTree>(nodes);
//  result->Init();
//  if (!result->LoadInternal(input_digests, nodes * kHashSize)) {
//    return {};
//  }
//  return result;
//}

MerkleTree::MerkleTree(size_t block_count):
  digest_buffer_(nullptr),
  digest_last_pos_(nullptr),
  block_count_(block_count),
  leaf_count_(GetMerkleLeafCount(block_count_)),
  node_count_(GetMerkleNodeCount(leaf_count_)),
  first_leaf_(node_count_ - leaf_count_),
  digest_allocated_size_(node_count_ * kHashSize),
  block_offset_(0),
  node_realloc_offset_(0),
  old_first_leaf_(0),
  valid_(false),
  is_dirty_(false),
  digest_buffer_realloc_(false) {

}

MerkleTree::~MerkleTree() {
  root_ = nullptr;
  nodes_.clear();
  if (digest_buffer_) {
    free(digest_buffer_);
  }
}

std::string MerkleTree::root_hash() const {
  //DCHECK(root_);
  if (root_->valid()) {
    return std::string(root_->hash(), SHA_DIGEST_LENGTH);
  } else if (root_->is_zero()) {
    DLOG(INFO) << "MerkleTree::root_hash: warning: root node is not valid";
    return std::string(kZeroFilledSha1, SHA_DIGEST_LENGTH);
  }
  DLOG(INFO) << "MerkleTree::root_hash: warning: root node is not valid";
  return std::string();
}

bool MerkleTree::valid() const {
  for (auto it = nodes_.begin(); it != nodes_.end(); ++it) {
    MerkleTreeNode* node = it->get();
    if (!node->valid()) {
      return false;
    }
  }
  return true;
}

bool MerkleTree::NodeIsSet(size_t index) const {
  if (index >= node_count()) {
    return false;
  }
  if (nodes_.size() <= index) {
    return false;
  }
  if (nodes_[index].get() == nullptr) {
    return false;
  }
  if (nodes_[index]->hash_ == nullptr) {
    return false;
  }
  return nodes_[index]->valid() || nodes_[index]->is_zero();
}

void MerkleTree::Init() {
  // allocate the buf
  digest_buffer_ = static_cast<char *>(malloc(digest_allocated_size_));
  io_buffer_ = new net::WrappedIOBuffer(digest_buffer_);
  nodes_.reserve(node_count_);
  for (size_t i = 0; i < node_count_; ++i) {
    nodes_.push_back(std::make_unique<MerkleTreeNode>());
  }
  root_ = nodes_[0].get();
}

bool MerkleTree::Encode(char* buf) {
  // copy in a sequencial manner
  for (size_t i = 0; i < node_count_; i++) {
    memcpy(buf, nodes_[i]->hash(), kHashSize);
    buf += kHashSize;
  }
  return true;
}

bool MerkleTree::Decode(const char* buf, size_t len) {
  // decode in a sequencial manner
  // Init() should have been called first
  char* current = const_cast<char *>(buf);
  char* ptr = nullptr;
  for (size_t i = 0; i < node_count_; i++) {
    ptr = nodes_[i]->hash();
    memcpy(ptr, current, kHashSize);
    current += kHashSize;
  }
  return true;
}

bool MerkleTree::AddLeaf(const void* input_data, size_t input_size) {
  size_t node_offset = first_leaf_ + block_offset_;
  return AddLeaf(node_offset, input_data, input_size);
}

bool MerkleTree::AddLeaf(int64_t node_offset, const void* input_data, size_t input_size) {
  size_t current_pos = node_offset - first_leaf_;

  if (ShouldGrow(node_offset)) {
    // make room for digests
    GrowDigestBuffer(node_offset);
  }

  if (node_offset >= nodes_.size()) {   
    size_t diff = node_offset - (nodes_.size() + 1);
    for (size_t i = 0; i < diff; ++i) {
      nodes_.push_back(std::make_unique<MerkleTreeNode>());
      block_count_++;
    }
    
    leaf_count_ = GetMerkleLeafCount(block_count_);
    node_count_ = GetMerkleNodeCount(leaf_count_);
  }
  // reset the block offset so we know that the 0 offset
  // was actually rset
  char* ptr = nullptr;
  if (digest_buffer_realloc_) {
    ptr = digest_last_pos_;//digest_buffer_ + (kHashSize * node_offset);
  } else {
    //LOG(INFO) << "positioning pointer pos: " << current_pos << " node_offset: " << node_offset;
    ptr = current_pos == 0 ? digest_buffer_ : digest_buffer_ + (kHashSize * current_pos);
  }

  DCHECK((uintptr_t)ptr < (uintptr_t)(digest_buffer_ + digest_allocated_size_));
 
  const char* hash_start = reinterpret_cast<const char*>(input_data);
  size_t hash_size = kBlockSize > input_size ? input_size : kBlockSize;

  nodes_[node_offset]->level_ = node_offset;
  nodes_[node_offset]->Init(ptr);
  nodes_[node_offset]->Update(hash_start, hash_size);
  nodes_[node_offset]->Finish();

  //DLOG(INFO) << "AddLeaf: hashed offset " << node_offset << " size: " << input_size << " : " << base::ToLowerASCII(base::HexEncode(nodes_[node_offset]->hash(), kHashSize));

  if (digest_buffer_realloc_) {
    digest_last_pos_ += kHashSize;
  } 

  current_pos == 0 ? block_offset_++ : block_offset_ += current_pos;

  is_dirty_ = true;

  return true;
}

bool MerkleTree::UpdateLeaf(int64_t offset, const void* input_data, size_t input_size) {
  DCHECK(offset >= first_leaf_);
  const char* hash_start = reinterpret_cast<const char*>(input_data);
  size_t hash_size = kBlockSize > input_size ? input_size : kBlockSize;
  
  size_t digest_offset = offset - first_leaf_;

  char* ptr = digest_offset == 0 ? digest_buffer_ : digest_buffer_ + (kHashSize * digest_offset);
  
  nodes_[offset]->level_ = offset;
  nodes_[offset]->Init(ptr);
  nodes_[offset]->Update(hash_start, hash_size);
  nodes_[offset]->Finish();

  //DLOG(INFO) << "UpdateLeaf: hashed offset " << offset << " size: " << input_size << " : " << base::ToLowerASCII(base::HexEncode(nodes_[offset]->hash(), kHashSize));

  is_dirty_ = true;

  return true;
}

bool MerkleTree::Rebuild() {
  
  char* ptr = digest_buffer_;

  if (digest_buffer_realloc_) {
    //DLOG(INFO) << "oops theres nodes to add so we need to move the leaf_start to a new position";
    size_t nodes_to_add = node_count_ - nodes_.size();
    old_first_leaf_ = first_leaf_;
    first_leaf_ = node_count_ - leaf_count_;

    std::vector<std::unique_ptr<MerkleTreeNode>> leafs; 
    
    for (size_t i = old_first_leaf_; i < nodes_.size(); i++) {
      //DLOG(INFO) << "adding leaf: " << i << " : " << base::ToLowerASCII(base::HexEncode(nodes_[i]->hash(), kHashSize));
      leafs.push_back(std::move(nodes_[i]));
      nodes_[i] = std::make_unique<MerkleTreeNode>();
      //nodes_[i]->Init(local);
      //nodes_[i]->Clear();
    }

    for (size_t i = 0; i < nodes_to_add; ++i) {
      auto node = std::make_unique<MerkleTreeNode>();
      nodes_.push_back(std::move(node));
    }

    size_t offset = first_leaf_;
    for (size_t i = 0; i < leafs.size(); i++) {
      //DLOG(INFO) << "moving leaf: " << old_first_leaf_ + i << " to " << offset;
      nodes_[offset] = std::move(leafs[i]);
      nodes_[offset]->level_ = offset;
      DLOG(INFO) << "[" << offset << "] : " << base::ToLowerASCII(base::HexEncode(nodes_[offset]->hash(), kHashSize));
      offset++;
    }
    
    for (size_t i = old_first_leaf_; i < first_leaf_; i++) {
      auto node = std::make_unique<MerkleTreeNode>();
      nodes_[i] = std::move(node);
      nodes_[i]->level_ = i;
      nodes_[i]->Init(digest_last_pos_);
      nodes_[i]->Clear();
      digest_last_pos_ += kHashSize;
    }

    size_t rest_offset = first_leaf_ + leafs.size();
    for (size_t i = rest_offset; i < node_count_; ++i) {
      nodes_[i]->level_ = rest_offset;
      nodes_[i]->Init(digest_last_pos_);
      nodes_[i]->Clear();
      digest_last_pos_ += kHashSize;
    }
    
  }

  // jump the leafs as we want to refactor only root nodes
  //ptr = ptr + (kHashSize * leaf_count_);

  // refactor the root nodes according to the new values on leaf nodes
  size_t level_start = first_leaf_;
  size_t level_size = leaf_count_;
  //DLOG(INFO) << "MerkleTree::Rebuild: level_start(first_leaf_): " << level_start << " level_size(leaf_count_): " << level_size << " node_count: " << node_count_ << " nodes.size: " << nodes_.size();
  while (level_start > 0) {
    size_t parent = GetMerkleParent(level_start);
    for (size_t i = level_start; i < level_start + level_size; i += 2, ++parent) {
      
      nodes_[parent]->level_ = parent;
      //nodes_[parent]->Init(ptr);
      nodes_[parent]->Update(nodes_[i].get());
      nodes_[parent]->Update(nodes_[i + 1].get());
      nodes_[parent]->Finish();

     // DLOG(INFO) << "MerkleTree::Rebuild: parent: " << parent 
     //   << " hash(" << i << "): " <<  base::ToLowerASCII(base::HexEncode(nodes_[i]->hash(), kHashSize))
     //   << " + hash(" << i + 1 << "): " <<  base::ToLowerASCII(base::HexEncode(nodes_[i+1]->hash(), kHashSize))
      //  << " parent(" << parent << ") " << base::ToLowerASCII(base::HexEncode(nodes_[parent]->hash(), kHashSize));  
      //ptr = ptr + kHashSize;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  DCHECK(level_size == 1);
  valid_ = true;
  is_dirty_ = false;
  return true;
}

bool MerkleTree::Build() {
  char* ptr = digest_buffer_;
  //char* ptr = nullptr;

  //for debugging
  size_t offset = block_count_;

  //if (current_pos == 0) {
  ptr = ptr + (kHashSize * block_count_);
  //} else {
  //  digest_buffer_ + (kHashSize * current_pos);
  //}

  // jump the filled up leafs
  //ptr = ptr + (kHashSize * block_count_);
  // reset the 'rest' leafs to zero
  //DLOG(INFO) << "block_count_ = " << block_count_ << " leaf_count_ = " << leaf_count_;
  //DLOG(INFO) <<  "for (size_t i = " << block_count_ << " (block_count_); i < " << leaf_count_ << " (leaf_count_); ++i)";
  for (size_t i = block_count_; i < leaf_count_; ++i) {
    nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
    nodes_[first_leaf_ + i]->Init(ptr);
    nodes_[first_leaf_ + i]->Clear();
    //DLOG(INFO) << "zerado: " << first_leaf_ + i << " at " << (intptr_t)nodes_[first_leaf_ + i]->hash_ << " buf offset: " << offset;
    ptr = ptr + kHashSize;
    offset++;
  }

  // refactor the root nodes according to the new values on leaf nodes
  size_t level_start = first_leaf_;
  size_t level_size = leaf_count_;
  while (level_start > 0) {
    size_t parent = GetMerkleParent(level_start);
    for (size_t i = level_start; i < level_start + level_size; i += 2, ++parent) {
     // DLOG(INFO) << "parent: " << parent << " at " << (intptr_t)ptr << " buf offset: " << offset << " left " << i << ":" << (intptr_t)nodes_[i]->hash_ << " init: " << nodes_[i]->initialized_ << " right: " << i + 1 << ":" << (intptr_t)nodes_[i+1]->hash_ << " init: " << nodes_[i+1]->initialized_;
      nodes_[parent]->level_ = parent;
      nodes_[parent]->Init(ptr);
      nodes_[parent]->Update(nodes_[i].get());
      nodes_[parent]->Update(nodes_[i + 1].get());
      nodes_[parent]->Finish();
   //   DLOG(INFO) << "result: " << base::HexEncode(nodes_[parent]->hash(), kHashSize);
      ptr = ptr + kHashSize;
      offset++;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  DCHECK(level_size == 1);
  valid_ = true;
  is_dirty_ = false;
  return true;
}

bool MerkleTree::Build(const void* input_data, size_t input_size) {
  char* ptr = digest_buffer_;
  const char* hash_start = reinterpret_cast<const char*>(input_data);
  const char* hash_end = hash_start + input_size;
  size_t hash_size = kBlockSize > input_size ? input_size : kBlockSize;
  for (size_t i = 0; i < block_count_; ++i) {
    DCHECK((uintptr_t)ptr < (uintptr_t)(digest_buffer_ + digest_allocated_size_));
 
    nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
    nodes_[first_leaf_ + i]->Init(ptr);
    nodes_[first_leaf_ + i]->Update(hash_start, hash_size);
    nodes_[first_leaf_ + i]->Finish();
    ptr = ptr + kHashSize;
    hash_start += kBlockSize;
    hash_size = hash_start + kBlockSize > hash_end ? (hash_end - hash_start) : kBlockSize;
  }

  for (size_t i = block_count_; i < leaf_count_; ++i) {
    DCHECK((uintptr_t)ptr < (uintptr_t)(digest_buffer_ + digest_allocated_size_));
 
    nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
    nodes_[first_leaf_ + i]->Init(ptr);
    nodes_[first_leaf_ + i]->Clear();
    ptr = ptr + kHashSize;
  }

  size_t level_start = first_leaf_;
  size_t level_size = leaf_count_;
  while (level_start > 0) {
    size_t parent = GetMerkleParent(level_start);
    for (size_t i = level_start; i < level_start + level_size; i += 2, ++parent) {
      DCHECK((uintptr_t)ptr < (uintptr_t)(digest_buffer_ + digest_allocated_size_));
 
      nodes_[parent]->level_ = parent;
      nodes_[parent]->Init(ptr);
      nodes_[parent]->Update(nodes_[i].get());
      nodes_[parent]->Update(nodes_[i + 1].get());
      nodes_[parent]->Finish();
      ptr = ptr + kHashSize;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  DCHECK(level_size == 1);
  valid_ = true;
  is_dirty_ = false;
  return true;
}

bool MerkleTree::Build(FileSet* fileset) {
  //DLOG(INFO) << "MerkleTree::Build(FileSet): nodes_.size(): " << nodes_.size() << " node_count_: " << node_count_ << " digest_buffer size/nodes: " << digest_allocated_size_ << " = " << (digest_allocated_size_ / kHashSize) << " nodes";
  char* ptr = digest_buffer_;
  // global block offset
  size_t block_offset = 0;

  for (size_t i = 0; i < fileset->file_count(); ++i) {
    FileSet::Reader reader;
    char* input_data = 0;
    size_t blk_cnt_pfile = fileset->GetBlockCount(i);
    size_t file_size = fileset->GetLength(i);
    fileset->GetReader(i, &reader);
    reader.Read(0, &input_data, file_size);
    DCHECK(input_data);
    const char* hash_start = reinterpret_cast<const char*>(input_data);
    const char* hash_end = hash_start + file_size;
    size_t hash_size = kBlockSize > file_size ? file_size : kBlockSize;
    //DLOG(INFO) << "MerkleTree::Build(FileSet) processing file " << i << " size: " << file_size << " blocks: " << blk_cnt_pfile;

    for (size_t x = 0; x < blk_cnt_pfile; ++x) {
      DCHECK((uintptr_t)ptr < (uintptr_t)(digest_buffer_ + digest_allocated_size_));
      size_t leaf_offset = first_leaf_ + block_offset;
      //DLOG(INFO) << "MerkleTree::Build(FileSet) compute block " << x << " len " << hash_size << " file " << i << " len " << file_size << " : node [" << leaf_offset << "]";
      nodes_[leaf_offset]->level_ = leaf_offset;
      nodes_[leaf_offset]->Init(ptr);
      nodes_[leaf_offset]->Update(hash_start, hash_size);
      nodes_[leaf_offset]->Finish();
      ptr = ptr + kHashSize;
      hash_start += kBlockSize;
      hash_size = hash_start + kBlockSize > hash_end ? (hash_end - hash_start) : kBlockSize;
      block_offset++;
    }

  }

  size_t last_leaf_offset = first_leaf_ + (block_offset - 1);
  //DLOG(INFO) << "MerkleTree::Build(FileSet): block_count_ = " << block_count_ << " last leaf computed = " << block_offset << " offset: " << last_leaf_offset << " leaf_count_ = " << leaf_count_;  
  for (size_t i = block_count_; i < leaf_count_; ++i) {
    //DLOG(INFO) << "MerkleTree::Build(FileSet): clearing node [" << first_leaf_ + i << "]";
    nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
    nodes_[first_leaf_ + i]->Init(ptr);
    nodes_[first_leaf_ + i]->Clear();
    ptr += kHashSize;
  }

  size_t level_start = first_leaf_;
  size_t level_size = leaf_count_;
  while (level_start > 0) {
    size_t parent = GetMerkleParent(level_start);
    for (size_t i = level_start; i < level_start + level_size; i += 2, ++parent) {
    //  DLOG(INFO) << "MerkleTree::Build(FileSet): parent node [" << parent << "] = left[" << i << "] + right[" << i + 1 << "]";
      nodes_[parent]->level_ = parent;
      nodes_[parent]->Init(ptr);
      nodes_[parent]->Update(nodes_[i].get());
      nodes_[parent]->Update(nodes_[i + 1].get());
      nodes_[parent]->Finish();
      ptr = ptr + kHashSize;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  DCHECK(level_size == 1);
  valid_ = true;
  is_dirty_ = false;
  return true;
}

// bool MerkleTree::Build(FileSet* fileset) {
//   char* ptr = digest_buffer_;

//   for (size_t i = 0; i < fileset->file_count(); ++i) {
//     base::StringPiece hash = fileset->GetMerkleRoot(i);
//     memcpy(ptr, hash.data(), hash.size());
//     nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
//     nodes_[first_leaf_ + i]->Init(ptr, true /* previously computed */);
//     ptr += kHashSize;
//   }

//   for (size_t i = block_count_; i < leaf_count_; ++i) {
//     nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
//     nodes_[first_leaf_ + i]->Init(ptr);
//     nodes_[first_leaf_ + i]->Clear();
//     ptr += kHashSize;
//   }

//   size_t level_start = first_leaf_;
//   size_t level_size = leaf_count_;
//   while (level_start > 0) {
//     size_t parent = GetMerkleParent(level_start);
//     for (size_t i = level_start; i < level_start + level_size; i += 2, ++parent) {
//       nodes_[parent]->level_ = parent;
//       nodes_[parent]->Init(ptr);
//       nodes_[parent]->Update(nodes_[i].get());
//       nodes_[parent]->Update(nodes_[i + 1].get());
//       nodes_[parent]->Finish();
//       ptr = ptr + kHashSize;
//     }
//     level_start = GetMerkleParent(level_start);
//     level_size /= 2;
//   }
//   DCHECK(level_size == 1);
//   valid_ = true;
//   is_dirty_ = false;
//   return true;
// }

// bool MerkleTree::LoadInternal(const void* input_digests) {
//   const char* input_digest = reinterpret_cast<const char*>(input_digests);
//   char* output_digest = digest_buffer_;
//   // wish theres no copy, but we switched to a mutable/appendable merkle tree
//   // so we cant depend on external buffers and lifetime

//   // one way to do this, would be to use a Growable on the storage to
//   // and move it as the internal IOBuffer to prevent this copy
//   memcpy(output_digest, input_digest, digest_size());

//   for (size_t i = 0; i < leaf_count_; ++i) {
//     nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
//     nodes_[first_leaf_ + i]->Init(output_digest, true);
//     output_digest += kHashSize;
//     block_offset_++;
//   }

//   int level_start = first_leaf_;
//   int level_size = leaf_count_;
//   while (level_start > 0) {
//     int parent = GetMerkleParent(level_start);
//     for (int i = level_start; i < level_start + level_size; i += 2, ++parent) {
//       nodes_[parent]->level_ = parent;
//       nodes_[parent]->Init(output_digest, true);
//       output_digest += kHashSize;
//     }
//     level_start = GetMerkleParent(level_start);
//     level_size /= 2;
//   }
//   DCHECK(level_size == 1);
//   return true;
// }

bool MerkleTree::LoadInternal(const void* input_digests, size_t data_len) {
  char* output_digest = digest_buffer_;

  for (size_t i = 0; i < leaf_count_; ++i) {
    //DLOG(INFO) << "init " << first_leaf_ + i << " with " << (void*)output_digest;
    nodes_[first_leaf_ + i]->level_ = first_leaf_ + i;
    nodes_[first_leaf_ + i]->Init(output_digest, true);
    output_digest += kHashSize;
    block_offset_++;
  }

  int level_start = first_leaf_;
  int level_size = leaf_count_;
  while (level_start > 0) {
    int parent = GetMerkleParent(level_start);
    for (int i = level_start; i < level_start + level_size; i += 2, ++parent) {
     // DLOG(INFO) << "init " << parent << " with " << (void*)output_digest;
      nodes_[parent]->level_ = parent;
      nodes_[parent]->Init(output_digest, true);
      output_digest += kHashSize;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  return Decode(reinterpret_cast<const char *>(input_digests), data_len);
}

bool MerkleTree::Verify(const void* data, size_t data_len) {
  return false;
}

bool MerkleTree::VerifyBlock(size_t block_offset, const void* data) {
  return false;
}

bool MerkleTree::VerifyBlocks(size_t start_offset, size_t end_offset, const void* data, size_t data_len) {
  return false;
}

void MerkleTree::Print() {
  //if (is_dirty_) {
  //  DLOG(ERROR) << "cannot print. the tree is dirty, so it may be in a inconsistent state";
  //  return;
  //}
  for (size_t j = 0; j < node_count(); j++) {
    const MerkleTreeNode* n = node(j);
    std::string node_str = n->hash() ? base::ToLowerASCII(base::HexEncode(n->hash(), kHashSize)) : "";
    printf("[%zu] level: %zu: %s\n", j, n->level_, node_str.c_str());
  }
}

void MerkleTree::GrowDigestBuffer(size_t node_realloc_offset) {
  //printf("merkle tree before grow:\n");
  //Print();
  size_t grow_size = kHashSize * 10;
  digest_allocated_size_ += grow_size;
  char* old_pos = digest_buffer_;
  digest_buffer_ = reinterpret_cast<char *>(realloc(digest_buffer_, digest_allocated_size_));
  digest_buffer_realloc_ = true;
  node_realloc_offset_ = node_realloc_offset;
 // DLOG(INFO) << "growing digest buffer: old: " << (void *) old_pos  << " new:" << (void *)digest_buffer_;
  DigestBufferChanged();
}

void MerkleTree::DigestBufferChanged() {
  digest_last_pos_ = digest_buffer_;
  for (size_t i = 0; i < leaf_count_; ++i) {
    nodes_[first_leaf_ + i]->Init(digest_last_pos_, true);
    digest_last_pos_ += kHashSize;
  }

  int level_start = first_leaf_;
  int level_size = leaf_count_;
  while (level_start > 0) {
    int parent = GetMerkleParent(level_start);
    for (int i = level_start; i < level_start + level_size; i += 2, ++parent) {
      nodes_[parent]->Init(digest_last_pos_, true);
      digest_last_pos_ += kHashSize;
    }
    level_start = GetMerkleParent(level_start);
    level_size /= 2;
  }
  DCHECK(level_size == 1);
  //printf("merkle tree after grow:\n");
  //Print();
}

}
