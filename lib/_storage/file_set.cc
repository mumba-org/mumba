// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/file_set.h"

#include "base/strings/stringprintf.h"
#include "base/files/file_util.h"
#include "storage/merkle_tree.h"

namespace storage {

namespace {

constexpr size_t kBlockSize = 65536;

}

FileSet::Reader::Reader(): 
  file_id_(0), 
  offset_(0), 
  length_(0) {

}

void FileSet::Reader::Init(int file_id, const base::MemoryMappedFile* file) {
  file_id_ = file_id;
  file_ = file;
  length_ = file->length();
}

int64_t FileSet::Reader::Read(size_t offset, char** start, size_t size) {
  offset_ = offset <= length_ ? offset : length_;
  size_t offset_size = offset_ + size;
  // check if the size is safe, or else cut to remaining
  size_t to_read = offset_size <= length_ ? size : length_ - offset_;
  // theres a chance that its zero, so we have nothing else to read
  if (to_read == 0)
   return 0;

  //printf("  reading %zu from %zu to %zu of %zu\n", to_read, offset_, (offset_ + to_read) ,length_);
  
  *start = const_cast<char *>(reinterpret_cast<const char *>(file_->data() + offset_));

  return to_read;
}

FileSet::Writer::Writer(): 
  file_id_(0), 
  offset_(0), 
  length_(0) {

}

void FileSet::Writer::Init(int file_id, base::MemoryMappedFile* file) {
  file_id_ = file_id;
  file_ = file;
  length_ = file->length();
}

int64_t FileSet::Writer::Write(size_t offset, char* buffer, size_t size) {
  offset_ = offset;
  uint8_t* dest = file_->data() + offset_;
  memcpy(dest, buffer, size);
  return size;
}

FileSet::FileSet() {

}
  
FileSet::~FileSet() {

}

int FileSet::Load(const base::FilePath& file_path, size_t size, bool readonly) {
  std::unique_ptr<base::MemoryMappedFile> mmaped_file(new base::MemoryMappedFile);
  
  if (!base::PathExists(file_path) && size > 0) {
    if (readonly)
      return -1;
    
    base::File file(file_path, base::File::FLAG_CREATE | base::File::FLAG_READ | base::File::FLAG_WRITE);
    base::MemoryMappedFile::Region region = {0, size};
    
    if (!mmaped_file->Initialize(std::move(file), region, base::MemoryMappedFile::READ_WRITE_EXTEND)) {
      return -1;
    }
  } else {
    if (!mmaped_file->Initialize(file_path, readonly ? base::MemoryMappedFile::READ_ONLY : base::MemoryMappedFile::READ_WRITE_EXTEND)) {
      return -1;
    }
  }
  int num = next_file_.GetNext();
  file_path_map_.emplace(std::make_pair(file_path.value(), num));
  files_.emplace(std::make_pair(num, std::move(mmaped_file)));
  return num;
}

void FileSet::Unload(const base::FilePath& file_path) {
  auto it = file_path_map_.find(file_path.value());
  if (it == file_path_map_.end()) {
    return;
  }
  files_.erase(files_.find(it->second));
}

void FileSet::Unload(int file) {
  auto it = files_.find(file);
  if (it == files_.end()) {
    return;
  }
  files_.erase(it);

  for (auto it = file_path_map_.begin(); it != file_path_map_.end(); ++it) {
    if (it->second == file) {
      file_path_map_.erase(it);
      break;
    }
  }
}

void* FileSet::Map(int index) {
  auto it = files_.find(index);
  if (it == files_.end()) {
    return nullptr;
  }
  return it->second->data();
}

size_t FileSet::GetBlockCount(int index) const {
  auto it = files_.find(index);
  if (it == files_.end()) {
    return 0;
  }
  return GetBlockCountInternal(it->second.get());
}

base::StringPiece FileSet::GetPath(int index) const {
  for (auto it = file_path_map_.begin(); it != file_path_map_.end(); ++it) {
    if (it->second == index) {
      return base::StringPiece(it->first);
    }
  }
  return base::StringPiece();
}

size_t FileSet::GetLength(int index) const {
  auto it = files_.find(index);
  if (it == files_.end()) {
    return 0;
  }
  return it->second->length();
}

size_t FileSet::GetLength(const base::FilePath& file_path) const {
  auto it = file_path_map_.find(file_path.value());
  if (it == file_path_map_.end()) {
    return 0;
  }
  return files_.find(it->second)->second->length();
}

size_t FileSet::GetTotalLength() const {
  size_t total = 0;
  for (auto it = files_.begin(); it != files_.end(); ++it) {
    total += it->second->length();
  }
  return total;
}

size_t FileSet::GetTotalBlockCount() const {
  int total = 0;
  for (auto it = files_.begin(); it != files_.end(); ++it) {
    total += GetBlockCountInternal(it->second.get());
  }
  return total;
}

bool FileSet::GetReader(const base::FilePath& file_path, FileSet::Reader* reader) const {
  auto it = file_path_map_.find(file_path.value());
  if (it == file_path_map_.end()) {
    return false;
  }
  int id = it->second;
  // the other index check make this safe
  const base::MemoryMappedFile* file = files_.find(id)->second.get();
  reader->Init(id, file);
  return true;
}

bool FileSet::GetReader(int index, FileSet::Reader* reader) const {
  auto it = files_.find(index);
  if (it == files_.end()) {
    return false;
  }
  const base::MemoryMappedFile* file = it->second.get();
  reader->Init(index, file);
  return true;
}

bool FileSet::GetWriter(const base::FilePath& file_path, FileSet::Writer* writer) const {
  auto it = file_path_map_.find(file_path.value());
  if (it == file_path_map_.end()) {
    return false;
  }
  int id = it->second;
  // the other index check make this safe
  base::MemoryMappedFile* file = files_.find(id)->second.get();
  writer->Init(id, file);
  return true;
}

bool FileSet::GetWriter(int index, FileSet::Writer* writer) const {
  auto it = files_.find(index);
  if (it == files_.end()) {
    return false;
  }
  base::MemoryMappedFile* file = it->second.get();
  writer->Init(index, file);
  return true;
}

MerkleTree* FileSet::GetMerkleTree(int index) const {
  auto it = merkle_trees_.find(index);
  if (it == merkle_trees_.end()) {
    return nullptr;
  }
  return it->second.get();
}

std::string FileSet::GetMerkleRoot(int index) const {
  auto it = merkle_trees_.find(index);
  if (it == merkle_trees_.end()) {
    return std::string();
  }
  return it->second->root_hash();
}

void FileSet::SetMerkleTree(int index, std::unique_ptr<MerkleTree> merkle_tree) {
  merkle_trees_.emplace(std::make_pair(index, std::move(merkle_tree)));
}

// size_t FileSet::GetBlockCountInternal(base::MemoryMappedFile* file) const {
//   const size_t len = file->length();
//   size_t block_count = len / kBlockSize;

//   if (block_count <= 0 && len > 0) {
//     return 1;
//   }

//   size_t rest = len - (block_count * kBlockSize);
//   if (rest > 0) {
//     block_count++;
//   }

//   return block_count;
// }

size_t FileSet::GetBlockCountInternal(base::MemoryMappedFile* file) const {
  return (file->length() + kBlockSize - 1) / kBlockSize;
}

}