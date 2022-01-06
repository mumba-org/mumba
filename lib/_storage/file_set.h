// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_FILE_SET_H_
#define MUMBA_STORAGE_FILE_SET_H_

#include <vector>
#include <map>
#include <unordered_map>

#include "base/macros.h"
#include "base/atomic_sequence_num.h"
#include "base/files/memory_mapped_file.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"

namespace storage {
class MerkleTree;

class FileSet {
public:
  class Reader {
  public:
    Reader();
    ~Reader() = default;

    void Init(int file_id, const base::MemoryMappedFile* file);

    int file_id() const {
      return file_id_;
    }

    int64_t Read(size_t offset, char** start, size_t size);

  private:
    int file_id_;
    size_t offset_;
    size_t length_;
    const base::MemoryMappedFile* file_;
  };
  class Writer {
  public:
    Writer();
    ~Writer() = default;
    
    void Init(int file_id, base::MemoryMappedFile* file);

    int64_t Write(size_t offset, char* buffer, size_t size);

  private:
    int file_id_;
    size_t offset_;
    size_t length_;
    base::MemoryMappedFile* file_;
  };
  FileSet();
  ~FileSet();

  size_t file_count() const {
    return files_.size();
  }

  int Load(const base::FilePath& file_path, size_t size = 0, bool readonly = true);
  void Unload(const base::FilePath& file_path);
  void Unload(int file);

  base::StringPiece GetPath(int index) const;

  size_t GetLength(int index) const;
  size_t GetLength(const base::FilePath& file_path) const;
  size_t GetBlockCount(int index) const;

  size_t GetTotalLength() const;
  size_t GetTotalBlockCount() const;

  bool GetReader(const base::FilePath& file_path, Reader* reader) const;
  bool GetReader(int index, Reader* reader) const;

  bool GetWriter(const base::FilePath& file_path, Writer* writer) const;
  bool GetWriter(int index, Writer* writer) const;

  void* Map(int index);

  MerkleTree* GetMerkleTree(int index) const;
  void SetMerkleTree(int index, std::unique_ptr<MerkleTree> merkle_tree);

  std::string GetMerkleRoot(int index) const;
  
private:
  size_t GetBlockCountInternal(base::MemoryMappedFile* file) const;

  std::unordered_map<std::string, int> file_path_map_;
  std::map<int, std::unique_ptr<base::MemoryMappedFile>> files_;
  std::map<int, std::unique_ptr<MerkleTree>> merkle_trees_;

  base::AtomicSequenceNumber next_file_;

  DISALLOW_COPY_AND_ASSIGN(FileSet);
};

}

#endif