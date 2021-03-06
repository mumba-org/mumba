// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#ifndef PARQUET_FILE_READER_H
#define PARQUET_FILE_READER_H

#include <cstdint>
#include <iosfwd>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "core/shared/domain/storage/parquet/column_reader.h"
#include "core/shared/domain/storage/parquet/metadata.h"
#include "core/shared/domain/storage/parquet/properties.h"
#include "core/shared/domain/storage/parquet/schema.h"
#include "core/shared/domain/storage/parquet/statistics.h"
#include "core/shared/domain/storage/parquet/util/memory.h"
#include "core/shared/domain/storage/parquet/util/visibility.h"

namespace domain {

class ColumnReader;

class RowGroupReader {
 public:
  // Forward declare a virtual class 'Contents' to aid dependency injection and more
  // easily create test fixtures
  // An implementation of the Contents class is defined in the .cc file
  struct Contents {
    virtual ~Contents() {}
    virtual std::unique_ptr<PageReader> GetColumnPageReader(int i) = 0;
    virtual const RowGroupMetaData* metadata() const = 0;
    virtual const ReaderProperties* properties() const = 0;
  };

  explicit RowGroupReader(std::unique_ptr<Contents> contents);

  // Returns the rowgroup metadata
  const RowGroupMetaData* metadata() const;

  // Construct a ColumnReader for the indicated row group-relative
  // column. Ownership is shared with the RowGroupReader.
  std::shared_ptr<ColumnReader> Column(int i);

  std::unique_ptr<PageReader> GetColumnPageReader(int i);

 private:
  // Holds a pointer to an instance of Contents implementation
  std::unique_ptr<Contents> contents_;
};

class ParquetFileReader {
 public:
  // Forward declare a virtual class 'Contents' to aid dependency injection and more
  // easily create test fixtures
  // An implementation of the Contents class is defined in the .cc file
  struct Contents {
    static std::unique_ptr<Contents> Open(
        std::unique_ptr<RandomAccessSource> source,
        const ReaderProperties& props = default_reader_properties(),
        const std::shared_ptr<FileMetaData>& metadata = nullptr);

    virtual ~Contents() {}
    // Perform any cleanup associated with the file contents
    virtual void Close() = 0;
    virtual std::shared_ptr<RowGroupReader> GetRowGroup(int i) = 0;
    virtual std::shared_ptr<FileMetaData> metadata() const = 0;
  };

  ParquetFileReader();
  ~ParquetFileReader();

  // Create a reader from some implementation of parquet-cpp's generic file
  // input interface
  //
  // If you cannot provide exclusive access to your file resource, create a
  // subclass of RandomAccessSource that wraps the shared resource
  static std::unique_ptr<ParquetFileReader> Open(
      std::unique_ptr<RandomAccessSource> source,
      const ReaderProperties& props = default_reader_properties(),
      const std::shared_ptr<FileMetaData>& metadata = nullptr);

  // Create a file reader instance from an Arrow file object. Thread-safety is
  // the responsibility of the file implementation
  static std::unique_ptr<ParquetFileReader> Open(
      const std::shared_ptr<io::ReadableFileInterface>& source,
      const ReaderProperties& props = default_reader_properties(),
      const std::shared_ptr<FileMetaData>& metadata = nullptr);

  // API Convenience to open a serialized Parquet file on disk, using Arrow IO
  // interfaces.
  static std::unique_ptr<ParquetFileReader> OpenFile(
      const std::string& path, bool memory_map = true,
      const ReaderProperties& props = default_reader_properties(),
      const std::shared_ptr<FileMetaData>& metadata = nullptr);

  void Open(std::unique_ptr<Contents> contents);
  void Close();

  // The RowGroupReader is owned by the FileReader
  std::shared_ptr<RowGroupReader> RowGroup(int i);

  // Returns the file metadata. Only one instance is ever created
  std::shared_ptr<FileMetaData> metadata() const;

 private:
  // Holds a pointer to an instance of Contents implementation
  std::unique_ptr<Contents> contents_;
};

// Read only Parquet file metadata
std::shared_ptr<FileMetaData> PARQUET_EXPORT
ReadMetaData(const std::shared_ptr<io::ReadableFileInterface>& source);

/// \brief Scan all values in file. Useful for performance testing
/// \param[in] columns the column numbers to scan. If empty scans all
/// \param[in] column_batch_size number of values to read at a time when scanning column
/// \param[in] reader a ParquetFileReader instance
/// \return number of semantic rows in file
PARQUET_EXPORT
int64_t ScanFileContents(std::vector<int> columns, const int32_t column_batch_size,
                         ParquetFileReader* reader);

}  // namespace domain

#endif  // PARQUET_FILE_READER_H
