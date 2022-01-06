// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage_file.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
//#include "storage/storage_state.h"
#include "storage/storage.h"
#include "storage/storage_constants.h"
#include "storage/storage_utils.h"
#include "storage/db/db.h"
#include "storage/db/sqliteInt.h"
#include "third_party/zlib/google/zip_reader.h"
#include "third_party/zlib/google/zip_writer.h"
#include "third_party/zlib/google/zip.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

namespace storage {

namespace {

bool WriteBuffer(base::File* file, const char buffer[], int len) {
  return file->WriteAtCurrentPos(buffer, len) == len;
}

bool WriteArchive(base::File* out, base::File* in) {
  char buffer[1 << 12] = {};
  int read = 0;
  in->Seek(base::File::Whence::FROM_BEGIN, 0);
  while ((read = in->ReadAtCurrentPos(buffer, arraysize(buffer))) > 0) {
    if (out->WriteAtCurrentPos(buffer, read) != read)
      return false;
  }
  return read == 0;
}

bool ReadArchive(base::File* in, base::File* out) {
  char buffer[1 << 12] = {};
  int read = 0;
  //in->Seek(base::File::Whence::FROM_BEGIN, 0);
  while ((read = in->ReadAtCurrentPos(buffer, arraysize(buffer))) > 0) {
    if (out->WriteAtCurrentPos(buffer, read) != read)
      return false;
  }
  return read == 0;
}

bool ParseStorageStateFromString(const std::string& data, storage_proto::StorageState* out) {
  return out->ParseFromString(data);//StorageState::ParseProtoFromXMLString(data, out);
}

}  // namespace

// static 
std::unique_ptr<StorageFile> StorageFile::CreateFromDir(const base::FilePath& content_dir, const base::FilePath& out_file) {
  base::FilePath disk_state_file = content_dir.AppendASCII(kStorageStateFileName);

  std::string disk_state_contents;

  if (!base::ReadFileToString(disk_state_file, &disk_state_contents)) {
    return {};
  }

  base::FilePath::StringType name = out_file.RemoveExtension().BaseName().value();
#if defined (OS_WIN)
  base::FilePath out_zip = out_file.DirName().Append(name + L".zip");
#else
  base::FilePath out_zip = out_file.DirName().AppendASCII(name + ".zip");
#endif

  // create the zip file with the contents
  if (!zip::Zip(content_dir, out_zip, /*include_hidden_files=*/true)) {
    return {};
  }

  base::File zip_file(out_zip, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!zip_file.IsValid()) {
    return {};
  }

  std::unique_ptr<base::File> file(new base::File(out_file, (base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE)));

  if (!file->IsValid()) {
    return {};
  }

  std::unique_ptr<StorageFile> disk_file(new StorageFile(out_file, std::move(file)));
  
  if (disk_file->WriteOnce(disk_state_contents, &zip_file) != kOK) {
    return {};
  }

  zip_file.Close();

  // by now, the zip contents must be a part of the big disk file
  // so we can delete it
  base::DeleteFile(out_zip, false);
  
  return disk_file;
}

std::unique_ptr<StorageFile> StorageFile::CreateFromZip(const base::FilePath& disk_state_file, const base::FilePath& zip_file, const base::FilePath& out_file) {
  std::string disk_state_contents;

  if (!base::ReadFileToString(disk_state_file, &disk_state_contents)) {
    return {};
  }

  base::File zip(zip_file, base::File::FLAG_OPEN | base::File::FLAG_READ);
  
  if (!zip.IsValid()) {
    return {};
  }

  std::unique_ptr<base::File> file(new base::File(out_file, (base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE)));

  if (!file->IsValid()) {
    return {};
  }

  std::unique_ptr<StorageFile> disk_file(new StorageFile(out_file, std::move(file)));
  
  // NOTE: Write() should cache the blocks the same way as Read() would
  if (disk_file->WriteOnce(disk_state_contents, &zip) != kOK) {
    return {};
  }

  zip.Close();

  // by now, the zip contents must be a part of the big disk file
  // so we can delete it
  base::DeleteFile(zip_file, false);
  
  return disk_file;
}

// static 
std::unique_ptr<StorageFile> StorageFile::Open(const base::FilePath& path) {
  std::unique_ptr<base::File> file(new base::File(path, (base::File::FLAG_OPEN | base::File::FLAG_READ | base::File::FLAG_WRITE)));

  if (!file->IsValid()) {
    return {};
  }

  std::unique_ptr<StorageFile> disk_file(new StorageFile(path, std::move(file)));
  
  if (disk_file->ReadOnce() != kOK) {
    return {};
  }

  
  return disk_file;
}

// static 
bool StorageFile::Delete(const base::FilePath& path) {
  return base::DeleteFile(path, false);
}

StorageFile::StorageFile(const base::FilePath& path, std::unique_ptr<base::File> file):
 path_(path),
 file_(std::move(file)),
 is_open_(true) {

}

StorageFile::~StorageFile() {
  if (is_open_) {
    Close();
  }
}

void StorageFile::Close() {
  file_->Close();
}

StorageFile::Status StorageFile::ReadOnce() {
  Status s = ReadHeader();
  
  if (s != kOK)
    return s;
  
  s = ReadStorageStateBlock();
  
  if (s != kOK)
    return s;
  
  return ExtractContentBlock();
}

StorageFile::Status StorageFile::WriteOnce(const std::string& disk_state_contents, base::File* zip_file) {
  state_.reset(new storage_proto::StorageState());
  if (!ParseStorageStateFromString(disk_state_contents, state_.get())) {
    return kERR_WRITE_HEADER;
  }
  std::string proto_contents;
  if (!state_->SerializeToString(&proto_contents)) {
    return kERR_WRITE_HEADER; 
  }

  Status s = WriteHeader();
  
  if (s != kOK)
    return s;
  
  s = WriteStorageStateBlock(proto_contents);
  
  if (s != kOK)
    return s;
  
  return WriteContentBlock(zip_file);
}

StorageFile::Status StorageFile::ReadHeader()  {

  file_->Seek(base::File::Whence::FROM_BEGIN, 0);

  char buffer[kStorageFileHeaderMagicSize] = {0};
  // read header
  if (file_->ReadAtCurrentPos(buffer, kStorageFileHeaderMagicSize) !=
      kStorageFileHeaderMagicSize) {
    return kERR_READ_HEADER;
  }

  if (strncmp(buffer, kStorageFileHeaderMagic, kStorageFileHeaderMagicSize)) {
    return kERR_READ_HEADER; 
  }
  
  char format_version_buf[4] = {0};
  if (!file_->ReadAtCurrentPos(format_version_buf, 4)) {
    return kERR_READ_HEADER; 
  }

  if (format_version_buf[0] != kStorageFileHeaderVersion) {
    // bad/wrong version
    return kERR_READ_HEADER;
  }

  return kOK;
}

StorageFile::Status StorageFile::ReadStorageStateBlock() {
  char disk_state_size_buf[4] = {0};
  
  if (!file_->ReadAtCurrentPos(disk_state_size_buf, 4)) {
    return kERR_READ_MANIFEST;
  }
  int disk_state_size = static_cast<int>(disk_state_size_buf[3] << 24 | disk_state_size_buf[2] << 16 | disk_state_size_buf[1] << 8 | disk_state_size_buf[0]);

  //LOG(INFO) << "readed disk_state size of " << disk_state_size << " - [" << disk_state_size_buf[0] << "][" << disk_state_size_buf[1] << "][" << disk_state_size_buf[2] << "][" << disk_state_size_buf[3] << "]";
  
  char* buf = new char[disk_state_size];

  if (!file_->ReadAtCurrentPos(buf, disk_state_size)) {
    return kERR_READ_MANIFEST;
  }
  
  state_.reset(new storage_proto::StorageState());

  if (!state_->ParseFromArray(buf, disk_state_size)) {
    return kERR_READ_MANIFEST; 
    delete[] buf;  
  }

  //LOG(INFO) << "disk state on header:\n" <<
	//  "status: " << state_->status() << "\n" <<
	//  "address: " << state_->address() << "\n";

  delete[] buf;

  return kOK;
}

StorageFile::Status StorageFile::ExtractContentBlock() {
  base::FilePath unpacked_dir_ = path_.RemoveExtension();
  if (!base::DirectoryExists(unpacked_dir_)) {
    if (!base::CreateDirectory(unpacked_dir_)) {
      LOG(ERROR) << "error creating directory " << unpacked_dir_;
      return kERR_READ_CONTENT;
    }
  } else {
    // if theres a dir already, consider the content extracted
    // and move on
    return kOK;  
  }

  // TODO: this is very inneficient. 
  // we are copying the content to a new external zip file
  // to open it later and extract it all from there.
  // we should implement the "inners" of zlib here to be able to
  // extract the contents directly from the input disk file
  base::FilePath::StringType name = unpacked_dir_.BaseName().value();
#if defined(OS_WIN)
  base::FilePath zip_path = unpacked_dir_.Append(name + L".zip");
#else
  base::FilePath zip_path = unpacked_dir_.AppendASCII(name + ".zip");
#endif
  base::File zip_file(zip_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ | base::File::FLAG_WRITE);

  ReadArchive(file_.get(), &zip_file);

  zip::ZipReader reader;
  if (!reader.OpenFromPlatformFile(zip_file.GetPlatformFile())) {
    return kERR_READ_CONTENT;
  }
  while (reader.HasMore()) {
    reader.OpenCurrentEntryInZip();
    const base::FilePath& entry_path =
       reader.current_entry_info()->file_path();
    //if (entry_path.BaseName().MaybeAsASCII() == kStorageStateFileName) { // we ignore the disk_state file on extraction
    //  reader.AdvanceToNextEntry();
    //  continue;
    //}
    base::FilePath out_path = unpacked_dir_.Append(entry_path);   
  //  //D//LOG(INFO) << "processing " << out_path;
    zip::FilePathWriterDelegate delegate(out_path);

    // force the creation of dirs, even if they are empty
    //if (IsStorageDir(state_->profile(), out_path) && !base::DirectoryExists(out_path)) {
    if (!base::DirectoryExists(out_path)) {
//      //D//LOG(INFO) << "creating directory " << out_path;
      base::CreateDirectory(out_path);
    }
    reader.ExtractCurrentEntry(&delegate, std::numeric_limits<uint64_t>::max());
    reader.AdvanceToNextEntry();
  }

  // lets hope the ZipReader doesnt do anything funny with the platform file
  // after this point
  zip_file.Close();

  base::DeleteFile(zip_path, false);

  return kOK;
}

StorageFile::Status StorageFile::WriteHeader() {
  const uint8_t format_version[] = {kStorageFileHeaderVersion, 0, 0, 0};
  
  // magic
  if (!WriteBuffer(file_.get(), kStorageFileHeaderMagic, kStorageFileHeaderMagicSize)) {
    return kERR_WRITE_HEADER;
  }

  // version
  if (!WriteBuffer(file_.get(), reinterpret_cast<const char*>(format_version), arraysize(format_version))) {
    return kERR_WRITE_HEADER;
  }

  return kOK;
}

StorageFile::Status StorageFile::WriteStorageStateBlock(const std::string& disk_state_data) {
  
  const int disk_state_size = disk_state_data.size();
  const uint8_t disk_state_size_buf[] = {disk_state_size, disk_state_size >> 8,
                                        disk_state_size >> 16, disk_state_size >> 24};

  //LOG(INFO) << "writing disk_state size of " << disk_state_size << " - [" << disk_state_size_buf[0]<< "][" << disk_state_size_buf[1] << "][" << disk_state_size_buf[2] << "][" << disk_state_size_buf[3]<< "]";

  if (!WriteBuffer(file_.get(), reinterpret_cast<const char*>(disk_state_size_buf),
                   arraysize(disk_state_size_buf))) {
    return kERR_WRITE_MANIFEST;
  }

  if (!WriteBuffer(file_.get(), disk_state_data.c_str(), disk_state_data.length())) {
    return kERR_WRITE_MANIFEST;
  }

  return kOK;
}

StorageFile::Status StorageFile::WriteContentBlock(base::File* zip_file) {
  if (!WriteArchive(file_.get(), zip_file)) {
    return kERR_WRITE_CONTENT;
  }
  return kOK;
}

}
