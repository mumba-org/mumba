// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/filesystem_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char FilesystemDirectoryGetDirectoryHandler::kFullname[] = "/mumba.Mumba/FilesystemDirectoryGetDirectory";

FilesystemDirectoryGetDirectoryHandler::FilesystemDirectoryGetDirectoryHandler():
  fullname_(FilesystemDirectoryGetDirectoryHandler::kFullname) {

  Init();
}

FilesystemDirectoryGetDirectoryHandler::~FilesystemDirectoryGetDirectoryHandler() {}

base::StringPiece FilesystemDirectoryGetDirectoryHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemDirectoryGetDirectoryHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemDirectoryGetDirectoryHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemDirectoryGetDirectoryHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemDirectoryGetFileHandler::kFullname[] = "/mumba.Mumba/FilesystemDirectoryGetFile";

FilesystemDirectoryGetFileHandler::FilesystemDirectoryGetFileHandler():
  fullname_(FilesystemDirectoryGetFileHandler::kFullname) {

  Init();
}

FilesystemDirectoryGetFileHandler::~FilesystemDirectoryGetFileHandler() {}

base::StringPiece FilesystemDirectoryGetFileHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemDirectoryGetFileHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemDirectoryGetFileHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemDirectoryGetFileHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemDirectoryListHandler::kFullname[] = "/mumba.Mumba/FilesystemDirectoryList";

FilesystemDirectoryListHandler::FilesystemDirectoryListHandler():
  fullname_(FilesystemDirectoryListHandler::kFullname) {

  Init();
}

FilesystemDirectoryListHandler::~FilesystemDirectoryListHandler() {}

base::StringPiece FilesystemDirectoryListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemDirectoryListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemDirectoryListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemDirectoryListHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemDirectoryRemoveHandler::kFullname[] = "/mumba.Mumba/FilesystemDirectoryRemove";

FilesystemDirectoryRemoveHandler::FilesystemDirectoryRemoveHandler():
  fullname_(FilesystemDirectoryRemoveHandler::kFullname) {

  Init();
}

FilesystemDirectoryRemoveHandler::~FilesystemDirectoryRemoveHandler() {}

base::StringPiece FilesystemDirectoryRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemDirectoryRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemDirectoryRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemDirectoryRemoveHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryCopyHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryCopy";

FilesystemEntryCopyHandler::FilesystemEntryCopyHandler():
  fullname_(FilesystemEntryCopyHandler::kFullname) {

  Init();
}

FilesystemEntryCopyHandler::~FilesystemEntryCopyHandler() {}

base::StringPiece FilesystemEntryCopyHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryCopyHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryCopyHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryCopyHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryGetParentHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryGetParent";

FilesystemEntryGetParentHandler::FilesystemEntryGetParentHandler():
  fullname_(FilesystemEntryGetParentHandler::kFullname) {

  Init();
}

FilesystemEntryGetParentHandler::~FilesystemEntryGetParentHandler() {}

base::StringPiece FilesystemEntryGetParentHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryGetParentHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryGetParentHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryGetParentHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryInfoHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryInfo";

FilesystemEntryInfoHandler::FilesystemEntryInfoHandler():
  fullname_(FilesystemEntryInfoHandler::kFullname) {

  Init();
}

FilesystemEntryInfoHandler::~FilesystemEntryInfoHandler() {}

base::StringPiece FilesystemEntryInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryInfoHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryMetadataHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryMetadata";

FilesystemEntryMetadataHandler::FilesystemEntryMetadataHandler():
  fullname_(FilesystemEntryMetadataHandler::kFullname) {

  Init();
}

FilesystemEntryMetadataHandler::~FilesystemEntryMetadataHandler() {}

base::StringPiece FilesystemEntryMetadataHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryMetadataHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryMetadataHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryMetadataHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryMoveHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryMove";

FilesystemEntryMoveHandler::FilesystemEntryMoveHandler():
  fullname_(FilesystemEntryMoveHandler::kFullname) {

  Init();
}

FilesystemEntryMoveHandler::~FilesystemEntryMoveHandler() {}

base::StringPiece FilesystemEntryMoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryMoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryMoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryMoveHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemEntryRemoveHandler::kFullname[] = "/mumba.Mumba/FilesystemEntryRemove";

FilesystemEntryRemoveHandler::FilesystemEntryRemoveHandler():
  fullname_(FilesystemEntryRemoveHandler::kFullname) {

  Init();
}

FilesystemEntryRemoveHandler::~FilesystemEntryRemoveHandler() {}

base::StringPiece FilesystemEntryRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemEntryRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemEntryRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemEntryRemoveHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemFileReadHandler::kFullname[] = "/mumba.Mumba/FilesystemFileRead";

FilesystemFileReadHandler::FilesystemFileReadHandler():
  fullname_(FilesystemFileReadHandler::kFullname) {

  Init();
}

FilesystemFileReadHandler::~FilesystemFileReadHandler() {}

base::StringPiece FilesystemFileReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemFileReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemFileReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemFileReadHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemFileWriteHandler::kFullname[] = "/mumba.Mumba/FilesystemFileWrite";

FilesystemFileWriteHandler::FilesystemFileWriteHandler():
  fullname_(FilesystemFileWriteHandler::kFullname) {

  Init();
}

FilesystemFileWriteHandler::~FilesystemFileWriteHandler() {}

base::StringPiece FilesystemFileWriteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemFileWriteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemFileWriteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemFileWriteHandler::output() const {
  // FIXME
  return fullname_;
}

const char FilesystemInfoHandler::kFullname[] = "/mumba.Mumba/FilesystemInfo";

FilesystemInfoHandler::FilesystemInfoHandler():
  fullname_(FilesystemInfoHandler::kFullname) {

  Init();
}

FilesystemInfoHandler::~FilesystemInfoHandler() {}

base::StringPiece FilesystemInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void FilesystemInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void FilesystemInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& FilesystemInfoHandler::output() const {
  // FIXME
  return fullname_;
}


}