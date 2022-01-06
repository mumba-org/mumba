// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/blob_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char BlobListHandler::kFullname[] = "/mumba.Mumba/BlobList";

BlobListHandler::BlobListHandler():
  fullname_(BlobListHandler::kFullname) {

  Init();
}

BlobListHandler::~BlobListHandler() {}

base::StringPiece BlobListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BlobListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BlobListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BlobListHandler::output() const {
  // FIXME
  return fullname_;
}

const char BlobReadHandler::kFullname[] = "/mumba.Mumba/BlobRead";

BlobReadHandler::BlobReadHandler():
  fullname_(BlobReadHandler::kFullname) {

  Init();
}

BlobReadHandler::~BlobReadHandler() {}

base::StringPiece BlobReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BlobReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BlobReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BlobReadHandler::output() const {
  // FIXME
  return fullname_;
}

const char BlobWriteHandler::kFullname[] = "/mumba.Mumba/BlobWrite";

BlobWriteHandler::BlobWriteHandler():
  fullname_(BlobWriteHandler::kFullname) {

  Init();
}

BlobWriteHandler::~BlobWriteHandler() {}

base::StringPiece BlobWriteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BlobWriteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BlobWriteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BlobWriteHandler::output() const {
  // FIXME
  return fullname_;
}

const char BlobCreateHandler::kFullname[] = "/mumba.Mumba/BlobCreate";

BlobCreateHandler::BlobCreateHandler():
  fullname_(BlobCreateHandler::kFullname) {

  Init();
}

BlobCreateHandler::~BlobCreateHandler() {}

base::StringPiece BlobCreateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BlobCreateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BlobCreateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BlobCreateHandler::output() const {
  // FIXME
  return fullname_;
}

const char BlobDeleteHandler::kFullname[] = "/mumba.Mumba/BlobDelete";

BlobDeleteHandler::BlobDeleteHandler():
  fullname_(BlobDeleteHandler::kFullname) {

  Init();
}

BlobDeleteHandler::~BlobDeleteHandler() {}

base::StringPiece BlobDeleteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void BlobDeleteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void BlobDeleteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& BlobDeleteHandler::output() const {
  // FIXME
  return fullname_;
}

}