// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/index_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char IndexAddHandler::kFullname[] = "/mumba.Mumba/IndexAdd";
const char IndexCreateHandler::kFullname[] = "/mumba.Mumba/IndexCreate";
const char IndexDropHandler::kFullname[] = "/mumba.Mumba/IndexDrop";
const char IndexQueryHandler::kFullname[] = "/mumba.Mumba/IndexQuery";
const char IndexRemoveHandler::kFullname[] = "/mumba.Mumba/IndexRemove";

IndexAddHandler::IndexAddHandler():
  fullname_(IndexAddHandler::kFullname) {

  Init();
}

IndexAddHandler::~IndexAddHandler() {}

base::StringPiece IndexAddHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexAddHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexAddHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexAddHandler::output() const {
  // FIXME
  return fullname_;
}

IndexCreateHandler::IndexCreateHandler():
  fullname_(IndexCreateHandler::kFullname) {

  Init();
}

IndexCreateHandler::~IndexCreateHandler() {}

base::StringPiece IndexCreateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexCreateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexCreateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexCreateHandler::output() const {
  // FIXME
  return fullname_;
}

IndexDropHandler::IndexDropHandler():
  fullname_(IndexDropHandler::kFullname) {

  Init();
}

IndexDropHandler::~IndexDropHandler() {}

base::StringPiece IndexDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexDropHandler::output() const {
  // FIXME
  return fullname_;
}

IndexQueryHandler::IndexQueryHandler():
  fullname_(IndexQueryHandler::kFullname) {

  Init();
}

IndexQueryHandler::~IndexQueryHandler() {}

base::StringPiece IndexQueryHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexQueryHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexQueryHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexQueryHandler::output() const {
  // FIXME
  return fullname_;
}

IndexRemoveHandler::IndexRemoveHandler():
  fullname_(IndexRemoveHandler::kFullname) {

  Init();
}

IndexRemoveHandler::~IndexRemoveHandler() {}

base::StringPiece IndexRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexRemoveHandler::output() const {
  // FIXME
  return fullname_;
}

}