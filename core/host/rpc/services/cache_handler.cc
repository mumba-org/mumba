// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/cache_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char CacheCreateHandler::kFullname[] = "/mumba.Mumba/CacheCreate";

CacheCreateHandler::CacheCreateHandler():
  fullname_(CacheCreateHandler::kFullname) {

  Init();
}

CacheCreateHandler::~CacheCreateHandler() {}

base::StringPiece CacheCreateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheCreateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheCreateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheCreateHandler::output() const {
  // FIXME
  return fullname_;
}

const char CacheDropHandler::kFullname[] = "/mumba.Mumba/CacheDrop";

CacheDropHandler::CacheDropHandler():
  fullname_(CacheDropHandler::kFullname) {

  Init();
}

CacheDropHandler::~CacheDropHandler() {}

base::StringPiece CacheDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheDropHandler::output() const {
  // FIXME
  return fullname_;
}

const char CacheItemAddHandler::kFullname[] = "/mumba.Mumba/CacheItemAdd";

CacheItemAddHandler::CacheItemAddHandler():
  fullname_(CacheItemAddHandler::kFullname) {

  Init();
}

CacheItemAddHandler::~CacheItemAddHandler() {}

base::StringPiece CacheItemAddHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheItemAddHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheItemAddHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheItemAddHandler::output() const {
  // FIXME
  return fullname_;
}

const char CacheItemReadHandler::kFullname[] = "/mumba.Mumba/CacheItemRead";

CacheItemReadHandler::CacheItemReadHandler():
  fullname_(CacheItemReadHandler::kFullname) {

  Init();
}

CacheItemReadHandler::~CacheItemReadHandler() {}

base::StringPiece CacheItemReadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheItemReadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheItemReadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheItemReadHandler::output() const {
  // FIXME
  return fullname_;
}

const char CacheItemRemoveHandler::kFullname[] = "/mumba.Mumba/CacheItemRemove";

CacheItemRemoveHandler::CacheItemRemoveHandler():
  fullname_(CacheItemRemoveHandler::kFullname) {

  Init();
}

CacheItemRemoveHandler::~CacheItemRemoveHandler() {}

base::StringPiece CacheItemRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheItemRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheItemRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheItemRemoveHandler::output() const {
  // FIXME
  return fullname_;
}


const char CacheItemWriteHandler::kFullname[] = "/mumba.Mumba/CacheItemWrite";

CacheItemWriteHandler::CacheItemWriteHandler():
  fullname_(CacheItemWriteHandler::kFullname) {

  Init();
}

CacheItemWriteHandler::~CacheItemWriteHandler() {}

base::StringPiece CacheItemWriteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CacheItemWriteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CacheItemWriteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CacheItemWriteHandler::output() const {
  // FIXME
  return fullname_;
}


}