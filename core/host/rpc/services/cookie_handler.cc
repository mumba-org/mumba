// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/cookie_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char CookieGetAllHandler::kFullname[] = "/mumba.Mumba/CookieGetAll";

CookieGetAllHandler::CookieGetAllHandler():
  fullname_(CookieGetAllHandler::kFullname) {

  Init();
}

CookieGetAllHandler::~CookieGetAllHandler() {}

base::StringPiece CookieGetAllHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CookieGetAllHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CookieGetAllHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CookieGetAllHandler::output() const {
  // FIXME
  return fullname_;
}

const char CookieGetHandler::kFullname[] = "/mumba.Mumba/CookieGet";

CookieGetHandler::CookieGetHandler():
  fullname_(CookieGetHandler::kFullname) {

  Init();
}

CookieGetHandler::~CookieGetHandler() {}

base::StringPiece CookieGetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CookieGetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CookieGetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CookieGetHandler::output() const {
  // FIXME
  return fullname_;
}

const char CookieDeleteHandler::kFullname[] = "/mumba.Mumba/CookieDelete";

CookieDeleteHandler::CookieDeleteHandler():
  fullname_(CookieDeleteHandler::kFullname) {

  Init();
}

CookieDeleteHandler::~CookieDeleteHandler() {}

base::StringPiece CookieDeleteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CookieDeleteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CookieDeleteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CookieDeleteHandler::output() const {
  // FIXME
  return fullname_;
}

const char CookieHasHandler::kFullname[] = "/mumba.Mumba/CookieHas";

CookieHasHandler::CookieHasHandler():
  fullname_(CookieHasHandler::kFullname) {

  Init();
}

CookieHasHandler::~CookieHasHandler() {}

base::StringPiece CookieHasHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CookieHasHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CookieHasHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CookieHasHandler::output() const {
  // FIXME
  return fullname_;
}

const char CookieSetHandler::kFullname[] = "/mumba.Mumba/CookieSet";

CookieSetHandler::CookieSetHandler():
  fullname_(CookieSetHandler::kFullname) {

  Init();
}

CookieSetHandler::~CookieSetHandler() {}

base::StringPiece CookieSetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CookieSetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CookieSetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CookieSetHandler::output() const {
  // FIXME
  return fullname_;
}


}