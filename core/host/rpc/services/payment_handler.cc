// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/payment_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char PaymentClearHandler::kFullname[] = "/mumba.Mumba/PaymentClear";
const char PaymentSetHandler::kFullname[] = "/mumba.Mumba/PaymentSet";
const char PaymentListHandler::kFullname[] = "/mumba.Mumba/PaymentList";
const char PaymentKeysHandler::kFullname[] = "/mumba.Mumba/PaymentKeys";
const char PaymentGetHandler::kFullname[] = "/mumba.Mumba/PaymentGet";
const char PaymentDeleteHandler::kFullname[] = "/mumba.Mumba/PaymentDelete";

PaymentClearHandler::PaymentClearHandler():
  fullname_(PaymentClearHandler::kFullname) {

  Init();
}

PaymentClearHandler::~PaymentClearHandler() {}

base::StringPiece PaymentClearHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentClearHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentClearHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentClearHandler::output() const {
  // FIXME
  return fullname_;
}

PaymentSetHandler::PaymentSetHandler():
  fullname_(PaymentSetHandler::kFullname) {

  Init();
}

PaymentSetHandler::~PaymentSetHandler() {}

base::StringPiece PaymentSetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentSetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentSetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentSetHandler::output() const {
  // FIXME
  return fullname_;
}

PaymentListHandler::PaymentListHandler():
  fullname_(PaymentListHandler::kFullname) {

  Init();
}

PaymentListHandler::~PaymentListHandler() {}

base::StringPiece PaymentListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentListHandler::output() const {
  // FIXME
  return fullname_;
}

PaymentKeysHandler::PaymentKeysHandler():
  fullname_(PaymentKeysHandler::kFullname) {

  Init();
}

PaymentKeysHandler::~PaymentKeysHandler() {}

base::StringPiece PaymentKeysHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentKeysHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentKeysHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentKeysHandler::output() const {
  // FIXME
  return fullname_;
}

PaymentGetHandler::PaymentGetHandler():
  fullname_(PaymentGetHandler::kFullname) {

  Init();
}

PaymentGetHandler::~PaymentGetHandler() {}

base::StringPiece PaymentGetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentGetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentGetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentGetHandler::output() const {
  // FIXME
  return fullname_;
}

PaymentDeleteHandler::PaymentDeleteHandler():
  fullname_(PaymentDeleteHandler::kFullname) {

  Init();
}

PaymentDeleteHandler::~PaymentDeleteHandler() {}

base::StringPiece PaymentDeleteHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PaymentDeleteHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PaymentDeleteHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PaymentDeleteHandler::output() const {
  // FIXME
  return fullname_;
}

}