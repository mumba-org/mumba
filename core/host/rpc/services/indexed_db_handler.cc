// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/indexed_db_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char IndexedDbClearObjectStoreHandler::kFullname[] = "/mumba.Mumba/IndexedDbClearObjectStore";
const char IndexedDbCountHandler::kFullname[] = "/mumba.Mumba/IndexedDbCount";
const char IndexedDbDeleteDbHandler::kFullname[] = "/mumba.Mumba/IndexedDbDeleteDb";
const char IndexedDbGetAllHandler::kFullname[] = "/mumba.Mumba/IndexedDbGetAll";
const char IndexedDbGetHandler::kFullname[] = "/mumba.Mumba/IndexedDbGet";
const char IndexedDbGetKeyHandler::kFullname[] = "/mumba.Mumba/IndexedDbGetKey";
const char IndexedDbRequestDataHandler::kFullname[] = "/mumba.Mumba/IndexedDbRequestData";

IndexedDbClearObjectStoreHandler::IndexedDbClearObjectStoreHandler():
  fullname_(IndexedDbClearObjectStoreHandler::kFullname) {

  Init();
}

IndexedDbClearObjectStoreHandler::~IndexedDbClearObjectStoreHandler() {}

base::StringPiece IndexedDbClearObjectStoreHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbClearObjectStoreHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbClearObjectStoreHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbClearObjectStoreHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbCountHandler::IndexedDbCountHandler():
  fullname_(IndexedDbCountHandler::kFullname) {

  Init();
}

IndexedDbCountHandler::~IndexedDbCountHandler() {}

base::StringPiece IndexedDbCountHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbCountHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbCountHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbCountHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbDeleteDbHandler::IndexedDbDeleteDbHandler():
  fullname_(IndexedDbDeleteDbHandler::kFullname) {

  Init();
}

IndexedDbDeleteDbHandler::~IndexedDbDeleteDbHandler() {}

base::StringPiece IndexedDbDeleteDbHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbDeleteDbHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbDeleteDbHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbDeleteDbHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbGetAllHandler::IndexedDbGetAllHandler():
  fullname_(IndexedDbGetAllHandler::kFullname) {

  Init();
}

IndexedDbGetAllHandler::~IndexedDbGetAllHandler() {}

base::StringPiece IndexedDbGetAllHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbGetAllHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbGetAllHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbGetAllHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbGetHandler::IndexedDbGetHandler():
  fullname_(IndexedDbGetHandler::kFullname) {

  Init();
}

IndexedDbGetHandler::~IndexedDbGetHandler() {}

base::StringPiece IndexedDbGetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbGetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbGetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbGetHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbGetKeyHandler::IndexedDbGetKeyHandler():
  fullname_(IndexedDbGetKeyHandler::kFullname) {

  Init();
}

IndexedDbGetKeyHandler::~IndexedDbGetKeyHandler() {}

base::StringPiece IndexedDbGetKeyHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbGetKeyHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbGetKeyHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbGetKeyHandler::output() const {
  // FIXME
  return fullname_;
}

IndexedDbRequestDataHandler::IndexedDbRequestDataHandler():
  fullname_(IndexedDbRequestDataHandler::kFullname) {

  Init();
}

IndexedDbRequestDataHandler::~IndexedDbRequestDataHandler() {}

base::StringPiece IndexedDbRequestDataHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IndexedDbRequestDataHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IndexedDbRequestDataHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IndexedDbRequestDataHandler::output() const {
  // FIXME
  return fullname_;
}


}