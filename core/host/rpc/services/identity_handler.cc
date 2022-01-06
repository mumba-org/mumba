// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/identity_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char IdentityCreateHandler::kFullname[] = "/mumba.Mumba/IdentityCreate";

IdentityCreateHandler::IdentityCreateHandler():
  fullname_(IdentityCreateHandler::kFullname) {

  Init();
}

IdentityCreateHandler::~IdentityCreateHandler() {}

base::StringPiece IdentityCreateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityCreateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityCreateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityCreateHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityCredentialCreateHandler::kFullname[] = "/mumba.Mumba/IdentityCredentialCreate";

IdentityCredentialCreateHandler::IdentityCredentialCreateHandler():
  fullname_(IdentityCredentialCreateHandler::kFullname) {

  Init();
}

IdentityCredentialCreateHandler::~IdentityCredentialCreateHandler() {}

base::StringPiece IdentityCredentialCreateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityCredentialCreateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: IdentityCredentialCreate
}

void IdentityCredentialCreateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityCredentialCreateHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityCredentialDropHandler::kFullname[] = "/mumba.Mumba/IdentityCredentialDrop";

IdentityCredentialDropHandler::IdentityCredentialDropHandler():
  fullname_(IdentityCredentialDropHandler::kFullname) {

  Init();
}

IdentityCredentialDropHandler::~IdentityCredentialDropHandler() {}

base::StringPiece IdentityCredentialDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityCredentialDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityCredentialDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityCredentialDropHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityCredentialListHandler::kFullname[] = "/mumba.Mumba/IdentityCredentialList";

IdentityCredentialListHandler::IdentityCredentialListHandler():
  fullname_(IdentityCredentialListHandler::kFullname) {

  Init();
}

IdentityCredentialListHandler::~IdentityCredentialListHandler() {}

base::StringPiece IdentityCredentialListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityCredentialListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityCredentialListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityCredentialListHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityDropHandler::kFullname[] = "/mumba.Mumba/IdentityDrop";

IdentityDropHandler::IdentityDropHandler():
  fullname_(IdentityDropHandler::kFullname) {

  Init();
}

IdentityDropHandler::~IdentityDropHandler() {}

base::StringPiece IdentityDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityDropHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityGetHandler::kFullname[] = "/mumba.Mumba/IdentityGet";

IdentityGetHandler::IdentityGetHandler():
  fullname_(IdentityGetHandler::kFullname) {

  Init();
}

IdentityGetHandler::~IdentityGetHandler() {}

base::StringPiece IdentityGetHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityGetHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityGetHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityGetHandler::output() const {
  // FIXME
  return fullname_;
}

const char IdentityUpdateHandler::kFullname[] = "/mumba.Mumba/IdentityUpdate";

IdentityUpdateHandler::IdentityUpdateHandler():
  fullname_(IdentityUpdateHandler::kFullname) {

  Init();
}

IdentityUpdateHandler::~IdentityUpdateHandler() {}

base::StringPiece IdentityUpdateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void IdentityUpdateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void IdentityUpdateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& IdentityUpdateHandler::output() const {
  // FIXME
  return fullname_;
}


}