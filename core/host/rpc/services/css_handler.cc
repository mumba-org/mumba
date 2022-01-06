// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/css_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char CSSAddRuleHandler::kFullname[] = "/mumba.Mumba/CSSAddRule";

CSSAddRuleHandler::CSSAddRuleHandler():
  fullname_(CSSAddRuleHandler::kFullname) {

  Init();
}

CSSAddRuleHandler::~CSSAddRuleHandler() {}

base::StringPiece CSSAddRuleHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CSSAddRuleHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CSSAddRuleHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CSSAddRuleHandler::output() const {
  // FIXME
  return fullname_;
}

const char CSSGetStylesheetTextHandler::kFullname[] = "/mumba.Mumba/CSSGetStylesheetText";

CSSGetStylesheetTextHandler::CSSGetStylesheetTextHandler():
  fullname_(CSSGetStylesheetTextHandler::kFullname) {

  Init();
}

CSSGetStylesheetTextHandler::~CSSGetStylesheetTextHandler() {}

base::StringPiece CSSGetStylesheetTextHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CSSGetStylesheetTextHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CSSGetStylesheetTextHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CSSGetStylesheetTextHandler::output() const {
  // FIXME
  return fullname_;
}

const char CSSSetStyleTextsHandler::kFullname[] = "/mumba.Mumba/CSSSetStyleTexts";

CSSSetStyleTextsHandler::CSSSetStyleTextsHandler():
  fullname_(CSSSetStyleTextsHandler::kFullname) {

  Init();
}

CSSSetStyleTextsHandler::~CSSSetStyleTextsHandler() {}

base::StringPiece CSSSetStyleTextsHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CSSSetStyleTextsHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CSSSetStyleTextsHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CSSSetStyleTextsHandler::output() const {
  // FIXME
  return fullname_;
}

const char CSSSetStylesheetTextHandler::kFullname[] = "/mumba.Mumba/CSSSetStylesheetText";

CSSSetStylesheetTextHandler::CSSSetStylesheetTextHandler():
  fullname_(CSSSetStylesheetTextHandler::kFullname) {

  Init();
}

CSSSetStylesheetTextHandler::~CSSSetStylesheetTextHandler() {}

base::StringPiece CSSSetStylesheetTextHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void CSSSetStylesheetTextHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void CSSSetStylesheetTextHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& CSSSetStylesheetTextHandler::output() const {
  // FIXME
  return fullname_;
}

}