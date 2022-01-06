// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/dom_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char DomFocusHandler::kFullname[] = "/mumba.Mumba/DomFocus";

DomFocusHandler::DomFocusHandler():
  fullname_(DomFocusHandler::kFullname) {

  Init();
}

DomFocusHandler::~DomFocusHandler() {}

base::StringPiece DomFocusHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomFocusHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomFocusHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomFocusHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomGetAttributesHandler::kFullname[] = "/mumba.Mumba/DomGetAttributes";

DomGetAttributesHandler::DomGetAttributesHandler():
  fullname_(DomGetAttributesHandler::kFullname) {

  Init();
}

DomGetAttributesHandler::~DomGetAttributesHandler() {}

base::StringPiece DomGetAttributesHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomGetAttributesHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomGetAttributesHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomGetAttributesHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomGetOuterHtmlHandler::kFullname[] = "/mumba.Mumba/DomGetOuterHtml";

DomGetOuterHtmlHandler::DomGetOuterHtmlHandler():
  fullname_(DomGetOuterHtmlHandler::kFullname) {

  Init();
}

DomGetOuterHtmlHandler::~DomGetOuterHtmlHandler() {}

base::StringPiece DomGetOuterHtmlHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomGetOuterHtmlHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomGetOuterHtmlHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomGetOuterHtmlHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomGetSearchResultHandler::kFullname[] = "/mumba.Mumba/DomGetSearchResult";

DomGetSearchResultHandler::DomGetSearchResultHandler():
  fullname_(DomGetSearchResultHandler::kFullname) {

  Init();
}

DomGetSearchResultHandler::~DomGetSearchResultHandler() {}

base::StringPiece DomGetSearchResultHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomGetSearchResultHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomGetSearchResultHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomGetSearchResultHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomMoveToHandler::kFullname[] = "/mumba.Mumba/DomMoveTo";

DomMoveToHandler::DomMoveToHandler():
  fullname_(DomMoveToHandler::kFullname) {

  Init();
}

DomMoveToHandler::~DomMoveToHandler() {}

base::StringPiece DomMoveToHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomMoveToHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomMoveToHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomMoveToHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomPerformSearchHandler::kFullname[] = "/mumba.Mumba/DomPerformSearch";

DomPerformSearchHandler::DomPerformSearchHandler():
  fullname_(DomPerformSearchHandler::kFullname) {

  Init();
}

DomPerformSearchHandler::~DomPerformSearchHandler() {}

base::StringPiece DomPerformSearchHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomPerformSearchHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomPerformSearchHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomPerformSearchHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomQuerySelectorHandler::kFullname[] = "/mumba.Mumba/DomQuerySelector";

DomQuerySelectorHandler::DomQuerySelectorHandler():
  fullname_(DomQuerySelectorHandler::kFullname) {

  Init();
}

DomQuerySelectorHandler::~DomQuerySelectorHandler() {}

base::StringPiece DomQuerySelectorHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomQuerySelectorHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomQuerySelectorHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomQuerySelectorHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomSetAttributeHandler::kFullname[] = "/mumba.Mumba/DomSetAttribute";

DomSetAttributeHandler::DomSetAttributeHandler():
  fullname_(DomSetAttributeHandler::kFullname) {

  Init();
}

DomSetAttributeHandler::~DomSetAttributeHandler() {}

base::StringPiece DomSetAttributeHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomSetAttributeHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomSetAttributeHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomSetAttributeHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomSetNodeNameHandler::kFullname[] = "/mumba.Mumba/DomSetNodeName";

DomSetNodeNameHandler::DomSetNodeNameHandler():
  fullname_(DomSetNodeNameHandler::kFullname) {

  Init();
}

DomSetNodeNameHandler::~DomSetNodeNameHandler() {}

base::StringPiece DomSetNodeNameHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomSetNodeNameHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomSetNodeNameHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomSetNodeNameHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomSetNodeValueHandler::kFullname[] = "/mumba.Mumba/DomSetNodeValue";

DomSetNodeValueHandler::DomSetNodeValueHandler():
  fullname_(DomSetNodeValueHandler::kFullname) {

  Init();
}

DomSetNodeValueHandler::~DomSetNodeValueHandler() {}

base::StringPiece DomSetNodeValueHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomSetNodeValueHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomSetNodeValueHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomSetNodeValueHandler::output() const {
  // FIXME
  return fullname_;
}

const char DomSetOuterHtmlHandler::kFullname[] = "/mumba.Mumba/DomSetOuterHtml";

DomSetOuterHtmlHandler::DomSetOuterHtmlHandler():
  fullname_(DomSetOuterHtmlHandler::kFullname) {

  Init();
}

DomSetOuterHtmlHandler::~DomSetOuterHtmlHandler() {}

base::StringPiece DomSetOuterHtmlHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void DomSetOuterHtmlHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void DomSetOuterHtmlHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& DomSetOuterHtmlHandler::output() const {
  // FIXME
  return fullname_;
}

}