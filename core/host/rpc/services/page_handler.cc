// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/page_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char PageAddScriptHandler::kFullname[] = "/mumba.Mumba/PageAddScript";
const char PageBringToFrontHandler::kFullname[] = "/mumba.Mumba/PageBringToFront";
const char PageCloseHandler::kFullname[] = "/mumba.Mumba/PageClose";
const char PageGetContentHandler::kFullname[] = "/mumba.Mumba/PageGetContent";
const char PageNavigateHandler::kFullname[] = "/mumba.Mumba/PageNavigate";
const char PageReloadHandler::kFullname[] = "/mumba.Mumba/PageReload";
const char PageRemoveScriptHandler::kFullname[] = "/mumba.Mumba/PageRemoveScript";
const char PageSaveToPdfHandler::kFullname[] = "/mumba.Mumba/PageSaveToPdf";
const char PageScreenshotHandler::kFullname[] = "/mumba.Mumba/PageScreenshot";
const char PageSetContentHandler::kFullname[] = "/mumba.Mumba/PageSetContent";
const char PageStopLoadingHandler::kFullname[] = "/mumba.Mumba/PageStopLoading";

PageAddScriptHandler::PageAddScriptHandler():
  fullname_(PageAddScriptHandler::kFullname) {

  Init();
}

PageAddScriptHandler::~PageAddScriptHandler() {}

base::StringPiece PageAddScriptHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageAddScriptHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageAddScriptHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageAddScriptHandler::output() const {
  // FIXME
  return fullname_;
}

PageBringToFrontHandler::PageBringToFrontHandler():
  fullname_(PageBringToFrontHandler::kFullname) {

  Init();
}

PageBringToFrontHandler::~PageBringToFrontHandler() {}

base::StringPiece PageBringToFrontHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageBringToFrontHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageBringToFrontHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageBringToFrontHandler::output() const {
  // FIXME
  return fullname_;
}

PageCloseHandler::PageCloseHandler():
  fullname_(PageCloseHandler::kFullname) {

  Init();
}

PageCloseHandler::~PageCloseHandler() {}

base::StringPiece PageCloseHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageCloseHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageCloseHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageCloseHandler::output() const {
  // FIXME
  return fullname_;
}

PageGetContentHandler::PageGetContentHandler():
  fullname_(PageGetContentHandler::kFullname) {

  Init();
}

PageGetContentHandler::~PageGetContentHandler() {}

base::StringPiece PageGetContentHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageGetContentHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageGetContentHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageGetContentHandler::output() const {
  // FIXME
  return fullname_;
}

PageNavigateHandler::PageNavigateHandler():
  fullname_(PageNavigateHandler::kFullname) {

  Init();
}

PageNavigateHandler::~PageNavigateHandler() {}

base::StringPiece PageNavigateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageNavigateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageNavigateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageNavigateHandler::output() const {
  // FIXME
  return fullname_;
}

PageReloadHandler::PageReloadHandler():
  fullname_(PageReloadHandler::kFullname) {

  Init();
}

PageReloadHandler::~PageReloadHandler() {}

base::StringPiece PageReloadHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageReloadHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageReloadHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageReloadHandler::output() const {
  // FIXME
  return fullname_;
}

PageRemoveScriptHandler::PageRemoveScriptHandler():
  fullname_(PageRemoveScriptHandler::kFullname) {

  Init();
}

PageRemoveScriptHandler::~PageRemoveScriptHandler() {}

base::StringPiece PageRemoveScriptHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageRemoveScriptHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageRemoveScriptHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageRemoveScriptHandler::output() const {
  // FIXME
  return fullname_;
}

PageSaveToPdfHandler::PageSaveToPdfHandler():
  fullname_(PageSaveToPdfHandler::kFullname) {

  Init();
}

PageSaveToPdfHandler::~PageSaveToPdfHandler() {}

base::StringPiece PageSaveToPdfHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageSaveToPdfHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageSaveToPdfHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageSaveToPdfHandler::output() const {
  // FIXME
  return fullname_;
}

PageScreenshotHandler::PageScreenshotHandler():
  fullname_(PageScreenshotHandler::kFullname) {

  Init();
}

PageScreenshotHandler::~PageScreenshotHandler() {}

base::StringPiece PageScreenshotHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageScreenshotHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageScreenshotHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageScreenshotHandler::output() const {
  // FIXME
  return fullname_;
}

PageSetContentHandler::PageSetContentHandler():
  fullname_(PageSetContentHandler::kFullname) {

  Init();
}

PageSetContentHandler::~PageSetContentHandler() {}

base::StringPiece PageSetContentHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageSetContentHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageSetContentHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageSetContentHandler::output() const {
  // FIXME
  return fullname_;
}

PageStopLoadingHandler::PageStopLoadingHandler():
  fullname_(PageStopLoadingHandler::kFullname) {

  Init();
}

PageStopLoadingHandler::~PageStopLoadingHandler() {}

base::StringPiece PageStopLoadingHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void PageStopLoadingHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void PageStopLoadingHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& PageStopLoadingHandler::output() const {
  // FIXME
  return fullname_;
}


}