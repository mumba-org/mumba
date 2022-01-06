// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/ml_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ml/ml_controller.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char MLDatasetAddHandler::kFullname[] = "/mumba.Mumba/MLDatasetAdd";
const char MLDatasetDropHandler::kFullname[] = "/mumba.Mumba/MLDatasetDrop";
const char MLDatasetListHandler::kFullname[] = "/mumba.Mumba/MLDatasetList";
const char MLModelAddHandler::kFullname[] = "/mumba.Mumba/MLModelAdd";
const char MLModelDropHandler::kFullname[] = "/mumba.Mumba/MLModelDrop";
const char MLModelListHandler::kFullname[] = "/mumba.Mumba/MLModelList";
const char MLPredictorInstallHandler::kFullname[] = "/mumba.Mumba/MLPredictorInstall";
const char MLPredictorListHandler::kFullname[] = "/mumba.Mumba/MLPredictorList";
const char MLPredictorRemoveHandler::kFullname[] = "/mumba.Mumba/MLPredictorRemove";

MLDatasetAddHandler::MLDatasetAddHandler():
  fullname_(MLDatasetAddHandler::kFullname) {

  Init();
}

MLDatasetAddHandler::~MLDatasetAddHandler() {}

base::StringPiece MLDatasetAddHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLDatasetAddHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->AddDataset(str_payload, std::move(cb));
}

void MLDatasetAddHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLDatasetAddHandler::output() const {
  // FIXME
  return fullname_;
}

MLDatasetDropHandler::MLDatasetDropHandler():
  fullname_(MLDatasetDropHandler::kFullname) {

  Init();
}

MLDatasetDropHandler::~MLDatasetDropHandler() {}

base::StringPiece MLDatasetDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLDatasetDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->AddDataset(str_payload, std::move(cb));
}

void MLDatasetDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLDatasetDropHandler::output() const {
  // FIXME
  return fullname_;
}

MLDatasetListHandler::MLDatasetListHandler():
  fullname_(MLDatasetListHandler::kFullname) {

  Init();
}

MLDatasetListHandler::~MLDatasetListHandler() {}

base::StringPiece MLDatasetListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLDatasetListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->ListDataset(str_payload, std::move(cb));
}

void MLDatasetListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLDatasetListHandler::output() const {
  // FIXME
  return fullname_;
}

MLModelAddHandler::MLModelAddHandler():
  fullname_(MLModelAddHandler::kFullname) {

  Init();
}

MLModelAddHandler::~MLModelAddHandler() {}

base::StringPiece MLModelAddHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLModelAddHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->AddModel(str_payload, std::move(cb));
}

void MLModelAddHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLModelAddHandler::output() const {
  // FIXME
  return fullname_;
}

MLModelDropHandler::MLModelDropHandler():
  fullname_(MLModelDropHandler::kFullname) {

  Init();
}

MLModelDropHandler::~MLModelDropHandler() {}

base::StringPiece MLModelDropHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLModelDropHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->DropModel(str_payload, std::move(cb));
}

void MLModelDropHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLModelDropHandler::output() const {
  // FIXME
  return fullname_;
}

MLModelListHandler::MLModelListHandler():
  fullname_(MLModelListHandler::kFullname) {

  Init();
}

MLModelListHandler::~MLModelListHandler() {}

base::StringPiece MLModelListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLModelListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->ListModel(str_payload, std::move(cb));
}

void MLModelListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLModelListHandler::output() const {
  // FIXME
  return fullname_;
}

MLPredictorInstallHandler::MLPredictorInstallHandler():
  fullname_(MLPredictorInstallHandler::kFullname) {

  Init();
}

MLPredictorInstallHandler::~MLPredictorInstallHandler() {}

base::StringPiece MLPredictorInstallHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLPredictorInstallHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->InstallPredictor(str_payload, std::move(cb));
}

void MLPredictorInstallHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLPredictorInstallHandler::output() const {
  //scoped_refptr<HostController> controller = HostController::Instance(); 
  //Workspace* workspace = controller->current_workspace();
  // fixme
  return fullname_;//workspace->ml_controller()->install_output();
}

MLPredictorListHandler::MLPredictorListHandler():
  fullname_(MLPredictorListHandler::kFullname) {

  Init();
}

MLPredictorListHandler::~MLPredictorListHandler() {}

base::StringPiece MLPredictorListHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLPredictorListHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->ListPredictor(str_payload, std::move(cb));
}

void MLPredictorListHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLPredictorListHandler::output() const {
  //scoped_refptr<HostController> controller = HostController::Instance(); 
  //Workspace* workspace = controller->current_workspace();
  // fixme
  return fullname_;//workspace->ml_controller()->install_output();
}

MLPredictorRemoveHandler::MLPredictorRemoveHandler():
  fullname_(MLPredictorRemoveHandler::kFullname) {

  Init();
}

MLPredictorRemoveHandler::~MLPredictorRemoveHandler() {}

base::StringPiece MLPredictorRemoveHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void MLPredictorRemoveHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // std::string str_payload(data.data(), data.size());
  // scoped_refptr<HostController> controller = HostController::Instance(); 
  // Workspace* workspace = controller->current_workspace();
  // workspace->ml_controller()->RemovePredictor(str_payload, std::move(cb));
}

void MLPredictorRemoveHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& MLPredictorRemoveHandler::output() const {
  //scoped_refptr<HostController> controller = HostController::Instance(); 
  //Workspace* workspace = controller->current_workspace();
  // fixme
  return fullname_;//workspace->ml_controller()->install_output();
}


}