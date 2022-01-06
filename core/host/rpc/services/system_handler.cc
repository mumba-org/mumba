// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/system_handler.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"

namespace host {

const char SystemCpuInfoHandler::kFullname[] = "/mumba.Mumba/SystemCpuInfo";
const char SystemGpuInfoHandler::kFullname[] = "/mumba.Mumba/SystemGpuInfo";
const char SystemMemoryInfoHandler::kFullname[] = "/mumba.Mumba/SystemMemoryInfo";
const char SystemShutdownHandler::kFullname[] = "/mumba.Mumba/Shutdown";
const char SystemStatusHandler::kFullname[] = "/mumba.Mumba/SystemStatus";
const char SystemStorageHandler::kFullname[] = "/mumba.Mumba/SystemStorage";
const char SystemUpdateHandler::kFullname[] = "/mumba.Mumba/SystemUpdate";
const char SystemVersionHandler::kFullname[] = "/mumba.Mumba/SystemVersion";

SystemCpuInfoHandler::SystemCpuInfoHandler():
  fullname_(SystemCpuInfoHandler::kFullname) {

  Init();
}

SystemCpuInfoHandler::~SystemCpuInfoHandler() {}

base::StringPiece SystemCpuInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemCpuInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemCpuInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemCpuInfoHandler::output() const {
  // FIXME
  return fullname_;
}

SystemGpuInfoHandler::SystemGpuInfoHandler():
  fullname_(SystemGpuInfoHandler::kFullname) {

  Init();
}

SystemGpuInfoHandler::~SystemGpuInfoHandler() {}

base::StringPiece SystemGpuInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemGpuInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemGpuInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemGpuInfoHandler::output() const {
  // FIXME
  return fullname_;
}

SystemMemoryInfoHandler::SystemMemoryInfoHandler():
  fullname_(SystemMemoryInfoHandler::kFullname) {

  Init();
}

SystemMemoryInfoHandler::~SystemMemoryInfoHandler() {}

base::StringPiece SystemMemoryInfoHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemMemoryInfoHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemMemoryInfoHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemMemoryInfoHandler::output() const {
  // FIXME
  return fullname_;
}

SystemShutdownHandler::SystemShutdownHandler(): 
  fullname_(SystemShutdownHandler::kFullname) {
  Init();
}

SystemShutdownHandler::~SystemShutdownHandler() {

}

base::StringPiece SystemShutdownHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemShutdownHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  HostThread::PostTask(HostThread::UI,
    FROM_HERE,
    base::Bind(&SystemShutdownHandler::ShutdownOnUI, 
      base::Unretained(this),
      base::Passed(std::move(cb))));
}

void SystemShutdownHandler::ShutdownOnUI(base::Callback<void(int)> cb) {
  //DLOG(INFO) << "Shutdown: ShutdownOnUI: calling main loop quit..";
  scoped_refptr<HostController> controller = HostController::Instance();
  // perform a clean shutdown on host first
  controller->ShutdownHost();
  HostMainLoop* main_loop = HostMainLoop::GetInstance();
  DCHECK(main_loop);
  // now break the main loop
  main_loop->QuitMainMessageLoop();
  HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::OK));
}


void SystemShutdownHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
  fullname_,
  "/",
  base::KEEP_WHITESPACE,
  base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

SystemStatusHandler::SystemStatusHandler():
  fullname_(SystemStatusHandler::kFullname) {

  Init();
}

SystemStatusHandler::~SystemStatusHandler() {}

base::StringPiece SystemStatusHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemStatusHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemStatusHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemStatusHandler::output() const {
  // FIXME
  return fullname_;
}

SystemStorageHandler::SystemStorageHandler():
  fullname_(SystemStorageHandler::kFullname) {

  Init();
}

SystemStorageHandler::~SystemStorageHandler() {}

base::StringPiece SystemStorageHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemStorageHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemStorageHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemStorageHandler::output() const {
  // FIXME
  return fullname_;
}

SystemUpdateHandler::SystemUpdateHandler():
  fullname_(SystemUpdateHandler::kFullname) {

  Init();
}

SystemUpdateHandler::~SystemUpdateHandler() {}

base::StringPiece SystemUpdateHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemUpdateHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemUpdateHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemUpdateHandler::output() const {
  // FIXME
  return fullname_;
}

SystemVersionHandler::SystemVersionHandler():
  fullname_(SystemVersionHandler::kFullname) {

  Init();
}

SystemVersionHandler::~SystemVersionHandler() {}

base::StringPiece SystemVersionHandler::ns() const {
  auto offset = service_name_.find_first_of(".");
  return service_name_.substr(offset);
}

void SystemVersionHandler::HandleCall(std::vector<char> data, base::Callback<void(int)> cb) {
  // FIXME: implement
}

void SystemVersionHandler::Init() {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
    fullname_,
    "/",
    base::KEEP_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);

  service_name_ = pieces[0];
  method_name_ = pieces[1];
}

const std::string& SystemVersionHandler::output() const {
  // FIXME
  return fullname_;
}

}