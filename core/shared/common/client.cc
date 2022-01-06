// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/client.h"

#include "base/lazy_instance.h"
#include "base/debug/crash_logging.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "gpu/config/gpu_info.h"
#include "gpu/config/gpu_util.h"
#include "components/services/heap_profiling/public/cpp/client.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/simple_connection_filter.h"
#include "ui/base/resource/resource_bundle.h"

namespace common {

static Client* g_client;

Client::Schemes::Schemes() = default;
Client::Schemes::~Schemes() = default;

Client::Client(): host_client_(nullptr),
                  application_client_(nullptr),
                  gpu_client_(nullptr),
                  utility_client_(nullptr) {

}

Client::~Client() {

}

Client* GetClient() {
 return g_client;
}

void SetClient(Client* client) {
 g_client = client;
}

void Client::SetGpuInfo(const gpu::GPUInfo& gpu_info) {
  gpu::SetKeysForCrashLogging(gpu_info);
}

std::string Client::GetProduct() const {
 return std::string();
}

std::string Client::GetUserAgent() const {
  return std::string();
}

base::RefCountedMemory* Client::GetDataResourceBytes(
    int resource_id) {
  return nullptr;
}

base::string16 Client::GetLocalizedString(int message_id) const {
  return base::string16();
}

base::StringPiece Client::GetDataResource(
      int resource_id,
      ui::ScaleFactor scale_factor) const {
  return ui::ResourceBundle::GetSharedInstance().GetRawDataResourceForScale(
      resource_id, scale_factor);
}

bool Client::AllowScriptExtensionForServiceWorker(const GURL& script_url) {
  return false;
}

void Client::OnServiceManagerConnected(ServiceManagerConnection* connection) {
  static base::LazyInstance<heap_profiling::Client>::Leaky profiling_client =
      LAZY_INSTANCE_INITIALIZER;

  std::unique_ptr<service_manager::BinderRegistry> registry(
      new service_manager::BinderRegistry);
  registry->AddInterface(
      base::BindRepeating(&heap_profiling::Client::BindToInterface,
                          base::Unretained(&profiling_client.Get())));
  connection->AddConnectionFilter(
      std::make_unique<SimpleConnectionFilter>(std::move(registry)));
}

}