// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/utility/utility_thread_impl.h"

#include <utility>

#include "base/command_line.h"
#include "build/build_config.h"
#include "core/shared/common/client.h"
#include "core/shared/common/child_process.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/simple_connection_filter.h"
#include "core/utility/content_utility_client.h"
#include "core/utility/utility_blink_platform_impl.h"
#include "core/utility/utility_blink_platform_with_sandbox_support_impl.h"
#include "core/utility/utility_service_factory.h"
#include "core/utility/blink_platform_impl.h"
#include "ipc/ipc_sync_channel.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/sandbox/switches.h"

#if !defined(OS_ANDROID)
#include "core/shared/common/resource_usage_reporter.mojom.h"
#include "net/proxy_resolution/proxy_resolver_v8.h"
#endif

#if defined(OS_MACOSX)
#include "core/common/font_loader_mac.mojom.h"
#include "core/shared/common/service_names.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#endif

namespace utility {

#if !defined(OS_ANDROID)
class ResourceUsageReporterImpl : public common::mojom::ResourceUsageReporter {
 public:
  ResourceUsageReporterImpl() {}
  ~ResourceUsageReporterImpl() override {}

 private:
  void GetUsageData(GetUsageDataCallback callback) override {
    common::mojom::ResourceUsageDataPtr data = common::mojom::ResourceUsageData::New();
    size_t total_heap_size = net::ProxyResolverV8::GetTotalHeapSize();
    if (total_heap_size) {
      data->reports_v8_stats = true;
      data->v8_bytes_allocated = total_heap_size;
      data->v8_bytes_used = net::ProxyResolverV8::GetUsedHeapSize();
    }
    std::move(callback).Run(std::move(data));
  }

  DISALLOW_COPY_AND_ASSIGN(ResourceUsageReporterImpl);
};

void CreateResourceUsageReporter(common::mojom::ResourceUsageReporterRequest request) {
  mojo::MakeStrongBinding(std::make_unique<ResourceUsageReporterImpl>(),
                          std::move(request));
}
#endif  // !defined(OS_ANDROID)

UtilityThreadImpl::UtilityThreadImpl()
    : ChildThreadImpl(common::ChildThreadImpl::Options::Builder()
                          .AutoStartServiceManagerConnection(false)
                          .Build()) {
  Init();
}

UtilityThreadImpl::UtilityThreadImpl(const common::InProcessChildThreadParams& params)
    : common::ChildThreadImpl(common::ChildThreadImpl::Options::Builder()
                          .AutoStartServiceManagerConnection(false)
                          .InBrowserProcess(params)
                          .Build()) {
  Init();
}

UtilityThreadImpl::~UtilityThreadImpl() = default;

void UtilityThreadImpl::Shutdown() {
  common::ChildThreadImpl::Shutdown();
}

void UtilityThreadImpl::ReleaseProcess() {
  if (!IsInHostProcess()) {
    common::ChildProcess::current()->ReleaseProcess();
    return;
  }

  // Close the channel to cause the UtilityProcessHost to be deleted. We need to
  // take a different code path than the multi-process case because that case
  // depends on the child process going away to close the channel, but that
  // can't happen when we're in single process mode.
  channel()->Close();
}

void UtilityThreadImpl::EnsureBlinkInitialized() {
  EnsureBlinkInitializedInternal(/*sandbox_support=*/false);
}

#if defined(OS_POSIX) && !defined(OS_ANDROID) && !defined(OS_FUCHSIA)
void UtilityThreadImpl::EnsureBlinkInitializedWithSandboxSupport() {
  EnsureBlinkInitializedInternal(/*sandbox_support=*/true);
}
#endif

void UtilityThreadImpl::EnsureBlinkInitializedInternal(bool sandbox_support) {
  if (blink_platform_impl_)
    return;

  // We can only initialize Blink on one thread, and in single process mode
  // we run the utility thread on a separate thread. This means that if any
  // code needs Blink initialized in the utility process, they need to have
  // another path to support single process mode.
  if (IsInHostProcess())
    return;

  blink_platform_impl_ =
      sandbox_support
          ? std::make_unique<UtilityBlinkPlatformWithSandboxSupportImpl>()
          : std::make_unique<UtilityBlinkPlatformImpl>();
  blink::Platform::Initialize(blink_platform_impl_.get());
}

void UtilityThreadImpl::Init() {
  common::ChildProcess::current()->AddRefProcess();

  auto registry = std::make_unique<service_manager::BinderRegistry>();
  registry->AddInterface(
      base::Bind(&UtilityThreadImpl::BindServiceFactoryRequest,
                 base::Unretained(this)),
      base::ThreadTaskRunnerHandle::Get());
#if !defined(OS_ANDROID)
  if (!base::CommandLine::ForCurrentProcess()->HasSwitch(
          service_manager::switches::kNoneSandboxAndElevatedPrivileges)) {
    registry->AddInterface(base::BindRepeating(CreateResourceUsageReporter),
                           base::ThreadTaskRunnerHandle::Get());
  }
#endif  // !defined(OS_ANDROID)

  common::ServiceManagerConnection* connection = GetServiceManagerConnection();
  if (connection) {
    connection->AddConnectionFilter(
        std::make_unique<common::SimpleConnectionFilter>(std::move(registry)));
  }

  //GetContentClient()->utility()->UtilityThreadStarted();

  service_factory_.reset(new UtilityServiceFactory);

  if (connection)
    connection->Start();
}

bool UtilityThreadImpl::OnControlMessageReceived(const IPC::Message& msg) {
  return common::GetClient()->utility()->OnMessageReceived(msg);
}

#if defined(OS_MACOSX)
common::mojom::FontLoaderMac* UtilityThreadImpl::GetFontLoaderMac() {
  DCHECK(font_loader_mac_ptr_);
  return font_loader_mac_ptr_.get();
}

void UtilityThreadImpl::InitializeFontLoaderMac(
    service_manager::Connector* connector) {
  if (!font_loader_mac_ptr_) {
    connector->BindInterface(content::mojom::kBrowserServiceName,
                             &font_loader_mac_ptr_);
  }
}
#endif

void UtilityThreadImpl::BindServiceFactoryRequest(
    service_manager::mojom::ServiceFactoryRequest request) {
  DCHECK(service_factory_);
  service_factory_bindings_.AddBinding(service_factory_.get(),
                                       std::move(request));
}

}  // namespace content
