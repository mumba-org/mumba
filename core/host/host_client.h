// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_CLIENT_H__
#define MUMBA_HOST_HOST_CLIENT_H__

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/callback_forward.h"
#include "base/command_line.h"
#include "base/task_runner.h"
#include "base/memory/linked_ptr.h"
#include <memory>
#include "base/memory/ref_counted.h"
#include "base/values.h"
#include "net/base/mime_util.h"
#include "net/cookies/canonical_cookie.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_job_factory.h"
#include "core/shared/common/client.h"
#include "core/shared/common/content_export.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/mojom/service.mojom.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_registry.h"

#if defined(OS_POSIX) && !defined(OS_MACOSX)
#include "base/posix/global_descriptors.h"
#endif

namespace mojo {
class ApplicationDelegate;
}

namespace gfx {
class ImageSkia;  
}

namespace sandbox {
class TargetPolicy;
}

namespace host {
class DomainProcessHost;
class ApplicationProcessHost;
class ApplicationWindowHost;
class ControllerPresentationServiceDelegate;
class ApplicationContents;
class MediaObserver;
class ApplicationContentsViewDelegate;
class PictureInPictureWindowController;
class OverlayWindow;

class CONTENT_EXPORT HostClient {
public:
 HostClient();
 virtual ~HostClient();

 // Allows the embedder to change the default behavior of
 // HostThread::PostAfterStartupTask to better match whatever
 // definition of "startup" the embedder has in mind. This may be
 // called on any thread.
 // Note: see related HostThread::PostAfterStartupTask.
 void PostAfterStartupTask(
  const base::Location& from_here,
  const scoped_refptr<base::TaskRunner>& task_runner,
  base::OnceClosure task);

 base::FilePath GetShaderStorageCacheDirectory();

 using StaticMojoApplicationMap =
  std::map<GURL, base::Callback<std::unique_ptr<mojo::ApplicationDelegate>()>>;

 void RegisterInProcessMojoApplications(
  StaticMojoApplicationMap* apps);

 ApplicationContentsViewDelegate* GetApplicationContentsViewDelegate(
  ApplicationContents* app_contents);

 using OutOfProcessMojoApplicationMap = std::map<GURL, base::string16>;

 void RegisterOutOfProcessMojoApplications(
  OutOfProcessMojoApplicationMap* apps);

 void RegisterUnsandboxedOutOfProcessMojoApplications(
  OutOfProcessMojoApplicationMap* apps);

 void ExposeInterfacesToDomain(
      service_manager::BinderRegistry* registry,
      blink::AssociatedInterfaceRegistry* associated_registry,
      DomainProcessHost* domain_process_host);

   // Allows to register browser interfaces exposed through the
  // RenderProcessHost. Note that interface factory callbacks added to
  // |registry| will by default be run immediately on the IO thread, unless a
  // task runner is provided.
  virtual void ExposeInterfacesToApplication(
      service_manager::BinderRegistry* registry,
      blink::AssociatedInterfaceRegistry* associated_registry,
      ApplicationProcessHost* application_process_host) {}

  // Called when RenderFrameHostImpl connects to the Media service. Expose
  // interfaces to the service using |registry|.
  virtual void ExposeInterfacesToMediaService(
      service_manager::BinderRegistry* registry,
      ApplicationWindowHost* app_window_host) {}

 void DomainProcessWillLaunch(
    DomainProcessHost* host,
    service_manager::mojom::ServiceRequest* service_request);

 void ApplicationProcessWillLaunch(
    ApplicationProcessHost* host,
    service_manager::mojom::ServiceRequest* service_request);

 // Allows the embedder to pass extra command line flags.
 // switches::kProcessType will already be set at this point.
 void AppendExtraCommandLineSwitches(base::CommandLine* command_line,
  int child_process_id);

 void OverrideOnBindInterface(
      const service_manager::BindSourceInfo& remote_info,
      const std::string& name,
      mojo::ScopedMessagePipeHandle* handle);

 MediaObserver* GetMediaObserver();

 std::unique_ptr<OverlayWindow> CreateWindowForPictureInPicture(
    PictureInPictureWindowController* controller);

 const gfx::ImageSkia* GetDefaultFavicon();

#if defined(OS_WIN)
  // This is called on the PROCESS_LAUNCHER thread before the application process
  // is launched. It gives the embedder a chance to add loosen the sandbox
  // policy.
  bool PreSpawnApplication(sandbox::TargetPolicy* policy);
  bool PreSpawnDomain(sandbox::TargetPolicy* policy);
  // Returns the AppDomain SID for the specified sandboxed process type, or
  // empty string if this sandboxed process type does not support living inside
  // an AppDomain.
  base::string16 GetAppContainerSidForSandboxType(
      int sandbox_type) const;

#endif

ControllerPresentationServiceDelegate* 
   GetControllerPresentationServiceDelegate(ApplicationContents* application_contents);

private:

 DISALLOW_COPY_AND_ASSIGN(HostClient);
};

}

#endif