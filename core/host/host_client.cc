// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_client.h"

#include "base/files/file_path.h"
#include "base/path_service.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/host/host_service.h"
#include "core/host/application/domain_process_host.h"
#include "services/service_manager/public/cpp/connector.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/presentation_service_delegate.h"
#include "core/host/application/application_contents_view_delegate_views.h"
#include "core/host/ui/picture_in_picture_window_controller.h"
#include "core/host/ui/overlay_window.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/resources/grit/ui_resources.h"

namespace host {

HostClient::HostClient() {

}

HostClient::~HostClient() {
 
}

void HostClient::PostAfterStartupTask(
 const base::Location& from_here,
 const scoped_refptr<base::TaskRunner>& task_runner,
 base::OnceClosure task) {
 task_runner->PostTask(from_here, std::move(task));
}

void HostClient::RegisterInProcessMojoApplications(
 StaticMojoApplicationMap* apps) {

}

void HostClient::RegisterOutOfProcessMojoApplications(
 OutOfProcessMojoApplicationMap* apps) {

}

void HostClient::RegisterUnsandboxedOutOfProcessMojoApplications(
 OutOfProcessMojoApplicationMap* apps) {

}

ApplicationContentsViewDelegate* HostClient::GetApplicationContentsViewDelegate(
  ApplicationContents* app_contents) {
  return CreateApplicationContentsViewDelegate(app_contents);
}

base::FilePath HostClient::GetShaderStorageCacheDirectory() {
 base::FilePath user_data_dir;
 PathService::Get(common::DIR_ROOT, &user_data_dir);
 DCHECK(!user_data_dir.empty());
 return user_data_dir.Append(FILE_PATH_LITERAL("ShaderCache"));
}

void HostClient::ExposeInterfacesToDomain(
      service_manager::BinderRegistry* registry,
      blink::AssociatedInterfaceRegistry* associated_registry,
      DomainProcessHost* domain_process_host) {

}

void HostClient::ApplicationProcessWillLaunch(
    ApplicationProcessHost* host,
    service_manager::mojom::ServiceRequest* service_request) {
  service_manager::mojom::ServicePtr service;
  *service_request = mojo::MakeRequest(&service);
  service_manager::mojom::PIDReceiverPtr pid_receiver;
  service_manager::Identity domain_identity = host->GetChildIdentity();
  HostService::GetInstance()->connector()->StartService(
      service_manager::Identity(common::mojom::kApplicationServiceName,
                                domain_identity.user_id(),
                                domain_identity.instance()),
      std::move(service), mojo::MakeRequest(&pid_receiver));
}

void HostClient::DomainProcessWillLaunch(
    DomainProcessHost* host,
    service_manager::mojom::ServiceRequest* service_request) {

  //int id = host->GetID();
  //host->AddFilter(new DomainMessageFilter(id));
// #if BUILDFLAG(ENABLE_WEBRTC)
//   WebRtcLoggingHandlerHost* webrtc_logging_handler_host =
//       new WebRtcLoggingHandlerHost(id, profile,
//                                    g_browser_process->webrtc_log_uploader());
//   host->AddFilter(webrtc_logging_handler_host);
//   host->SetUserData(
//       WebRtcLoggingHandlerHost::kWebRtcLoggingHandlerHostKey,
//       std::make_unique<base::UserDataAdapter<WebRtcLoggingHandlerHost>>(
//           webrtc_logging_handler_host));

//   // The audio manager outlives the host, so it's safe to hand a raw pointer to
//   // it to the AudioDebugRecordingsHandler, which is owned by the host.
//   AudioDebugRecordingsHandler* audio_debug_recordings_handler =
//       new AudioDebugRecordingsHandler(profile);
//   host->SetUserData(
//       AudioDebugRecordingsHandler::kAudioDebugRecordingsHandlerKey,
//       std::make_unique<base::UserDataAdapter<AudioDebugRecordingsHandler>>(
//           audio_debug_recordings_handler));

// #endif
  
  //chrome::mojom::RendererConfigurationAssociatedPtr rc_interface;
  //host->GetChannel()->GetRemoteAssociatedInterface(&rc_interface);
  //rc_interface->SetInitialConfiguration(is_incognito_process);

  service_manager::mojom::ServicePtr service;
  *service_request = mojo::MakeRequest(&service);
  service_manager::mojom::PIDReceiverPtr pid_receiver;
  service_manager::Identity domain_identity = host->GetChildIdentity();
  HostService::GetInstance()->connector()->StartService(
      service_manager::Identity(common::mojom::kDomainServiceName,
                                domain_identity.user_id(),
                                domain_identity.instance()),
      std::move(service), mojo::MakeRequest(&pid_receiver));
}

void HostClient::AppendExtraCommandLineSwitches(base::CommandLine* command_line,
 int child_process_id) {
}

void HostClient::OverrideOnBindInterface(
      const service_manager::BindSourceInfo& remote_info,
      const std::string& name,
      mojo::ScopedMessagePipeHandle* handle) {

}

MediaObserver* HostClient::GetMediaObserver() {
  return nullptr;
}

std::unique_ptr<OverlayWindow> HostClient::CreateWindowForPictureInPicture(
    PictureInPictureWindowController* controller) {
#if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX)
  // Note: content::OverlayWindow::Create() is defined by platform-specific
  // implementation in chrome/browser/ui/views. This layering hack, which goes
  // through //content and ContentBrowserClient, allows us to work around the
  // dependency constraints that disallow directly calling
  // chrome/browser/ui/views code either from here or from other code in
  // chrome/browser.
  return OverlayWindow::Create(controller);
#else
  return nullptr;
#endif
}

const gfx::ImageSkia* HostClient::GetDefaultFavicon() {
  ui::ResourceBundle& rb = ui::ResourceBundle::GetSharedInstance();
  return rb.GetNativeImageNamed(IDR_DEFAULT_FAVICON).ToImageSkia();
}

#if defined(OS_WIN)

bool HostClient::PreSpawnApplication(sandbox::TargetPolicy* policy) {
  return true;
}

bool HostClient::PreSpawnDomain(sandbox::TargetPolicy* policy) {
  return true;
}

base::string16 HostClient::GetAppContainerSidForSandboxType(int sandbox_type) const {
  // TODO: we need to implement this for application and shell 
  //switch(sandbox_type) {
  //  case service_manager::SANDBOX_TYPE_APPLICATION:
  //   return base::string16();
  //  case service_manager::SANDBOX_TYPE_DOMAIN:
  //   return base::string16();
  //  case service_manager::SANDBOX_TYPE_GPU:
  //   return base::string16();
  //  case service_manager::SANDBOX_TYPE_UTILITY:
  //   return base::string16(); 
  //}
  return base::string16();
}

#endif

ControllerPresentationServiceDelegate* HostClient::GetControllerPresentationServiceDelegate(
  ApplicationContents* app_contents) {
  //if (media_router::MediaRouterEnabled(web_contents->GetBrowserContext())) {
    //return media_router::PresentationServiceDelegateImpl::
    //    GetOrCreateForApplicationContents(app_contents);
  //}
  return nullptr;
}

}