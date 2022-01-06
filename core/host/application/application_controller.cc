// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_controller.h"

#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/ui/tablist/tablist.h"
#include "core/host/ui/tablist/tablist_model.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/navigator_params.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_commands.h"
#include "core/host/volume/volume.h"
#include "net/rpc/server/rpc_socket_client.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/schema/schema.h"
#include "core/host/host_thread.h"
#include "core/host/route/route_registry.h"
#include "core/host/application/application_manager_host.h"
#include "core/host/application/application.h"
#include "core/host/application/runnable_manager.h"
#include "url/gurl.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"

namespace host {

namespace {

struct StartupTab {
  StartupTab() {}
  StartupTab(const GURL& address, bool pinned): url(address), is_pinned(pinned) {}
  ~StartupTab() {}

  GURL url;
  bool is_pinned = false;
};  

// void RunPendingCallbacksOnIO(common::mojom::ApplicationStatus status, ApplicationReplyCallback cb) {
//   std::move(cb).Run(status);
// }

// void RunPendingCallbacksOnIO(common::mojom::ApplicationStatus status, base::Callback<void(int)> user_callback) {
//   std::move(user_callback).Run(status == common::mojom::ApplicationStatus::kOk ? net::OK : net::ERR_FAILED);
// }

}

ApplicationController::ApplicationController(scoped_refptr<Workspace> workspace): 
  workspace_(workspace),
  runnable_manager_(workspace->runnable_manager()),
  pending_launches_(0) {

}

ApplicationController::~ApplicationController() {

}

void ApplicationController::InstallApplication(const std::string& identifier, base::Callback<void(int)> callback) {
  if (identifier.find_first_of("/") != std::string::npos) {
#if defined(OS_WIN)
    std::wstring result;
    DCHECK(base::UTF8ToWide(data.data(), data.size(), &result));
    base::FilePath path(result);
#else
    base::FilePath path(identifier);
#endif
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), base::WithBaseSyncPrimitives() },
      base::Bind(
        &ApplicationController::InstallApplicationFromPath,
          base::Unretained(this),
          path, 
          base::Passed(std::move(callback))));
  } else {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), base::WithBaseSyncPrimitives() },
      base::Bind(
        &ApplicationController::InstallApplicationFromDHTAddress,
          base::Unretained(this),
          identifier, 
          base::Passed(std::move(callback))));
  }
}

void ApplicationController::LaunchApplication(const GURL& url, LaunchOptions options, base::Callback<void(int)> callback, int app_id) {
  int id = app_id;
  if (id == -1) {
    id = workspace_->generate_next_application_id();
  }
  std::string app_name = url.scheme();
  
  options.user_callback = std::move(callback);
  launch_options_.emplace(std::make_pair(id, std::move(options)));
  // // check if the url already have an entry first
  // if (!workspace_->route_registry()->model()->HaveEntry(url)) {
  //   LOG(ERROR) << "failed to launch application " << url << ". Url entry not registered";
  //   if (!callback.is_null()) {
  //     std::move(callback).Run(net::ERR_FAILED);
  //   }
  //   return;
  // }
  Domain* domain = workspace_->GetDomain(app_name);
  if (!domain) {
    //DLOG(ERROR) << "no app found named '" << app_name << "'";
    if (!callback.is_null()) {
      std::move(callback).Run(net::ERR_FAILED);
    }
    return;
  }
  // take care to not add it twice as observer
  if (!domain->HaveObserver(this)) {
    domain->AddObserver(this);
  }

  common::mojom::ApplicationManagerClient* client = domain->host_manager()->GetApplicationManagerClientInterface();
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &common::mojom::ApplicationManagerClient::ClientApplicationLaunch,
      base::Unretained(client),
      id,
      url.spec(),
      options.window_mode,
      options.initial_bounds,
      options.window_open_disposition,
      options.fullscreen,
      options.headless,
      base::Bind(&ApplicationController::LaunchApplicationReply,
        base::Unretained(this),
        url.spec())));
}

void ApplicationController::LaunchApplicationAck(
  int app_id, 
  const std::string& app_name, 
  const GURL& app_url, 
  const base::UUID& app_uuid,
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless,
  ApplicationReplyCallback cb) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // FIXME: SHOW_STATE_MINIMIZED = 2
  //        SHOW_STATE_MAXIMIZED = 3
  //        SHOW_STATE_INACTIVE = 4
  // we have just fullscreen ..
  
  
  //DLOG(INFO) << "ApplicationController::LaunchApplicationAck: " << app_id << " headless? " << headless;
  Domain* domain = workspace_->GetDomain(app_name);
  
  if (!domain) {
    //DLOG(ERROR) << "no app found named '" << app_name << "'";
    //std::move(cb).Run(common::mojom::ApplicationStatus::kError);
    HostThread::PostTask(
        HostThread::IO, 
        FROM_HERE, 
        base::BindOnce(std::move(cb), common::mojom::ApplicationStatus::kError));
    return;
  }

  pending_launches_--;

  auto options_it = launch_options_.find(app_id);
  LaunchOptions options = std::move(options_it->second);
  launch_options_.erase(options_it);

  Application* app_handle = domain->NewApplication(
    app_id, 
    app_name, 
    app_url, 
    app_uuid, 
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless);

  // push a pending notification notice
  AddPendingNotification(app_handle, std::move(cb), std::move(options.user_callback));

  display::Screen* screen = display::Screen::GetScreen();
  display::Display display = screen->GetPrimaryDisplay();

  std::vector<StartupTab> tabs;
  TabStyle style = TabStyle::kAPP;
  ui::WindowShowState window_show_state = ui::SHOW_STATE_DEFAULT;
  
  if (fullscreen) {
    window_show_state = ui::SHOW_STATE_FULLSCREEN;
  }
  Dock::CreateParams params = Dock::CreateParams(window_mode, workspace_, app_url, initial_bounds, window_show_state, false);
  params.tabs_hidden = window_mode != Dock::TYPE_TABBED;
  Dock* dock = Dock::GetOrCreate(app_url, params);

  // in the embedded case, the caller is responsible for the app contents
  if (!options.embedded_view) {
    //Dock* dock = new Dock(params);
    bool first_tab = true;
    for (size_t i = 0; i < tabs.size(); ++i) {
      int add_types = first_tab ? TablistModel::ADD_ACTIVE :
                                  TablistModel::ADD_NONE;
      add_types |= TablistModel::ADD_FORCE_INDEX;
      if (tabs[i].is_pinned)
        add_types |= TablistModel::ADD_PINNED;

      NavigateParams params(dock, tabs[i].url,
                            ui::PAGE_TRANSITION_AUTO_TOPLEVEL);
      params.disposition = WindowOpenDisposition::NEW_FOREGROUND_TAB;
      params.tablist_add_types = add_types;
      params.application = app_handle;

      Navigate(&params);

      first_tab = false;
    }
    if (!dock->tablist_model()->GetActiveApplicationContents()) {
      if (!dock->tablist_model()->count()) {
        host::AddTabAt(dock, app_url, app_handle, -1, true, style);
      } else {
        dock->tablist_model()->ActivateTabAt(0, false);
      }
    } else {
      int tab_index = dock->tablist_model()->count();
      host::AddTabAt(dock, app_url, app_handle, tab_index, true, style);
    }
    app_handle->set_dock(dock);
  } else {// embedded cases
    int add_types = TablistModel::ADD_NONE;
    NavigateParams params(dock, app_url, ui::PAGE_TRANSITION_AUTO_TOPLEVEL);
    params.disposition = WindowOpenDisposition::NEW_FOREGROUND_TAB;
    params.tablist_add_types = add_types;
    params.application = app_handle;
    params.tab_style = TabStyle::kEMBED;
    app_handle->set_dock(dock);
    Navigate(&params);
  }

  // the AddPendingNotification() above was commented in favor of returning to the caller waiting
  // for the result of the launch
  // HostThread::PostTask(
  //       HostThread::IO, 
  //       FROM_HERE, 
  //       base::BindOnce(&RunPendingCallbackOnIO, 
  //       common::mojom::ApplicationStatus::kOk, 
  //       base::Passed(std::move(cb))));
}

bool ApplicationController::ActivateApplication(const std::string& scheme, int app_id) {
  Domain* domain = workspace_->GetDomain(scheme);
  if (!domain) {
    //DLOG(ERROR) << "no app found named '" << scheme << "'";
    return false;
  }
  Application* app = domain->GetApplication(app_id);
  if (!app) {
    return false;
  }
  Dock* dock = app->dock();
  TablistModel* tabs = dock->tablist_model();
  int index = tabs->GetIndexOfApplicationContents(app->contents());
  tabs->ActivateTabAt(index, false);
  return true;
}

bool ApplicationController::TerminateApplication(const std::string& scheme, int app_id) {
  Runnable* runnable = runnable_manager_->GetRunnable(app_id);
  if (!runnable) {
    return false;
  }
  runnable->TerminateNow();
  return true;
}

void ApplicationController::TerminateAllApplications(const std::string& scheme) {
  std::vector<Runnable*> runnables = runnable_manager_->GetRunnablesForDomain(scheme);
  for (auto* runnable : runnables) {
    runnable->TerminateNow();
  }
}

bool ApplicationController::CloseApplication(int app_id) {
  const auto& apps = workspace_->domain_manager()->apps();
  // this is very expensive for a close.. 
  // we should have some sort of ProcessMonitor with ids as keys
  // for every child process
  for (auto it = apps.begin(); it != apps.end(); ++it) {
    Domain* app = it->second;
    if (app->HaveApplication(app_id)) {
      SendCloseApplication(app, app_id);
      return true;
    }
  }
  return false;
}

bool ApplicationController::CloseApplicationAck(const std::string& scheme, int app_id) {
  Domain* domain = workspace_->GetDomain(scheme);
  if (!domain) {
    //DLOG(ERROR) << "no app found named '" << scheme << "'";
    return false;
  }
  Application* app = domain->GetApplication(app_id);
  if (!app) {
    return false;
  }
  ApplicationContents* contents = app->contents();
  if (!contents) {
    //DLOG(INFO) << "ApplicationController::CloseApplication: no contents attached. should kill process directly. (doing nothing for now)";
    return false;
  }
  contents->Close();
  return true;
}

void ApplicationController::LaunchApplicationReply(
  const std::string& app_name, 
  common::mojom::ApplicationStatus status, 
  common::mojom::ApplicationInstancePtr instance) {
  ////DLOG(INFO) << "Domain::LaunchApplicationReply for "<< app_name << ": ok? " << (status == common::mojom::ApplicationStatus::kOk);

  // This is just a ACK from app host process that it received the launch message..
  // to really launch now, the app host process must ask host(us) for it
  // we keep this counter to see if maybe some of them are missing
  pending_launches_++;
}

void ApplicationController::InstallApplicationFromPath(const base::FilePath& path, base::Callback<void(int)> cb) {
  workspace_->InstallVolumeSync(
      path,
      base::Bind(&ApplicationController::OnInstallVolumeReply, 
        base::Unretained(this),
        base::Passed(std::move(cb))));
}

void ApplicationController::InstallApplicationFromDHTAddress(const std::string& dht_address, base::Callback<void(int)> cb) {
  workspace_->InstallVolumeFromDHTAddressSync(
      dht_address,
      base::Bind(&ApplicationController::OnInstallVolumeReply, 
        base::Unretained(this),
        base::Passed(std::move(cb))));
}

void ApplicationController::AddPendingNotification(Application* app, ApplicationReplyCallback cb, base::Callback<void(int)> user_callback) {
  auto pending = std::make_unique<PendingNotification>();
  pending->target = app;
  pending->callback = std::move(cb);
  pending->user_callback = std::move(user_callback);
  pending_notifications_.push_back(std::move(pending));
}

void ApplicationController::ProcessPendingNotification(Application* app, common::mojom::ApplicationStatus status) {
  //DLOG(INFO) << "ApplicationController::ProcessPendingNotification";
  for (auto it = pending_notifications_.begin(); it != pending_notifications_.end(); ++it) {
    if ((*it)->target == app) {
      //DLOG(INFO) << "ApplicationController::ProcessPendingNotification: calling callback for application '" << app->name() << "'";
      // HostThread::PostTask(
      //   HostThread::IO, 
      //   FROM_HERE, 
      //   base::BindOnce(&RunPendingCallbacksOnIO, 
      //   status, 
      //   base::Passed(std::move((*it)->callback)),
      //   base::Passed(std::move((*it)->user_callback))));
      //std::move((*it)->callback).Run(status);
      // HostThread::PostTask(
      //   HostThread::IO, 
      //   FROM_HERE, 
      //   base::BindOnce(&RunPendingCallbacksOnIO, 
      //   status, 
      //   base::Passed(std::move((*it)->callback))));
      
      //  HostThread::PostTask(
      //   HostThread::IO, 
      //   FROM_HERE, 
      //   base::BindOnce(&RunPendingCallbacksOnIO, 
      //   status, 
      //   base::Passed(std::move((*it)->user_callback))));
      std::move((*it)->user_callback).Run(status == common::mojom::ApplicationStatus::kOk ? net::OK : net::ERR_FAILED);
      std::move((*it)->callback).Run(status);

      pending_notifications_.erase(it);
      return;
    }
  } 
}

void ApplicationController::OnApplicationInitialized(Domain* domain, Application* application) {
  //DLOG(INFO) << "ApplicationController::OnApplicationInitialized";
}

void ApplicationController::OnApplicationLaunched(Domain* domain, Application* application) {
  //DLOG(INFO) << "ApplicationController::OnApplicationLaunched";
  ProcessPendingNotification(application, common::mojom::ApplicationStatus::kOk);
}

void ApplicationController::OnApplicationShutdown(Domain* domain, Application* application) {
  //DLOG(INFO) << "ApplicationController::OnApplicationShutdown";
  ProcessPendingNotification(application, common::mojom::ApplicationStatus::kError);
}

void ApplicationController::OnInstallVolumeReply(base::Callback<void(int)> cb, std::pair<bool, Volume*> result) {
  //LOG(INFO) << "volume install " << (result.first ? "ok" : "failed");
  if (result.first) {
    Volume* volume = result.second;
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), base::WithBaseSyncPrimitives() },
      base::BindOnce(
        &ApplicationController::CreateDomain,
        base::Unretained(this),
        base::Unretained(volume),
        base::Passed(std::move(cb))));
  }
  if (!cb.is_null()) {
    std::move(cb).Run(result.first ? net::OK : net::ERR_FAILED);
  }
}

void ApplicationController::CreateDomain(Volume* volume, base::Callback<void(int)> cb) {
  workspace_->CreateDomainFromVolume(volume, base::Bind(&ApplicationController::OnApplicationInstalled, base::Unretained(this), std::move(cb)));
}

void ApplicationController::OnApplicationInstalled(base::Callback<void(int)> cb, int result) {
  SchemaRegistry* schema_registry = workspace_->schema_registry();
  //Schema* mumba_schema = schema_registry->GetSchemaByName("mumba.proto");
  Schema* mumba_schema = schema_registry->GetSchemaByName("mumba");
  if (!mumba_schema) {
    //DLOG(INFO) << "main 'mumba' schema not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }
  const google::protobuf::Descriptor* message_descriptor = mumba_schema->GetMessageDescriptorNamed("Response");
  if (!message_descriptor) {
    //DLOG(INFO) << "output message for ServiceStart() 'ReplyStatus' not found";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }

    return;
  }
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
  google::protobuf::Message* mutable_message = message->New();
  const google::protobuf::Reflection* output_reflection = mutable_message->GetReflection();
  const google::protobuf::FieldDescriptor* status_field = message_descriptor->FindFieldByName("status_code");
  DCHECK(status_field);
  const google::protobuf::FieldDescriptor* message_field = message_descriptor->FindFieldByName("message");
  DCHECK(message_field);
  output_reflection->SetInt32(mutable_message, status_field, result == net::OK ? 200 : 500);
  output_reflection->SetString(mutable_message, message_field, result == net::OK ? "OK" : "FAILED");
  if (!mutable_message->SerializeToString(&install_output_)) {
    //DLOG(INFO) << "failed to serialize the message to string";
    if (!cb.is_null()) {
      HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, net::ERR_FAILED));
    }
    return;
  }
  if (!cb.is_null()) {
    HostThread::PostTask(HostThread::IO, FROM_HERE, base::BindOnce(cb, result));
  }
}

void ApplicationController::SendCloseApplication(Domain* domain, int id) {
  common::mojom::ApplicationManagerClient* client = domain->host_manager()->GetApplicationManagerClientInterface();
  //FIXME: we should have a shared int id and thats all that should be needed.
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE, 
    base::BindOnce(
      &common::mojom::ApplicationManagerClient::ClientApplicationClose,
      base::Unretained(client),
      domain->name(),
      id,
      base::BindOnce(&ApplicationController::CloseApplicationReply, base::Unretained(this))));
}

void ApplicationController::CloseApplicationReply(
  common::mojom::ApplicationStatus status) {
 // //DLOG(INFO) << "Domain::CloseApplicationReply: status = " << (int)status;
}

}