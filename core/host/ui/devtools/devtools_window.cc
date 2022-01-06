// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/devtools/devtools_window.h"

#include <algorithm>
#include <set>
#include <utility>

#include "base/base64.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/macros.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/time/time.h"
#include "base/values.h"
#include "core/host/host.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/dock_list.h"
#include "core/host/ui/tablist/dock_tablist.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/scoped_tabbed_dock_displayer.h"
#include "core/host/ui/tablist/tablist_model.h"
//#include "core/host/ui/webui/devtools_ui.h"
#include "core/shared/common/url_constants.h"
#include "components/keep_alive_registry/keep_alive_types.h"
#include "components/keep_alive_registry/scoped_keep_alive.h"
#include "components/zoom/page_zoom.h"
#include "components/zoom/zoom_controller.h"
#include "core/host/host_thread.h"
#include "core/host/child_process_security_policy.h"
#include "core/shared/common/referrer.h"
#include "core/shared/common/child_process_host.h"
//#include "core/host/devtools_agent_host.h"
#include "core/host/application/keyboard_event_processing_result.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application/navigation_controller.h"
#include "core/host/application/navigation_entry.h"
#include "core/host/application/application.h"
//#include "core/host/navigation_handle.h"
//#include "core/host/navigation_throttle.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_controller.h"
#include "core/shared/common/client.h"
#include "core/shared/common/url_constants.h"
#include "net/base/escape.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/blink/public/platform/web_input_event.h"
//#include "third_party/blink/public/common/renderer_preferences/renderer_preferences.h"
#include "third_party/blink/public/public_buildflags.h"
#include "ui/base/page_transition_types.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "ui/events/keycodes/keyboard_code_conversion.h"
#include "ui/events/keycodes/keyboard_codes.h"

using base::DictionaryValue;
using blink::WebInputEvent;

namespace host {

namespace {

typedef std::vector<DevToolsWindow*> DevToolsWindows;
base::LazyInstance<DevToolsWindows>::Leaky g_devtools_window_instances =
    LAZY_INSTANCE_INITIALIZER;

base::LazyInstance<
    std::vector<base::RepeatingCallback<void(DevToolsWindow*)>>>::Leaky
    g_creation_callbacks = LAZY_INSTANCE_INITIALIZER;

static const char kKeyUpEventName[] = "keyup";
static const char kKeyDownEventName[] = "keydown";
static const char kDefaultFrontendURL[] =
    "devtools://devtools/bundled/devtools_app.html";
static const char kWorkerFrontendURL[] =
    "devtools://devtools/bundled/worker_app.html";
static const char kJSFrontendURL[] = "devtools://devtools/bundled/js_app.html";
// static const char kFallbackFrontendURL[] =
//     "devtools://devtools/bundled/inspector.html";

bool FindInspectedDockAndTabIndex(
  ApplicationContents* inspected_app_contents, Dock** dock, int* tab) {
  if (!inspected_app_contents)
    return false;

  for (auto* b : *DockList::GetInstance()) {
    int tab_index =
        b->tablist_model()->GetIndexOfApplicationContents(inspected_app_contents);
    if (tab_index != TablistModel::kNoTab) {
      *dock = b;
      *tab = tab_index;
      return true;
    }
  }
  return false;
}


// DevToolsToolboxDelegate ----------------------------------------------------

class DevToolsToolboxDelegate
    : public ApplicationContentsObserver,
      public ApplicationContentsDelegate {
 public:
  DevToolsToolboxDelegate(
      ApplicationContents* toolbox_contents,
      DevToolsWindow::ObserverWithAccessor* app_contents_observer);
  ~DevToolsToolboxDelegate() override;

  ApplicationContents* OpenURL(
      ApplicationContents* source,
      const OpenURLParams& params) override;
  KeyboardEventProcessingResult PreHandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event) override;
  void HandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event) override;
  void ApplicationContentsDestroyed() override;

 private:
  DockWindow* GetInspectedDockWindow();
  DevToolsWindow::ObserverWithAccessor* inspected_contents_observer_;
  DISALLOW_COPY_AND_ASSIGN(DevToolsToolboxDelegate);
};

DevToolsToolboxDelegate::DevToolsToolboxDelegate(
    ApplicationContents* toolbox_contents,
    DevToolsWindow::ObserverWithAccessor* app_contents_observer)
    : ApplicationContentsObserver(toolbox_contents),
      inspected_contents_observer_(app_contents_observer) {
}

DevToolsToolboxDelegate::~DevToolsToolboxDelegate() {
}

ApplicationContents* DevToolsToolboxDelegate::OpenURL(
    ApplicationContents* source,
    const OpenURLParams& params) {
  //DCHECK(source == application_contents());
  //if (!params.url.SchemeIs(content::kChromeDevToolsScheme))
  //  return nullptr;
  //source->GetController().LoadURLWithParams(
  //    NavigationController::LoadURLParams(params));
  DCHECK(false);
  return source;
}

KeyboardEventProcessingResult
DevToolsToolboxDelegate::PreHandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  DockWindow* window = GetInspectedDockWindow();
  if (window)
    return window->PreHandleKeyboardEvent(event);
  return KeyboardEventProcessingResult::NOT_HANDLED;
}

void DevToolsToolboxDelegate::HandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  if (event.windows_key_code == 0x08) {
    // Do not navigate back in history on Windows (http://crbug.com/74156).
    return;
  }
  DockWindow* window = GetInspectedDockWindow();
  if (window) {
    window->HandleKeyboardEvent(event);
  }
}

void DevToolsToolboxDelegate::ApplicationContentsDestroyed() {
  delete this;
}

DockWindow* DevToolsToolboxDelegate::GetInspectedDockWindow() {
  ApplicationContents* inspected_contents =
      inspected_contents_observer_->application_contents();
  if (!inspected_contents)
    return nullptr;
  Dock* dock = nullptr;
  int tab = 0;
  if (FindInspectedDockAndTabIndex(inspected_contents, &dock, &tab))
    return dock->window();
  return nullptr;
}

// static
//GURL DecorateFrontendURL(const GURL& base_url) {
  // std::string frontend_url = base_url.spec();
  // std::string url_string(
  //     frontend_url +
  //     ((frontend_url.find("?") == std::string::npos) ? "?" : "&") +
  //     "dockSide=undocked");  // TODO(dgozman): remove this support in M38.
  // base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  // if (command_line->HasSwitch(switches::kDevToolsFlags)) {
  //   url_string += "&" + command_line->GetSwitchValueASCII(
  //       switches::kDevToolsFlags);
  // }

  // if (command_line->HasSwitch(switches::kCustomDevtoolsFrontend)) {
  //   url_string += "&debugFrontend=true";
  // }

  // return GURL(url_string);
//  return base_url; 
//}

}  // namespace

// DevToolsEventForwarder -----------------------------------------------------

class DevToolsEventForwarder {
 public:
  explicit DevToolsEventForwarder(DevToolsWindow* window)
     : devtools_window_(window) {}

  // Registers whitelisted shortcuts with the forwarder.
  // Only registered keys will be forwarded to the DevTools frontend.
  void SetWhitelistedShortcuts(const std::string& message);

  // Forwards a keyboard event to the DevTools frontend if it is whitelisted.
  // Returns |true| if the event has been forwarded, |false| otherwise.
  bool ForwardEvent(const NativeWebKeyboardEvent& event);

 private:
  static bool KeyWhitelistingAllowed(int key_code, int modifiers);
  static int CombineKeyCodeAndModifiers(int key_code, int modifiers);

  DevToolsWindow* devtools_window_;
  std::set<int> whitelisted_keys_;

  DISALLOW_COPY_AND_ASSIGN(DevToolsEventForwarder);
};

// void DevToolsEventForwarder::SetWhitelistedShortcuts(
//     const std::string& message) {
//   base::Optional<base::Value> parsed_message = base::JSONReader::Read(message);
//   if (!parsed_message || !parsed_message->is_list())
//     return;
//   for (const auto& list_item : parsed_message->GetList()) {
//     if (!list_item.is_dict())
//       continue;
//     int key_code = list_item.FindIntKey("keyCode").value_or(0);
//     if (key_code == 0)
//       continue;
//     int modifiers = list_item.FindIntKey("modifiers").value_or(0);
//     if (!KeyWhitelistingAllowed(key_code, modifiers)) {
//       LOG(WARNING) << "Key whitelisting forbidden: "
//                    << "(" << key_code << "," << modifiers << ")";
//       continue;
//     }
//     whitelisted_keys_.insert(CombineKeyCodeAndModifiers(key_code, modifiers));
//   }
// }

bool DevToolsEventForwarder::ForwardEvent(
    const NativeWebKeyboardEvent& event) {
  std::string event_type;
  switch (event.GetType()) {
    case WebInputEvent::Type::kKeyDown:
    case WebInputEvent::Type::kRawKeyDown:
      event_type = kKeyDownEventName;
      break;
    case WebInputEvent::Type::kKeyUp:
      event_type = kKeyUpEventName;
      break;
    default:
      return false;
  }

  int key_code = ui::LocatedToNonLocatedKeyboardCode(
      static_cast<ui::KeyboardCode>(event.windows_key_code));
  int modifiers = event.GetModifiers() &
                  (WebInputEvent::kShiftKey | WebInputEvent::kControlKey |
                   WebInputEvent::kAltKey | WebInputEvent::kMetaKey);
  int key = CombineKeyCodeAndModifiers(key_code, modifiers);
  if (whitelisted_keys_.find(key) == whitelisted_keys_.end())
    return false;

  // base::Value event_data(base::Value::Type::DICTIONARY);
  // event_data.SetStringKey("type", event_type);
  // event_data.SetStringKey("key", ui::KeycodeConverter::DomKeyToKeyString(
  //                                    static_cast<ui::DomKey>(event.dom_key)));
  // event_data.SetStringKey("code",
  //                         ui::KeycodeConverter::DomCodeToCodeString(
  //                             static_cast<ui::DomCode>(event.dom_code)));
  // event_data.SetIntKey("keyCode", key_code);
  // event_data.SetIntKey("modifiers", modifiers);
  // devtools_window_->bindings_->CallClientMethod(
  //     "DevToolsAPI", "keyEventUnhandled", std::move(event_data));
  return true;
}

int DevToolsEventForwarder::CombineKeyCodeAndModifiers(int key_code,
                                                       int modifiers) {
  return key_code | (modifiers << 16);
}

bool DevToolsEventForwarder::KeyWhitelistingAllowed(int key_code,
                                                    int modifiers) {
  return (ui::VKEY_F1 <= key_code && key_code <= ui::VKEY_F12) ||
      modifiers != 0;
}

// DevToolsWindow::ObserverWithAccessor -------------------------------

DevToolsWindow::ObserverWithAccessor::ObserverWithAccessor(
    ApplicationContents* app_contents)
    : ApplicationContentsObserver(app_contents) {
}

DevToolsWindow::ObserverWithAccessor::~ObserverWithAccessor() {
}

// DevToolsWindow::Throttle ------------------------------------------

// class DevToolsWindow::Throttle : public content::NavigationThrottle {
//  public:
//   Throttle(NavigationHandle* navigation_handle,
//            DevToolsWindow* devtools_window)
//       : NavigationThrottle(navigation_handle),
//         devtools_window_(devtools_window) {
//     devtools_window_->throttle_ = this;
//   }

//   ~Throttle() override {
//     if (devtools_window_)
//       devtools_window_->throttle_ = nullptr;
//   }

//   // content::NavigationThrottle implementation:
//   NavigationThrottle::ThrottleCheckResult WillStartRequest() override {
//     return DEFER;
//   }

//   const char* GetNameForLogging() override { return "DevToolsWindowThrottle"; }

//   void ResumeThrottle() {
//     if (devtools_window_) {
//       devtools_window_->throttle_ = nullptr;
//       devtools_window_ = nullptr;
//     }
//     Resume();
//   }

//  private:
//   DevToolsWindow* devtools_window_;

//   DISALLOW_COPY_AND_ASSIGN(Throttle);
// };

// Helper class that holds the owned main ApplicationContents for the docked
// devtools window and maintains a keepalive object that keeps the dock
// main loop alive long enough for the ApplicationContents to clean up properly.
class DevToolsWindow::OwnedMainApplicationContents {
 public:
  explicit OwnedMainApplicationContents(
      ApplicationContents* application_contents)
      : keep_alive_(KeepAliveOrigin::DEVTOOLS_WINDOW,
                    KeepAliveRestartOption::DISABLED),
        application_contents_(application_contents) {}
  
  explicit OwnedMainApplicationContents(
      std::unique_ptr<ApplicationContents> application_contents)
      : keep_alive_(KeepAliveOrigin::DEVTOOLS_WINDOW,
                    KeepAliveRestartOption::DISABLED),
        application_contents_(std::move(application_contents)) {}

  static std::unique_ptr<ApplicationContents> TakeApplicationContents(
      std::unique_ptr<OwnedMainApplicationContents> instance) {
    return std::move(instance->application_contents_);
  }

 private:
  ScopedKeepAlive keep_alive_;
  std::unique_ptr<ApplicationContents> application_contents_;
};

// DevToolsWindow -------------------------------------------------------------

const char DevToolsWindow::kDevToolsApp[] = "DevToolsApp";

DevToolsWindow::~DevToolsWindow() {
  //if (throttle_)
  //  throttle_->ResumeThrottle();

  domain_->RemoveObserver(this);

  if (reattach_complete_callback_) {
    std::move(reattach_complete_callback_).Run();
  }

  life_stage_ = kClosing;

  UpdateDockWindow();
  UpdateDockToolbar();

  owned_toolbox_app_contents_.reset();

  DevToolsWindows* instances = g_devtools_window_instances.Pointer();
  auto it(std::find(instances->begin(), instances->end(), this));
  DCHECK(it != instances->end());
  instances->erase(it);

  if (!close_callback_.is_null())
    std::move(close_callback_).Run();
  // Defer deletion of the main web contents, since we could get here
  // via RenderFrameHostImpl method that expects ApplicationContents to live
  // for some time. See http://crbug.com/997299 for details.
  if (owned_main_app_contents_) {
    base::SequencedTaskRunnerHandle::Get()->DeleteSoon(
        FROM_HERE, std::move(owned_main_app_contents_));
  }
}


// static
void DevToolsWindow::GetInTabApplicationContents(
    ApplicationContents* inspected_app_contents,
    base::OnceCallback<void(ApplicationContents*, DevToolsContentsResizingStrategy, bool)> result) {
  DevToolsWindow* window = GetInstanceForInspectedApplicationContents(
      inspected_app_contents);
  
  if (!window || window->life_stage_ == kClosing) {
    return;
  }

  // Not yet loaded window is treated as docked, but we should not present it
  // until we decided on docking.
  // bool is_docked_set = window->life_stage_ == kLoadCompleted ||
  //     window->life_stage_ == kIsDockedSet;
  // if (!is_docked_set) {
  //   DLOG(INFO) << "DevToolsWindow::GetInTabApplicationContents: is_dock_set = false";
  //   return nullptr;
  // }

  // // Undocked window should have toolbox web contents.
  // if (!window->is_docked_ && !window->toolbox_app_contents_) {
  //   DLOG(INFO) << "DevToolsWindow::GetInTabApplicationContents: is_docked_ = false && !toolbox_app_contents_ " << window->toolbox_app_contents_;
  //   return nullptr;
  // }

  //return window->is_docked_ ? window->main_app_contents_ :
  //    window->toolbox_app_contents_;
  if (window->main_app_contents_) {
    DevToolsContentsResizingStrategy strategy;
    strategy.CopyFrom(window->contents_resizing_strategy_);
    std::move(result).Run(window->main_app_contents_, std::move(strategy), false);
    return;
  }
  window->contents_complete_callback_ = std::move(result);
}

bool DevToolsWindow::HaveAnyInstance() {
  return g_devtools_window_instances.IsCreated();
}

// static
DevToolsWindow* DevToolsWindow::GetInstanceForInspectedApplicationContents(
    ApplicationContents* inspected_app_contents) {
  if (!inspected_app_contents || !g_devtools_window_instances.IsCreated()) {
    return nullptr;
  }
  DevToolsWindows* instances = g_devtools_window_instances.Pointer();
  for (auto it(instances->begin()); it != instances->end(); ++it) {
    if ((*it)->GetInspectedApplicationContents() == inspected_app_contents)
      return *it;
  }
  return nullptr;
}

// static
bool DevToolsWindow::IsDevToolsWindow(ApplicationContents* app_contents) {
  if (!app_contents || !g_devtools_window_instances.IsCreated())
    return false;
  DevToolsWindows* instances = g_devtools_window_instances.Pointer();
  for (auto it(instances->begin()); it != instances->end(); ++it) {
    if ((*it)->main_app_contents_ == app_contents ||
        (*it)->toolbox_app_contents_ == app_contents)
      return true;
  }
  return false;
}

// // static
// void DevToolsWindow::OpenDevToolsWindowForWorker(
//     Workspace* workspace,
//     const scoped_refptr<DevToolsAgentHost>& worker_agent) {
//   DevToolsWindow* window = FindDevToolsWindow(worker_agent.get());
//   if (!window) {
//     base::RecordAction(base::UserMetricsAction("DevTools_InspectWorker"));
//     window = Create(workspace, nullptr, kFrontendWorker, std::string(), false, "",
//                     "", worker_agent->IsAttached());
//     if (!window)
//       return;
//     window->bindings_->AttachTo(worker_agent);
//   }
//   window->ScheduleShow(DevToolsToggleAction::Show());
// }

// static
void DevToolsWindow::OpenDevToolsWindow(
    ApplicationContents* inspected_app_contents) {
  ToggleDevToolsWindow(
        inspected_app_contents, true, DevToolsToggleAction::Show(), "");
}

// static
// void DevToolsWindow::OpenDevToolsWindow(
//     scoped_refptr<content::DevToolsAgentHost> agent_host,
//     Workspace* workspace) {
//   OpenDevToolsWindow(agent_host, workspace, false /* use_bundled_frontend */);
// }

// static
// void DevToolsWindow::OpenDevToolsWindowWithBundledFrontend(
//     scoped_refptr<content::DevToolsAgentHost> agent_host,
//     Workspace* workspace) {
//   OpenDevToolsWindow(agent_host, workspace, true /* use_bundled_frontend */);
// }

// static
// void DevToolsWindow::OpenDevToolsWindow(
//     scoped_refptr<content::DevToolsAgentHost> agent_host,
//     Workspace* workspace,
//     bool use_bundled_frontend) {
//   if (!workspace)
//     workspace = Workspace::FromDockContext(agent_host->GetDockContext());

//   if (!workspace)
//     return;

//   std::string type = agent_host->GetType();

//   bool is_worker = type == DevToolsAgentHost::kTypeServiceWorker ||
//                    type == DevToolsAgentHost::kTypeSharedWorker;

//   if (!agent_host->GetFrontendURL().empty()) {
//     DevToolsWindow::OpenExternalFrontend(workspace, agent_host->GetFrontendURL(),
//                                          agent_host, use_bundled_frontend);
//     return;
//   }

//   if (is_worker) {
//     DevToolsWindow::OpenDevToolsWindowForWorker(workspace, agent_host);
//     return;
//   }

//   if (type == content::DevToolsAgentHost::kTypeFrame) {
//     DevToolsWindow::OpenDevToolsWindowForFrame(workspace, agent_host);
//     return;
//   }

//   ApplicationContents* app_contents = agent_host->GetApplicationContents();
//   if (app_contents)
//     DevToolsWindow::OpenDevToolsWindow(app_contents);
// }

// static
void DevToolsWindow::OpenDevToolsWindow(
    ApplicationContents* inspected_app_contents,
    const DevToolsToggleAction& action) {
  ToggleDevToolsWindow(inspected_app_contents, true, action, "");
}

// static
// void DevToolsWindow::OpenDevToolsWindowForFrame(
//     Workspace* workspace,
//     const scoped_refptr<content::DevToolsAgentHost>& agent_host) {
//   DevToolsWindow* window = FindDevToolsWindow(agent_host.get());
//   if (!window) {
//     window = DevToolsWindow::Create(workspace, nullptr, kFrontendDefault,
//                                     std::string(), false, std::string(),
//                                     std::string(), agent_host->IsAttached());
//     if (!window)
//       return;
//     window->bindings_->AttachTo(agent_host);
//   }
//   window->ScheduleShow(DevToolsToggleAction::Show());
// }

// static
void DevToolsWindow::ToggleDevToolsWindow(Dock* dock,
                                          const DevToolsToggleAction& action,
                                          DevToolsOpenedByAction opened_by) {
  if (action.type() == DevToolsToggleAction::kToggle) {// &&
    //  dock->is_type_devtools()) {
    dock->tablist_model()->CloseAllTabs();
    return;
  }

  ToggleDevToolsWindow(dock->tablist_model()->GetActiveApplicationContents(),
                       action.type() == DevToolsToggleAction::kInspect, action,
                       "", opened_by);
}

// static
// void DevToolsWindow::OpenExternalFrontend(
//     Workspace* workspace,
//     const std::string& frontend_url,
//     const scoped_refptr<content::DevToolsAgentHost>& agent_host,
//     bool use_bundled_frontend) {
//   DevToolsWindow* window = FindDevToolsWindow(agent_host.get());
//   if (window) {
//     window->ScheduleShow(DevToolsToggleAction::Show());
//     return;
//   }

//   std::string type = agent_host->GetType();
//   if (type == "node") {
//     // Direct node targets will always open using ToT front-end.
//     window = Create(workspace, nullptr, kFrontendV8, std::string(), false,
//                     std::string(), std::string(), agent_host->IsAttached());
//   } else {
//     bool is_worker = type == DevToolsAgentHost::kTypeServiceWorker ||
//                      type == DevToolsAgentHost::kTypeSharedWorker;

//     FrontendType frontend_type =
//         is_worker ? kFrontendRemoteWorker : kFrontendRemote;
//     std::string effective_frontend_url =
//         use_bundled_frontend ? kFallbackFrontendURL
//                              : DevToolsUI::GetProxyURL(frontend_url).spec();
//     window =
//         Create(workspace, nullptr, frontend_type, effective_frontend_url, false,
//                std::string(), std::string(), agent_host->IsAttached());
//   }
//   if (!window)
//     return;
//   window->bindings_->AttachTo(agent_host);
//   window->close_on_detach_ = false;
//   window->ScheduleShow(DevToolsToggleAction::Show());
// }

// static
// DevToolsWindow* DevToolsWindow::OpenNodeFrontendWindow(Workspace* workspace) {
//   for (DevToolsWindow* window : g_devtools_window_instances.Get()) {
//     if (window->frontend_type_ == kFrontendNode) {
//       window->ActivateWindow();
//       return window;
//     }
//   }

//   DevToolsWindow* window =
//       Create(workspace, nullptr, kFrontendNode, std::string(), false,
//              std::string(), std::string(), false);
//   if (!window)
//     return nullptr;
//   window->bindings_->AttachTo(DevToolsAgentHost::CreateForDiscovery());
//   window->ScheduleShow(DevToolsToggleAction::Show());
//   return window;
// }

// static
void DevToolsWindow::ToggleDevToolsWindow(
    ApplicationContents* inspected_app_contents,
    bool force_open,
    const DevToolsToggleAction& action,
    const std::string& settings,
    DevToolsOpenedByAction opened_by) {
  //scoped_refptr<DevToolsAgentHost> agent(
  //    DevToolsAgentHost::GetOrCreateFor(inspected_app_contents));
  DevToolsWindow* window = nullptr;//FindDevToolsWindow(agent.get());
  bool do_open = force_open;
  if (!window) {
    // Workspace* workspace = Workspace::FromDockContext(
    //     inspected_app_contents->GetDockContext());
    std::string panel;
    switch (action.type()) {
      case DevToolsToggleAction::kInspect:
      case DevToolsToggleAction::kShowElementsPanel:
        panel = "elements";
        break;
      case DevToolsToggleAction::kShowConsolePanel:
        panel = "console";
        break;
      case DevToolsToggleAction::kPauseInDebugger:
        panel = "sources";
        break;
      case DevToolsToggleAction::kShow:
      case DevToolsToggleAction::kToggle:
      case DevToolsToggleAction::kReveal:
      case DevToolsToggleAction::kNoOp:
        break;
    }
    window = Create(inspected_app_contents->GetDomain()->workspace(), inspected_app_contents, kFrontendDefault,
                    std::string(), true, settings, panel, false);//agent->IsAttached());
    if (!window)
      return;
    //window->bindings_->AttachTo(agent.get());
    do_open = true;
    //if (opened_by != DevToolsOpenedByAction::kUnknown)
    //  LogDevToolsOpenedByAction(opened_by);
  }

  // Update toolbar to reflect DevTools changes.
  window->UpdateDockToolbar();

  // If window is docked and visible, we hide it on toggle. If window is
  // undocked, we show (activate) it.
  if (!window->is_docked_ || do_open)
    window->ScheduleShow(action);
  else
    window->CloseWindow();
}

// // static
// void DevToolsWindow::InspectElement(
//     content::RenderFrameHost* inspected_frame_host,
//     int x,
//     int y) {
//   ApplicationContents* app_contents =
//       ApplicationContents::FromRenderFrameHost(inspected_frame_host);
//   scoped_refptr<DevToolsAgentHost> agent(
//       DevToolsAgentHost::GetOrCreateFor(app_contents));
//   agent->InspectElement(inspected_frame_host, x, y);
//   bool should_measure_time = !FindDevToolsWindow(agent.get());
//   base::TimeTicks start_time = base::TimeTicks::Now();
//   // TODO(loislo): we should initiate DevTools window opening from within
//   // renderer. Otherwise, we still can hit a race condition here.
//   OpenDevToolsWindow(app_contents, DevToolsToggleAction::ShowElementsPanel());
//   LogDevToolsOpenedByAction(DevToolsOpenedByAction::kContextMenuInspect);
//   DevToolsWindow* window = FindDevToolsWindow(agent.get());
//   if (window && should_measure_time)
//     window->inspect_element_start_time_ = start_time;
// }

// static
// void DevToolsWindow::LogDevToolsOpenedByAction(
//     DevToolsOpenedByAction opened_by) {
//   base::UmaHistogramEnumeration("DevTools.OpenedByAction", opened_by);
// }

// static
// std::unique_ptr<content::NavigationThrottle>
// DevToolsWindow::MaybeCreateNavigationThrottle(
//     content::NavigationHandle* handle) {
//   ApplicationContents* app_contents = handle->GetApplicationContents();
//   if (!app_contents || !app_contents->HasOriginalOpener() ||
//       app_contents->GetController().GetLastCommittedEntry()) {
//     return nullptr;
//   }

//   ApplicationContents* opener = ApplicationContents::FromRenderFrameHost(
//       handle->GetApplicationContents()->GetOriginalOpener());
//   DevToolsWindow* window = GetInstanceForInspectedApplicationContents(opener);
//   if (!window || !window->open_new_window_for_popups_ ||
//       GetInstanceForInspectedApplicationContents(app_contents))
//     return nullptr;

//   DevToolsWindow::OpenDevToolsWindow(app_contents);
//   window = GetInstanceForInspectedApplicationContents(app_contents);
//   if (!window)
//     return nullptr;

//   return std::make_unique<Throttle>(handle, window);
// }

void DevToolsWindow::UpdateInspectedApplicationContents(
    ApplicationContents* new_app_contents,
    base::OnceCallback<void()> callback) {
  DCHECK(!reattach_complete_callback_);
  reattach_complete_callback_ = std::move(callback);

  inspected_contents_observer_ =
      std::make_unique<ObserverWithAccessor>(new_app_contents);
  // bindings_->AttachTo(
  //     content::DevToolsAgentHost::GetOrCreateFor(new_app_contents));
  // bindings_->CallClientMethod(
  //     "DevToolsAPI", "reattachMainTarget", {}, {}, {},
  //     base::BindOnce(&DevToolsWindow::OnReattachMainTargetComplete,
  //                    base::Unretained(this)));
}

void DevToolsWindow::ScheduleShow(const DevToolsToggleAction& action) {
  if (life_stage_ == kLoadCompleted) {
    Show(action);
    return;
  }

  // Action will be done only after load completed.
  action_on_load_ = action;

  if (!can_dock_) {
    // No harm to show always-undocked window right away.
    is_docked_ = false;
    Show(DevToolsToggleAction::Show());
  }
}

void DevToolsWindow::Show(const DevToolsToggleAction& action) {
  if (life_stage_ == kClosing)
    return;

  if (action.type() == DevToolsToggleAction::kNoOp)
    return;
  if (is_docked_) {
    DCHECK(can_dock_);
    Dock* inspected_dock = nullptr;
    int inspected_tab_index = -1;
    FindInspectedDockAndTabIndex(GetInspectedApplicationContents(),
                                    &inspected_dock,
                                    &inspected_tab_index);
    DCHECK(inspected_dock);
    DCHECK_NE(-1, inspected_tab_index);

    RegisterModalDialogManager(inspected_dock);

    // Tell inspected dock to update splitter and switch to inspected panel.
    DockWindow* inspected_window = inspected_dock->window();
    main_app_contents_->SetDelegate(this);

    TablistModel* tablist_model = inspected_dock->tablist_model();
    tablist_model->ActivateTabAt(inspected_tab_index, false);//,
                                 //  {TablistModel::GestureType::kOther});

    inspected_window->UpdateDevTools();
    main_app_contents_->SetInitialFocus();
    inspected_window->Show();
    // On Aura, focusing once is not enough. Do it again.
    // Note that focusing only here but not before isn't enough either. We just
    // need to focus twice.
    main_app_contents_->SetInitialFocus();

    DoAction(action);
    return;
  }

  // Avoid consecutive window switching if the devtools window has been opened
  // and the Inspect Element shortcut is pressed in the inspected tab.
  bool should_show_window =
      !dock_ || (action.type() != DevToolsToggleAction::kInspect);

  if (!dock_)
    CreateDevToolsDock();

  // Ignore action if dock does not exist and could not be created.
  if (!dock_)
    return;

  RegisterModalDialogManager(dock_);

  if (should_show_window) {
    dock_->window()->Show();
    main_app_contents_->SetInitialFocus();
  }
  if (toolbox_app_contents_)
    UpdateDockWindow();

  DoAction(action);
}

// static
bool DevToolsWindow::HandleBeforeUnload(ApplicationContents* frontend_contents,
    bool proceed, bool* proceed_to_fire_unload) {
  DevToolsWindow* window = AsDevToolsWindow(frontend_contents);
  if (!window)
    return false;
  if (!window->intercepted_page_beforeunload_)
    return false;
  window->BeforeUnloadFired(frontend_contents, proceed,
      proceed_to_fire_unload);
  return true;
}

// static
bool DevToolsWindow::InterceptPageBeforeUnload(ApplicationContents* contents) {
  DevToolsWindow* window =
      DevToolsWindow::GetInstanceForInspectedApplicationContents(contents);
  if (!window || window->intercepted_page_beforeunload_)
    return false;

  // Not yet loaded frontend will not handle beforeunload.
  if (window->life_stage_ != kLoadCompleted)
    return false;

  window->intercepted_page_beforeunload_ = true;
  // Handle case of devtools inspecting another devtools instance by passing
  // the call up to the inspecting devtools instance.
  // TODO(chrisha): Make devtools handle |auto_cancel=false| unload handler
  // dispatches; otherwise, discarding queries can cause unload dialogs to
  // pop-up for tabs with an attached devtools.
  if (!DevToolsWindow::InterceptPageBeforeUnload(window->main_app_contents_)) {
    window->main_app_contents_->DispatchBeforeUnload();//false /* auto_cancel */);
  }
  return true;
}

// static
bool DevToolsWindow::NeedsToInterceptBeforeUnload(
    ApplicationContents* contents) {
  DevToolsWindow* window =
      DevToolsWindow::GetInstanceForInspectedApplicationContents(contents);
  return window && !window->intercepted_page_beforeunload_ &&
         window->life_stage_ == kLoadCompleted;
}

// static
bool DevToolsWindow::HasFiredBeforeUnloadEventForDevToolsDock(
    Dock* dock) {
  //DCHECK(dock->is_type_devtools());
  // When FastUnloadController is used, devtools frontend will be detached
  // from the dock window at this point which means we've already fired
  // beforeunload.
  if (dock->tablist_model()->empty())
    return true;
  DevToolsWindow* window = AsDevToolsWindow(dock);
  if (!window)
    return false;
  return window->intercepted_page_beforeunload_;
}

// static
void DevToolsWindow::OnPageCloseCanceled(ApplicationContents* contents) {
  DevToolsWindow* window =
      DevToolsWindow::GetInstanceForInspectedApplicationContents(contents);
  if (!window)
    return;
  window->intercepted_page_beforeunload_ = false;
  // Propagate to devtools opened on devtools if any.
  DevToolsWindow::OnPageCloseCanceled(window->main_app_contents_);
}

DevToolsWindow::DevToolsWindow(FrontendType frontend_type,
                               scoped_refptr<Workspace> workspace,
                               Domain* domain,
                               //ApplicationContents* main_app_contents,
                               //DevToolsUIBindings* bindings,
                               ApplicationContents* inspected_app_contents,
                               bool can_dock)
    : frontend_type_(frontend_type),
      workspace_(workspace),
      domain_(domain),
      //main_app_contents_(main_app_contents),
      main_app_contents_(nullptr),
      toolbox_app_contents_(nullptr),
      //bindings_(bindings),
      dock_(nullptr),
      is_docked_(true),
      can_dock_(can_dock),
      close_on_detach_(true),
      // This initialization allows external front-end to work without changes.
      // We don't wait for docking call, but instead immediately show undocked.
      // Passing "dockSide=undocked" parameter ensures proper UI.
      life_stage_(can_dock ? kNotLoaded : kIsDockedSet),
      action_on_load_(DevToolsToggleAction::NoOp()),
      intercepted_page_beforeunload_(false),
      ready_for_test_(false) {
  // Set up delegate, so we get fully-functional window immediately.
  // It will not appear in UI though until |life_stage_ == kLoadCompleted|.
  //main_app_contents_->SetDelegate(this);
  domain_->AddObserver(this);
  // Bindings take ownership over devtools as its delegate.
  //bindings_->SetDelegate(this);
  // DevTools uses PageZoom::Zoom(), so main_app_contents_ requires a
  // ZoomController.
  
  g_devtools_window_instances.Get().push_back(this);

  // There is no inspected_app_contents in case of various workers.
  if (inspected_app_contents)
    inspected_contents_observer_.reset(
        new ObserverWithAccessor(inspected_app_contents));

  // Initialize docked page to be of the right size.
  if (can_dock_ && inspected_app_contents) {
    ApplicationWindowHostView* inspected_view =
        inspected_app_contents->GetApplicationWindowHost()->GetView();
    if (inspected_view) {
      main_app_contents_size_ = inspected_view->GetViewBounds().size();
      //main_app_contents_->GetApplicationWindowHost()->GetView()->SetSize(size);
    }
  }

  event_forwarder_.reset(new DevToolsEventForwarder(this));

  // Tag the DevTools main ApplicationContents with its TaskManager specific UserData
  // so that it shows up in the task manager.
  //task_manager::ApplicationContentsTags::CreateForDevToolsContents(main_app_contents_);

  std::vector<base::RepeatingCallback<void(DevToolsWindow*)>> copy(
      g_creation_callbacks.Get());

  LaunchOptions options;
  options.embedded_view = true;
  workspace_->application_controller()->LaunchApplication(GURL(domain_->name() + "://devtools"), options, base::Callback<void(int)>());
  
  for (const auto& callback : copy)
    callback.Run(this);
}

// static
// bool DevToolsWindow::AllowDevToolsFor(Workspace* workspace,
//                                       ApplicationContents* app_contents) {
//   // Don't allow DevTools UI in kiosk mode, because the DevTools UI would be
//   // broken there. See https://crbug.com/514551 for context.
//   if (base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kKioskMode))
//     return false;

//   return true;//ChromeDevToolsManagerDelegate::AllowInspection(workspace, app_contents);
// }

// static
DevToolsWindow* DevToolsWindow::Create(
    scoped_refptr<Workspace> workspace,
    ApplicationContents* inspected_app_contents,
    FrontendType frontend_type,
    const std::string& frontend_url,
    bool can_dock,
    const std::string& settings,
    const std::string& panel,
    bool has_other_clients) {

  if (inspected_app_contents) {
    // Check for a place to dock.
    Dock* dock = nullptr;
    int tab;
    if (!FindInspectedDockAndTabIndex(inspected_app_contents, &dock,
                                         &tab)) {// ||
        //!dock->is_type_normal()) {
      can_dock = false;
    }
  }
  
  //GURL app_url("world://new");
  Domain* world_domain = workspace->GetDomain("world");
  DCHECK(world_domain);

  // // Create ApplicationContents with devtools.
  // int id = workspace->generate_next_application_id();
  // base::UUID app_uuid = base::UUID::generate();
  // std::unique_ptr<Application> app = std::make_unique<Application>(world_domain, id, world_domain->name(), app_url, app_uuid);

  // //GURL url(GetDevToolsURL(workspace, frontend_type, frontend_url, can_dock, panel,
  // //                        has_other_clients));
  // ApplicationContents::CreateParams create_params;
  // create_params.workspace = workspace;
  // create_params.url = app_url;
  // create_params.parent = world_domain;
  // create_params.url_resolver = workspace->url_resolver();
  // create_params.application = app.get();
  // ApplicationContents* main_app_contents =
  //     ApplicationContents::Create(create_params);
  // //main_app_contents->LoadURL(
  //    DecorateFrontendURL(url), NavigateParams(workspace, url, ui::PAGE_TRANSITION_AUTO_TOPLEVEL));
  //DevToolsUIBindings* bindings =
  //    DevToolsUIBindings::ForApplicationContents(main_app_contents.get());

  //if (!bindings)
  //  return nullptr;
  DevToolsWindow* window = new DevToolsWindow(
                            frontend_type, 
                            workspace,
                            world_domain,
                           // main_app_contents, 
                            //bindings,
                            inspected_app_contents, 
                            can_dock);
  return window;
}

// static
GURL DevToolsWindow::GetDevToolsURL(scoped_refptr<Workspace> workspace,
                                    FrontendType frontend_type,
                                    const std::string& frontend_url,
                                    bool can_dock,
                                    const std::string& panel,
                                    bool has_other_clients) {
  std::string url;

  std::string remote_base;// =
      //"?remoteBase=" + DevToolsUI::GetRemoteBaseURL().spec();

  const std::string valid_frontend = frontend_url;
      //frontend_url.empty() ? chrome::kChromeUIDevToolsURL : frontend_url;

  // remoteFrontend is here for backwards compatibility only.
  std::string remote_frontend =
      valid_frontend + ((valid_frontend.find("?") == std::string::npos)
                            ? "?remoteFrontend=true"
                            : "&remoteFrontend=true");
  switch (frontend_type) {
    case kFrontendDefault:
      url = kDefaultFrontendURL + remote_base;
      if (can_dock)
        url += "&can_dock=true";
      if (!panel.empty())
        url += "&panel=" + panel;
      break;
    case kFrontendWorker:
      url = kWorkerFrontendURL + remote_base;
      break;
    case kFrontendV8:
      url = kJSFrontendURL + remote_base;
      break;
    case kFrontendRemote:
      url = remote_frontend;
      break;
    case kFrontendRemoteWorker:
      // isSharedWorker is here for backwards compatibility only.
      url = remote_frontend + "&isSharedWorker=true";
      break;
  }

  if (has_other_clients)
    url += "&hasOtherClients=true";
  return GURL(url);//DevToolsUIBindings::SanitizeFrontendURL(GURL(url));
}

// static
// DevToolsWindow* DevToolsWindow::FindDevToolsWindow(
//     DevToolsAgentHost* agent_host) {
//   if (!agent_host || !g_devtools_window_instances.IsCreated())
//     return nullptr;
//   DevToolsWindows* instances = g_devtools_window_instances.Pointer();
//   for (auto it(instances->begin()); it != instances->end(); ++it) {
//     if ((*it)->bindings_->IsAttachedTo(agent_host))
//       return *it;
//   }
//   return nullptr;
// }

// static
DevToolsWindow* DevToolsWindow::AsDevToolsWindow(
    ApplicationContents* app_contents) {
  if (!app_contents || !g_devtools_window_instances.IsCreated())
    return nullptr;
  DevToolsWindows* instances = g_devtools_window_instances.Pointer();
  for (auto it(instances->begin()); it != instances->end(); ++it) {
    if ((*it)->main_app_contents_ == app_contents)
      return *it;
  }
  return nullptr;
}

// static
DevToolsWindow* DevToolsWindow::AsDevToolsWindow(Dock* dock) {
  //DCHECK(dock->is_type_devtools());
  if (dock->tablist_model()->empty())
    return nullptr;
  ApplicationContents* contents = dock->tablist_model()->GetApplicationContentsAt(0);
  return AsDevToolsWindow(contents);
}

ApplicationContents* DevToolsWindow::OpenURLFromTab(
    ApplicationContents* source,
    const GURL& url) {
  DCHECK(source == main_app_contents_);
  // if (!params.url.SchemeIs(content::kChromeDevToolsScheme)) {
  //   return OpenURLFromInspectedTab(params);
  // }
 // main_app_contents_->Reload(false);
  //main_app_contents_->Reload(ReloadType::NORMAL, false);
  main_app_contents_->OpenURL(url);
  return main_app_contents_;
}

ApplicationContents* DevToolsWindow::OpenURLFromInspectedTab(const GURL& url) {
  ApplicationContents* inspected_app_contents = GetInspectedApplicationContents();
  if (!inspected_app_contents)
    return nullptr;
  //modified.referrer = common::Referrer();
  return inspected_app_contents->OpenURL(url);
}

void DevToolsWindow::ActivateContents(ApplicationContents* contents) {
  if (is_docked_) {
    ApplicationContents* inspected_tab = GetInspectedApplicationContents();
    if (inspected_tab)
      inspected_tab->GetDelegate()->ActivateContents(inspected_tab);
  } else if (dock_) {
    dock_->window()->Activate();
  }
}

void DevToolsWindow::AddNewContents(const std::string& app_name,
                      ApplicationContents* source,
                      ApplicationContents* new_contents,
                      WindowOpenDisposition disposition,
                      const gfx::Rect& initial_rect,
                      bool user_gesture,
                      bool* was_blocked) {
  if (new_contents == toolbox_app_contents_) {
    owned_toolbox_app_contents_.reset(new_contents);

    toolbox_app_contents_->SetDelegate(
        new DevToolsToolboxDelegate(toolbox_app_contents_,
                                    inspected_contents_observer_.get()));
    if (main_app_contents_->GetApplicationWindowHost() &&
        toolbox_app_contents_->GetApplicationWindowHost()) {
      gfx::Size size =
          main_app_contents_->GetApplicationWindowHost()->GetView()->GetViewBounds().size();
      toolbox_app_contents_->GetApplicationWindowHost()->GetView()->SetSize(size);
    }
    UpdateDockWindow();
    return;
  }

  ApplicationContents* inspected_app_contents = GetInspectedApplicationContents();
  if (inspected_app_contents) {
    inspected_app_contents->GetDelegate()->AddNewContents(
        app_name,
        source, 
        new_contents, 
        //target_url, 
        disposition, 
        initial_rect,
        user_gesture, 
        was_blocked);
  }
}

void DevToolsWindow::ApplicationContentsCreated(ApplicationContents* source_contents,
                                        int opener_render_process_id,
                                        int opener_render_frame_id,
                                        const std::string& frame_name,
                                        const GURL& target_url,
                                        ApplicationContents* new_contents) {
  // if (target_url.SchemeIs(content::kChromeDevToolsScheme) &&
  //     target_url.path().rfind("toolbox.html") != std::string::npos) {
  //   CHECK(can_dock_);

  //   // Ownership will be passed in DevToolsWindow::AddNewContents.
  //   if (owned_toolbox_app_contents_)
  //     owned_toolbox_app_contents_.reset();
  //   toolbox_app_contents_ = new_contents;

  //   // Tag the DevTools toolbox ApplicationContents with its TaskManager specific
  //   // UserData so that it shows up in the task manager.
  //   task_manager::ApplicationContentsTags::CreateForDevToolsContents(
  //       toolbox_app_contents_);

  //   // The toolbox holds a placeholder for the inspected ApplicationContents. When the
  //   // placeholder is resized, a frame is requested. The inspected ApplicationContents
  //   // is resized when the frame is rendered. Force rendering of the toolbox at
  //   // all times, to make sure that a frame can be rendered even when the
  //   // inspected ApplicationContents fully covers the toolbox. https://crbug.com/828307
  //   toolbox_app_contents_->IncrementCapturerCount(gfx::Size(),
  //                                                 /* stay_hidden */ false);
  // }
}

void DevToolsWindow::CloseContents(ApplicationContents* source) {
  CHECK(is_docked_);
  life_stage_ = kClosing;
  UpdateDockWindow();
  // In case of docked main_app_contents_, we own it so delete here.
  // Embedding DevTools window will be deleted as a result of
  // DevToolsUIBindings destruction.
  CHECK(owned_main_app_contents_);
  owned_main_app_contents_.reset();
}

void DevToolsWindow::ContentsZoomChange(bool zoom_in) {
  DCHECK(is_docked_);
  zoom::PageZoom::Zoom(main_app_contents_, zoom_in ? common::PAGE_ZOOM_IN
                                                   : common::PAGE_ZOOM_OUT);
}

void DevToolsWindow::BeforeUnloadFired(ApplicationContents* tab,
                                       bool proceed,
                                       bool* proceed_to_fire_unload) {
  if (!intercepted_page_beforeunload_) {
    // Docked devtools window closed directly.
    //if (proceed)
    //  bindings_->Detach();
    *proceed_to_fire_unload = proceed;
  } else {
    // Inspected page is attempting to close.
    ApplicationContents* inspected_app_contents = GetInspectedApplicationContents();
    if (proceed) {
      inspected_app_contents->DispatchBeforeUnload();
    } else {
      bool should_proceed;
      inspected_app_contents->GetDelegate()->BeforeUnloadFired(
          inspected_app_contents, false, &should_proceed);
      DCHECK(!should_proceed);
    }
    *proceed_to_fire_unload = false;
  }
}

KeyboardEventProcessingResult DevToolsWindow::PreHandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  DockWindow* inspected_window = GetInspectedDockWindow();
  if (inspected_window) {
    return inspected_window->PreHandleKeyboardEvent(event);
  }
  return KeyboardEventProcessingResult::NOT_HANDLED;
}

void DevToolsWindow::HandleKeyboardEvent(
    ApplicationContents* source,
    const NativeWebKeyboardEvent& event) {
  if (event.windows_key_code == 0x08) {
    // Do not navigate back in history on Windows (http://crbug.com/74156).
    return;
  }
  DockWindow* inspected_window = GetInspectedDockWindow();
  if (inspected_window) {
    inspected_window->HandleKeyboardEvent(event);
  }
}

bool DevToolsWindow::PreHandleGestureEvent(
    ApplicationContents* source,
    const blink::WebGestureEvent& event) {
  // Disable pinch zooming.
  return blink::WebInputEvent::IsPinchGestureEventType(event.GetType());
}

void DevToolsWindow::ActivateWindow() {
  if (life_stage_ != kLoadCompleted)
    return;
  if (is_docked_ && GetInspectedDockWindow())
    main_app_contents_->Focus();
  else if (!is_docked_ && !dock_->window()->IsActive())
    dock_->window()->Activate();
}

void DevToolsWindow::CloseWindow() {
  DCHECK(is_docked_);
  life_stage_ = kClosing;
  main_app_contents_->DispatchBeforeUnload();
}

// void DevToolsWindow::Inspect(scoped_refptr<content::DevToolsAgentHost> host) {
//   DevToolsWindow::OpenDevToolsWindow(host, workspace_);
// }

void DevToolsWindow::SetInspectedPageBounds(const gfx::Rect& rect) {
  DevToolsContentsResizingStrategy strategy(rect);
  if (contents_resizing_strategy_.Equals(strategy))
    return;

  contents_resizing_strategy_.CopyFrom(strategy);
  UpdateDockWindow();
}

void DevToolsWindow::InspectElementCompleted() {
  if (!inspect_element_start_time_.is_null()) {
    UMA_HISTOGRAM_TIMES("DevTools.InspectElement",
        base::TimeTicks::Now() - inspect_element_start_time_);
    inspect_element_start_time_ = base::TimeTicks();
  }
}

void DevToolsWindow::SetIsDocked(bool dock_requested) {
  if (life_stage_ == kClosing)
    return;

  DCHECK(can_dock_ || !dock_requested);
  if (!can_dock_)
    dock_requested = false;

  bool was_docked = is_docked_;
  is_docked_ = dock_requested;

  if (life_stage_ != kLoadCompleted) {
    // This is a first time call we waited for to initialize.
    life_stage_ = life_stage_ == kOnLoadFired ? kLoadCompleted : kIsDockedSet;
    if (life_stage_ == kLoadCompleted)
      LoadCompleted();
    return;
  }

  if (dock_requested == was_docked)
    return;

  if (dock_requested && !was_docked) {
    // Detach window from the external devtools dock. It will lead to
    // the dock object's close and delete. Remove observer first.
    TablistModel* tablist_model = dock_->tablist_model();
    DCHECK(!owned_main_app_contents_);

    // Removing the only ApplicationContents from the tab strip of dock_ will
    // eventually lead to the destruction of dock_ as well, which is why it's
    // okay to just null the raw pointer here.
    dock_ = nullptr;

    owned_main_app_contents_ = std::make_unique<OwnedMainApplicationContents>(
        tablist_model->DetachApplicationContentsAt(
            tablist_model->GetIndexOfApplicationContents(main_app_contents_)));
  } else if (!dock_requested && was_docked) {
    UpdateDockWindow();
  }

  Show(DevToolsToggleAction::Show());
}

void DevToolsWindow::OpenInNewTab(const std::string& url) {
  GURL fixed_url(url);
  ApplicationContents* inspected_app_contents = GetInspectedApplicationContents();
  int child_id = common::ChildProcessHost::kInvalidUniqueID;
  if (inspected_app_contents) {
    ApplicationWindowHost* render_view_host =
        inspected_app_contents->GetApplicationWindowHost();
    if (render_view_host)
      child_id = render_view_host->GetProcess()->GetID();
  }
  // Use about:blank instead of an empty GURL. The dock treats an empty GURL
  // as navigating to the home page, which may be privileged (chrome://newtab/).
  // if (!content::ChildProcessSecurityPolicy::GetInstance()->CanRequestURL(
  //         child_id, fixed_url))
  //   fixed_url = GURL(url::kAboutBlankURL);

  // OpenURLParams params(fixed_url, common::Referrer(),
  //                               WindowOpenDisposition::NEW_FOREGROUND_TAB,
  //                               ui::PAGE_TRANSITION_LINK, false);
  GURL open_url(url);
  // if (!inspected_app_contents || !inspected_app_contents->OpenURL(params)) {
  //   chrome::ScopedTabbedDockDisplayer displayer(workspace_);
  //   chrome::AddSelectedTabWithURL(displayer.dock(), fixed_url,
  //                                 ui::PAGE_TRANSITION_LINK);
  // }
  if (inspected_app_contents) {
    inspected_app_contents->OpenURL(open_url);
  } else {
    ScopedTabbedDockDisplayer displayer(workspace_);
    AddSelectedTabWithURL(displayer.dock(), fixed_url, ui::PAGE_TRANSITION_LINK);
  }
}

// void DevToolsWindow::SetWhitelistedShortcuts(
//     const std::string& message) {
//   event_forwarder_->SetWhitelistedShortcuts(message);
// }

// void DevToolsWindow::SetEyeDropperActive(bool active) {
//   ApplicationContents* app_contents = GetInspectedApplicationContents();
//   if (!app_contents)
//     return;
//   if (active) {
//     eye_dropper_ = std::make_unique<DevToolsEyeDropper>(
//         app_contents,
//         base::BindRepeating(&DevToolsWindow::ColorPickedInEyeDropper,
//                             base::Unretained(this)));
//   } else {
//     eye_dropper_.reset();
//   }
// }

// void DevToolsWindow::ColorPickedInEyeDropper(int r, int g, int b, int a) {
//   base::DictionaryValue color;
//   color.SetInteger("r", r);
//   color.SetInteger("g", g);
//   color.SetInteger("b", b);
//   color.SetInteger("a", a);
//   bindings_->CallClientMethod("DevToolsAPI", "eyeDropperPickedColor",
//                               std::move(color));
// }

void DevToolsWindow::InspectedContentsClosing() {
  if (!close_on_detach_)
    return;
  intercepted_page_beforeunload_ = false;
  life_stage_ = kClosing;
  main_app_contents_->ClosePage();
}

// InfoBarService* DevToolsWindow::GetInfoBarService() {
//   return is_docked_ ?
//       InfoBarService::FromApplicationContents(GetInspectedApplicationContents()) :
//       InfoBarService::FromApplicationContents(main_app_contents_);
// }

void DevToolsWindow::ApplicationProcessGone(bool crashed) {
  // Docked DevToolsWindow owns its main_app_contents_ and must delete it.
  // Undocked main_app_contents_ are owned and handled by dock.
  // see crbug.com/369932
  if (is_docked_) {
    CloseContents(main_app_contents_);
  } else if (dock_ && crashed) {
    dock_->window()->Close();
  }
}

void DevToolsWindow::OnLoadCompleted() {
  // First seed inspected tab id for extension APIs.
  // ApplicationContents* inspected_app_contents = GetInspectedApplicationContents();
  // if (inspected_app_contents) {
  //   sessions::SessionTabHelper* session_tab_helper =
  //       sessions::SessionTabHelper::FromApplicationContents(inspected_app_contents);
  //   if (session_tab_helper) {
  //     bindings_->CallClientMethod(
  //         "DevToolsAPI", "setInspectedTabId",
  //         base::Value(session_tab_helper->session_id().id()));
  //   }
  // }

  if (life_stage_ == kClosing)
    return;

  // We could be in kLoadCompleted state already if frontend reloads itself.
  if (life_stage_ != kLoadCompleted) {
    // Load is completed when both kIsDockedSet and kOnLoadFired happened.
    // Here we set kOnLoadFired.
    life_stage_ = life_stage_ == kIsDockedSet ? kLoadCompleted : kOnLoadFired;
  }
  if (life_stage_ == kLoadCompleted)
    LoadCompleted();
}


void DevToolsWindow::ConnectionReady() {
  // if (throttle_)
  //   throttle_->ResumeThrottle();
}

void DevToolsWindow::SetOpenNewWindowForPopups(bool value) {
  open_new_window_for_popups_ = value;
}

void DevToolsWindow::CreateDevToolsDock() {
  // PrefService* prefs = workspace_->GetPrefs();
  // if (!prefs->GetDictionary(prefs::kAppWindowPlacement)->HasKey(kDevToolsApp)) {
  //   // Ensure there is always a default size so that
  //   // DockFrame::InitDockFrame can retrieve it later.
  //   DictionaryPrefUpdate update(prefs, prefs::kAppWindowPlacement);
  //   base::Value* wp_prefs = update.Get();
  //   base::Value dev_tools_defaults(base::Value::Type::DICTIONARY);
  //   dev_tools_defaults.SetIntKey("left", 100);
  //   dev_tools_defaults.SetIntKey("top", 100);
  //   dev_tools_defaults.SetIntKey("right", 740);
  //   dev_tools_defaults.SetIntKey("bottom", 740);
  //   dev_tools_defaults.SetBoolKey("maximized", false);
  //   dev_tools_defaults.SetBoolKey("always_on_top", false);
  //   wp_prefs->SetKey(kDevToolsApp, std::move(dev_tools_defaults));
  // }

  // if (Dock::GetCreationStatusForWorkspace(workspace_) !=
  //     Dock::CreationStatus::kOk) {
  //   return;
  // }
  dock_ =
      Dock::GetOrCreate(GURL("world://devtools"), Dock::CreateParams(workspace_, GURL("world://devtools"), false));
      //Dock::GetOrCreate(Dock::CreateParams::CreateForDevTools(workspace_));
  // dock_->tablist_model()->AddApplicationContents(
  //     OwnedMainApplicationContents::TakeApplicationContents(
  //         std::move(owned_main_app_contents_)),
  //     -1, ui::PAGE_TRANSITION_AUTO_TOPLEVEL, TablistModel::ADD_ACTIVE);
}

DockWindow* DevToolsWindow::GetInspectedDockWindow() {
  Dock* dock = nullptr;
  int tab;
  return FindInspectedDockAndTabIndex(GetInspectedApplicationContents(), &dock,
                                         &tab)
             ? dock->window()
             : nullptr;
}

void DevToolsWindow::DoAction(const DevToolsToggleAction& action) {
  switch (action.type()) {
    case DevToolsToggleAction::kInspect:
      //bindings_->CallClientMethod("DevToolsAPI", "enterInspectElementMode");
      break;

    case DevToolsToggleAction::kShowElementsPanel:
    case DevToolsToggleAction::kPauseInDebugger:
    case DevToolsToggleAction::kShowConsolePanel:
    case DevToolsToggleAction::kShow:
    case DevToolsToggleAction::kToggle:
      // Do nothing.
      break;

    case DevToolsToggleAction::kReveal: {
      const DevToolsToggleAction::RevealParams* params =
          action.params();
      CHECK(params);
      // bindings_->CallClientMethod(
      //     "DevToolsAPI", "revealSourceLine", base::Value(params->url),
      //     base::Value(static_cast<int>(params->line_number)),
      //     base::Value(static_cast<int>(params->column_number)));
      break;
    }
    default:
      NOTREACHED();
      break;
  }
}

void DevToolsWindow::UpdateDockToolbar() {
  // DockWindow* inspected_window = GetInspectedDockWindow();
  // if (inspected_window)
  //   inspected_window->UpdateToolbar(nullptr);
}

void DevToolsWindow::UpdateDockWindow() {
  DockWindow* inspected_window = GetInspectedDockWindow();
  if (inspected_window)
    inspected_window->UpdateDevTools();
}

ApplicationContents* DevToolsWindow::GetInspectedApplicationContents() {
  return inspected_contents_observer_
             ? inspected_contents_observer_->application_contents()
             : nullptr;
}

void DevToolsWindow::LoadCompleted() {
  Show(action_on_load_);
  action_on_load_ = DevToolsToggleAction::NoOp();
  if (!load_completed_callback_.is_null()) {
    std::move(load_completed_callback_).Run();
  }
}

void DevToolsWindow::SetLoadCompletedCallback(base::OnceClosure closure) {
  if (life_stage_ == kLoadCompleted || life_stage_ == kClosing) {
    if (!closure.is_null())
      std::move(closure).Run();
    return;
  }
  load_completed_callback_ = std::move(closure);
}

bool DevToolsWindow::ForwardKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  return event_forwarder_->ForwardEvent(event);
}

bool DevToolsWindow::ReloadInspectedApplicationContents(bool bypass_cache) {
  // Only route reload via front-end if the agent is attached.
  ApplicationContents* wc = GetInspectedApplicationContents();
  if (!wc || wc->GetCrashedStatus() != base::TERMINATION_STATUS_STILL_RUNNING)
    return false;
  // bindings_->CallClientMethod("DevToolsAPI", "reloadInspectedPage",
  //                             base::Value(bypass_cache));
  return true;
}

void DevToolsWindow::RegisterModalDialogManager(Dock* dock) {
  // web_modal::ApplicationContentsModalDialogManager::CreateForApplicationContents(
  //     main_app_contents_);
  // web_modal::ApplicationContentsModalDialogManager::FromApplicationContents(main_app_contents_)
  //     ->SetDelegate(dock);
}

void DevToolsWindow::OnReattachMainTargetComplete(base::Value) {
  std::move(reattach_complete_callback_).Run();
}

void DevToolsWindow::OnApplicationLaunched(Domain* domain, Application* application) {
  
}

void DevToolsWindow::OnApplicationInitialized(Domain* domain, Application* application) {
  main_app_contents_ = application->contents();
  DCHECK(main_app_contents_);
  owned_main_app_contents_ = 
          std::make_unique<OwnedMainApplicationContents>(main_app_contents_);
  main_app_contents_->SetDelegate(this);
  main_app_contents_->GetApplicationWindowHost()->GetView()->SetSize(main_app_contents_size_);
  zoom::ZoomController::CreateForApplicationContents(main_app_contents_);
  zoom::ZoomController::FromApplicationContents(main_app_contents_)
      ->SetShowsNotificationBubble(false);
  if (!contents_complete_callback_.is_null()) {
    DevToolsContentsResizingStrategy strategy;
    strategy.CopyFrom(contents_resizing_strategy_);
    std::move(contents_complete_callback_).Run(main_app_contents_, std::move(strategy), true);
  }
}

void DevToolsWindow::OnApplicationShutdown(Domain* domain, Application* application) {

}

}