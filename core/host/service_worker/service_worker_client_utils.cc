// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_client_utils.h"

#include <algorithm>
#include <tuple>

#include "base/location.h"
#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
//#include "core/host/frame_host/frame_tree_node.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_provider_host.h"
#include "core/host/service_worker/service_worker_version.h"
#include "core/host/service_worker/origin_utils.h"
//#include "core/host/storage_partition_impl.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
//#include "core/host/navigation_handle.h"
//#include "core/host/page_navigator.h"
//#include "core/host/payment_app_provider.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
//#include "core/host/web_contents.h"
#include "core/shared/common/child_process_host.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "third_party/blink/public/mojom/page/page_visibility_state.mojom.h"
#include "ui/base/mojo/window_open_disposition.mojom.h"
#include "url/gurl.h"

namespace host {
namespace service_worker_client_utils {

namespace {

using OpenURLCallback = base::OnceCallback<void(int, int)>;

// The OpenURLObserver class is a ApplicationContentsObserver that will wait for a
// ApplicationContents to be initialized, run the |callback| passed to its constructor
// then self destroy.
// The callback will receive the process and frame ids. If something went wrong
// those will be (kInvalidUniqueID, MSG_ROUTING_NONE).
// The callback will be called in the IO thread.
class OpenURLObserver : public ApplicationContentsObserver {
 public:
  OpenURLObserver(ApplicationContents* web_contents,
                  //int frame_tree_node_id,
                  OpenURLCallback callback)
      : ApplicationContentsObserver(web_contents),
        //frame_tree_node_id_(frame_tree_node_id),
        callback_(std::move(callback)) {}

  void DidFinishNavigation() override {
    // DCHECK(web_contents());
    // if (!navigation_handle->HasCommitted()) {
    //   // Return error.
    //   RunCallback(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE);
    //   return;
    // }

    // // if (navigation_handle->GetFrameTreeNodeId() != frame_tree_node_id_) {
    // //   // Return error.
    // //   RunCallback(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE);
    // //   return;
    // // }

    // RenderFrameHost* render_frame_host =
    //     navigation_handle->GetRenderFrameHost();
    // RunCallback(render_frame_host->GetProcess()->GetID(),
    //             render_frame_host->GetRoutingID());
    RunCallback(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE);
  }

  void ApplicationProcessGone(base::TerminationStatus status) override {
    RunCallback(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE);
  }

  void ApplicationContentsDestroyed() override {
    RunCallback(common::ChildProcessHost::kInvalidUniqueID, MSG_ROUTING_NONE);
  }

 private:
  void RunCallback(int render_process_id, int render_frame_id) {
    // After running the callback, |this| will stop observing, thus
    // web_contents() should return nullptr and |RunCallback| should no longer
    // be called. Then, |this| will self destroy.
    DCHECK(application_contents());
    DCHECK(callback_);

    HostThread::PostTask(HostThread::IO, FROM_HERE,
                            base::BindOnce(std::move(callback_),
                                           render_process_id, render_frame_id));
    Observe(nullptr);
    base::ThreadTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, this);
  }

  //int frame_tree_node_id_;
  OpenURLCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(OpenURLObserver);
};

blink::mojom::ServiceWorkerClientInfoPtr GetWindowClientInfoOnUI(
    int render_process_id,
    int render_frame_id,
    base::TimeTicks create_time,
    const std::string& client_uuid) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationWindowHost* render_frame_host =
      ApplicationWindowHost::FromID(render_process_id, render_frame_id);
  if (!render_frame_host) {
    return nullptr;
  }

  // TODO(mlamouri,michaeln): it is possible to end up collecting information
  // for a frame that is actually being navigated and isn't exactly what we are
  // expecting.

 blink::mojom::PageVisibilityState visibility_state =
      render_frame_host->is_hidden()
          ? blink::mojom::PageVisibilityState::kHidden
          : blink::mojom::PageVisibilityState::kVisible;

  return blink::mojom::ServiceWorkerClientInfo::New(
      render_frame_host->GetLastCommittedURL(), client_uuid,
      blink::mojom::ServiceWorkerClientType::kWindow,
      //render_frame_host->GetVisibilityState(), 
      visibility_state,
      render_frame_host->is_focused(),
      network::mojom::RequestContextFrameType::kTopLevel,
      // render_frame_host->GetParent()
      //     ? network::mojom::RequestContextFrameType::kNested
      //     : network::mojom::RequestContextFrameType::kTopLevel,
      //render_frame_host->frame_tree_node()->last_focus_time(), 
      //render_frame_host->last_focus_time(), 
      create_time,
      create_time);
}

blink::mojom::ServiceWorkerClientInfoPtr FocusOnUI(
    int render_process_id,
    int render_frame_id,
    base::TimeTicks create_time,
    const std::string& client_uuid) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationWindowHost* render_frame_host =
      ApplicationWindowHost::FromID(render_process_id, render_frame_id);
  ApplicationContents* web_contents = ApplicationContents::FromApplicationWindowHost(render_frame_host);

  if (!render_frame_host || !web_contents)
    return nullptr;

  // FrameTreeNode* frame_tree_node = render_frame_host->frame_tree_node();

  // // Focus the frame in the frame tree node, in case it has changed.
  // frame_tree_node->frame_tree()->SetFocusedFrame(
  //     frame_tree_node, render_frame_host->GetSiteInstance());
  render_frame_host->SetFocusedFrame();

  // Focus the frame's view to make sure the frame is now considered as focused.
  render_frame_host->GetView()->Focus();

  // Move the web contents to the foreground.
  web_contents->Activate();

  return GetWindowClientInfoOnUI(render_process_id, render_frame_id,
                                 create_time, client_uuid);
}

// This is only called for main frame navigations in OpenWindowOnUI().
// void DidOpenURLOnUI(WindowType type,
//                     OpenURLCallback callback,
//                     ApplicationContents* web_contents) {
//   DCHECK_CURRENTLY_ON(HostThread::UI);

  // if (!web_contents) {
  //   HostThread::PostTask(
  //       HostThread::IO, FROM_HERE,
  //       base::BindOnce(std::move(callback), common::ChildProcessHost::kInvalidUniqueID,
  //                      MSG_ROUTING_NONE));
  //   return;
  // }

  // // ContentBrowserClient::OpenURL calls ui::BaseWindow::Show which
  // // makes the destination window the main+key window, but won't make Chrome
  // // the active application (https://crbug.com/470830). Since OpenWindow is
  // // always called from a user gesture (e.g. notification click), we should
  // // explicitly activate the window, which brings Chrome to the front.
  // static_cast<ApplicationContents*>(web_contents)->Activate();

  // ApplicationWindowHost* rfhi = web_contents->GetWindow();//web_contents->GetMainWindow();
  // new OpenURLObserver(web_contents,
  //                    // rfhi->frame_tree_node()->frame_tree_node_id(),
  //                     std::move(callback));

  //if (type == WindowType::PAYMENT_HANDLER_WINDOW) {
    // Set the opened web_contents to payment app provider to manage its life
    // cycle.
    //PaymentAppProvider::GetInstance()->SetOpenedWindow(web_contents);
  //}
//}

void OpenWindowOnUI(
    const GURL& url,
    const GURL& script_url,
    int worker_process_id,
    const scoped_refptr<ServiceWorkerContextWrapper>& context_wrapper,
    WindowType type,
    OpenURLCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // // BrowserContext* browser_context =
  // //     context_wrapper->storage_partition()
  // //         ? context_wrapper->storage_partition()->browser_context()
  // //         : nullptr;
  // // // We are shutting down.
  // // if (!browser_context)
  // //   return;

  // ApplicationProcessHost* render_process_host =
  //     ApplicationProcessHost::FromID(worker_process_id);
  // // if (render_process_host->IsForGuestsOnly()) {
  // //   HostThread::PostTask(
  // //       HostThread::IO, FROM_HERE,
  // //       base::BindOnce(std::move(callback), common::ChildProcessHost::kInvalidUniqueID,
  // //                      MSG_ROUTING_NONE));
  // //   return;
  // // }

  // OpenURLParams params(
  //     url,
  //     common::Referrer::SanitizeForRequest(
  //         url, common::Referrer(script_url, blink::kWebReferrerPolicyDefault)),
  //     type == WindowType::PAYMENT_HANDLER_WINDOW
  //         ? WindowOpenDisposition::NEW_POPUP
  //         : WindowOpenDisposition::NEW_FOREGROUND_TAB,
  //     ui::PAGE_TRANSITION_AUTO_TOPLEVEL, true /* is_renderer_initiated */);
  // params.open_app_window_if_possible = type == WindowType::NEW_TAB_WINDOW;

  // //GetClient()->host()->OpenURL(
  //     //browser_context,
  // Domain* domain = context_wrapper->domain();
  // domain->OpenURL(
  //     params,
  //     base::AdaptCallbackForRepeating(
  //         base::BindOnce(&DidOpenURLOnUI, type, std::move(callback))));
}

void NavigateClientOnUI(const GURL& url,
                        const GURL& script_url,
                        int process_id,
                        int frame_id,
                        OpenURLCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // ApplicationWindowHost* rfhi = ApplicationWindowHost::FromID(process_id, frame_id);
  // ApplicationContents* web_contents = ApplicationContents::FromApplicationWindowHost(rfhi);//RenderFrameHost(rfhi);

  // if (!rfhi || !web_contents) {
  //   HostThread::PostTask(
  //       HostThread::IO, FROM_HERE,
  //       base::BindOnce(std::move(callback), common::ChildProcessHost::kInvalidUniqueID,
  //                      MSG_ROUTING_NONE));
  //   return;
  // }

  // ui::PageTransition transition = ui::PAGE_TRANSITION_AUTO_TOPLEVEL;// rfhi->GetParent()
  //                                  //   ? ui::PAGE_TRANSITION_AUTO_SUBFRAME
  //                                  //   : ui::PAGE_TRANSITION_AUTO_TOPLEVEL;
  // //int frame_tree_node_id = rfhi->frame_tree_node()->frame_tree_node_id();

  // OpenURLParams params(
  //     url,
  //     common::Referrer::SanitizeForRequest(
  //         url, common::Referrer(script_url, blink::kWebReferrerPolicyDefault)),
  //     //frame_tree_node_id, 
  //     WindowOpenDisposition::CURRENT_TAB, 
  //     transition,
  //     true /* is_renderer_initiated */);
  // web_contents->OpenURL(params);
  // new OpenURLObserver(
  //   web_contents, 
  //   //frame_tree_node_id, 
  //   std::move(callback));
}

void AddWindowClient(
    ServiceWorkerProviderHost* host,
    std::vector<std::tuple<int, int, base::TimeTicks, std::string>>*
        client_info) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (host->client_type() != blink::mojom::ServiceWorkerClientType::kWindow)
    return;
  client_info->push_back(std::make_tuple(host->process_id(), host->frame_id(),
                                         host->create_time(),
                                         host->client_uuid()));
}

void AddNonWindowClient(
    const ServiceWorkerProviderHost* host,
    blink::mojom::ServiceWorkerClientQueryOptionsPtr options,
    ServiceWorkerClientPtrs* out_clients) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  blink::mojom::ServiceWorkerClientType host_client_type = host->client_type();
  if (host_client_type == blink::mojom::ServiceWorkerClientType::kWindow)
    return;
  if (options->client_type != blink::mojom::ServiceWorkerClientType::kAll &&
      options->client_type != host_client_type)
    return;

  auto client_info = blink::mojom::ServiceWorkerClientInfo::New(
      host->document_url(), host->client_uuid(), host_client_type,
      blink::mojom::PageVisibilityState::kHidden,
      false,  // is_focused
      network::mojom::RequestContextFrameType::kNone, base::TimeTicks(),
      host->create_time());
  out_clients->push_back(std::move(client_info));
}

void OnGetWindowClientsOnUI(
    // The tuple contains process_id, frame_id, create_time, client_uuid.
    const std::vector<std::tuple<int, int, base::TimeTicks, std::string>>&
        clients_info,
    const GURL& script_url,
    ClientsCallback callback,
    std::unique_ptr<ServiceWorkerClientPtrs> out_clients) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  for (const auto& it : clients_info) {
    blink::mojom::ServiceWorkerClientInfoPtr info = GetWindowClientInfoOnUI(
        std::get<0>(it), std::get<1>(it), std::get<2>(it), std::get<3>(it));

    // If the request to the provider_host returned a null
    // ServiceWorkerClientInfo, that means that it wasn't possible to associate
    // it with a valid RenderFrameHost. It might be because the frame was killed
    // or navigated in between.
    if (!info)
      continue;
    DCHECK(!info->client_uuid.empty());

    // We can get info for a frame that was navigating end ended up with a
    // different URL than expected. In such case, we should make sure to not
    // expose cross-origin WindowClient.
    if (GetOrigin(info->url) != GetOrigin(script_url))
      continue;

    out_clients->push_back(std::move(info));
  }

  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(std::move(callback), std::move(out_clients)));
}

struct ServiceWorkerClientInfoSort {
  bool operator()(const blink::mojom::ServiceWorkerClientInfoPtr& a,
                  const blink::mojom::ServiceWorkerClientInfoPtr& b) const {
    // Clients for windows should be appeared earlier.
    if (a->client_type == blink::mojom::ServiceWorkerClientType::kWindow &&
        b->client_type != blink::mojom::ServiceWorkerClientType::kWindow) {
      return true;
    }
    if (a->client_type != blink::mojom::ServiceWorkerClientType::kWindow &&
        b->client_type == blink::mojom::ServiceWorkerClientType::kWindow) {
      return false;
    }

    // Clients focused recently should be appeared earlier.
    if (a->last_focus_time != b->last_focus_time)
      return a->last_focus_time > b->last_focus_time;

    // Clients created before should be appeared earlier.
    return a->creation_time < b->creation_time;
  }
};

void DidGetClients(ClientsCallback callback,
                   std::unique_ptr<ServiceWorkerClientPtrs> clients) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  std::sort(clients->begin(), clients->end(), ServiceWorkerClientInfoSort());

  std::move(callback).Run(std::move(clients));
}

void GetNonWindowClients(
    const base::WeakPtr<ServiceWorkerVersion>& controller,
    blink::mojom::ServiceWorkerClientQueryOptionsPtr options,
    ClientsCallback callback,
    std::unique_ptr<ServiceWorkerClientPtrs> clients) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!options->include_uncontrolled) {
    for (auto& controllee : controller->controllee_map())
      AddNonWindowClient(controllee.second, std::move(options), clients.get());
  } else if (controller->context()) {
    GURL origin = GetOrigin(controller->script_url());
    for (auto it = controller->context()->GetClientProviderHostIterator(origin);
         !it->IsAtEnd(); it->Advance()) {
      AddNonWindowClient(it->GetProviderHost(), std::move(options),
                         clients.get());
    }
  }
  DidGetClients(std::move(callback), std::move(clients));
}

void DidGetWindowClients(
    const base::WeakPtr<ServiceWorkerVersion>& controller,
    blink::mojom::ServiceWorkerClientQueryOptionsPtr options,
    ClientsCallback callback,
    std::unique_ptr<ServiceWorkerClientPtrs> clients) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (options->client_type == blink::mojom::ServiceWorkerClientType::kAll) {
    GetNonWindowClients(controller, std::move(options), std::move(callback),
                        std::move(clients));
    return;
  }
  DidGetClients(std::move(callback), std::move(clients));
}

void GetWindowClients(const base::WeakPtr<ServiceWorkerVersion>& controller,
                      blink::mojom::ServiceWorkerClientQueryOptionsPtr options,
                      ClientsCallback callback,
                      std::unique_ptr<ServiceWorkerClientPtrs> clients) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(options->client_type ==
             blink::mojom::ServiceWorkerClientType::kWindow ||
         options->client_type == blink::mojom::ServiceWorkerClientType::kAll);

  std::vector<std::tuple<int, int, base::TimeTicks, std::string>> clients_info;
  if (!options->include_uncontrolled) {
    for (auto& controllee : controller->controllee_map())
      AddWindowClient(controllee.second, &clients_info);
  } else if (controller->context()) {
    GURL origin = GetOrigin(controller->script_url());
    for (auto it = controller->context()->GetClientProviderHostIterator(origin);
         !it->IsAtEnd(); it->Advance()) {
      AddWindowClient(it->GetProviderHost(), &clients_info);
    }
  }

  if (clients_info.empty()) {
    DidGetWindowClients(controller, std::move(options), std::move(callback),
                        std::move(clients));
    return;
  }

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&OnGetWindowClientsOnUI, clients_info,
                     controller->script_url(),
                     base::BindOnce(&DidGetWindowClients, controller,
                                    std::move(options), std::move(callback)),
                     std::move(clients)));
}

}  // namespace

void FocusWindowClient(ServiceWorkerProviderHost* provider_host,
                       ClientCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK_EQ(blink::mojom::ServiceWorkerClientType::kWindow,
            provider_host->client_type());
  HostThread::PostTaskAndReplyWithResult(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&FocusOnUI, provider_host->process_id(),
                     provider_host->frame_id(), provider_host->create_time(),
                     provider_host->client_uuid()),
      std::move(callback));
}

void OpenWindow(const GURL& url,
                const GURL& script_url,
                int worker_process_id,
                const base::WeakPtr<ServiceWorkerContextCore>& context,
                WindowType type,
                NavigationCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &OpenWindowOnUI, url, script_url, worker_process_id,
          base::WrapRefCounted(context->wrapper()), type,
          base::BindOnce(&DidNavigate, context, GetOrigin(script_url),
                         std::move(callback))));
}

void NavigateClient(const GURL& url,
                    const GURL& script_url,
                    int process_id,
                    int frame_id,
                    const base::WeakPtr<ServiceWorkerContextCore>& context,
                    NavigationCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &NavigateClientOnUI, url, script_url, process_id, frame_id,
          base::BindOnce(&DidNavigate, context, GetOrigin(script_url),
                         std::move(callback))));
}

void GetClient(const ServiceWorkerProviderHost* provider_host,
               ClientCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  blink::mojom::ServiceWorkerClientType client_type =
      provider_host->client_type();
  DCHECK(client_type == blink::mojom::ServiceWorkerClientType::kWindow ||
         client_type == blink::mojom::ServiceWorkerClientType::kSharedWorker)
      << client_type;

  if (client_type == blink::mojom::ServiceWorkerClientType::kWindow) {
   DomainProcessHost* domain_process_host = DomainProcessHost::FromID(provider_host->process_id());
    if (domain_process_host) {
      std::move(callback).Run(
        blink::mojom::ServiceWorkerClientInfo::New(
          GURL("about://blank"), 
          provider_host->client_uuid(),
          blink::mojom::ServiceWorkerClientType::kWindow,
          blink::mojom::PageVisibilityState::kHidden,
          false,
          network::mojom::RequestContextFrameType::kTopLevel,
          provider_host->create_time(),
          provider_host->create_time()));
      return;
    }
    HostThread::PostTaskAndReplyWithResult(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&GetWindowClientInfoOnUI, provider_host->process_id(),
                       provider_host->route_id(), provider_host->create_time(),
                       provider_host->client_uuid()),
        std::move(callback));
    return;
  }

  auto client_info = blink::mojom::ServiceWorkerClientInfo::New(
      provider_host->document_url(), provider_host->client_uuid(),
      provider_host->client_type(), blink::mojom::PageVisibilityState::kHidden,
      false,  // is_focused
      network::mojom::RequestContextFrameType::kNone, base::TimeTicks(),
      provider_host->create_time());
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(std::move(callback), std::move(client_info)));
}

void GetClients(const base::WeakPtr<ServiceWorkerVersion>& controller,
                blink::mojom::ServiceWorkerClientQueryOptionsPtr options,
                ClientsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  auto clients = std::make_unique<ServiceWorkerClientPtrs>();
  if (!controller->HasControllee() && !options->include_uncontrolled) {
    DidGetClients(std::move(callback), std::move(clients));
    return;
  }

  // For Window clients we want to query the info on the UI thread first.
  if (options->client_type == blink::mojom::ServiceWorkerClientType::kWindow ||
      options->client_type == blink::mojom::ServiceWorkerClientType::kAll) {
    GetWindowClients(controller, std::move(options), std::move(callback),
                     std::move(clients));
    return;
  }

  GetNonWindowClients(controller, std::move(options), std::move(callback),
                      std::move(clients));
}

void DidNavigate(const base::WeakPtr<ServiceWorkerContextCore>& context,
                 const GURL& origin,
                 NavigationCallback callback,
                 int render_process_id,
                 int render_frame_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!context) {
    std::move(callback).Run(common::SERVICE_WORKER_ERROR_ABORT,
                            nullptr /* client_info */);
    return;
  }

  if (render_process_id == common::ChildProcessHost::kInvalidUniqueID &&
      render_frame_id == MSG_ROUTING_NONE) {
    std::move(callback).Run(common::SERVICE_WORKER_ERROR_FAILED,
                            nullptr /* client_info */);
    return;
  }

  for (std::unique_ptr<ServiceWorkerContextCore::ProviderHostIterator> it =
           context->GetClientProviderHostIterator(origin);
       !it->IsAtEnd(); it->Advance()) {
    ServiceWorkerProviderHost* provider_host = it->GetProviderHost();
    if (provider_host->process_id() != render_process_id ||
        provider_host->frame_id() != render_frame_id) {
      continue;
    }
    HostThread::PostTaskAndReplyWithResult(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&GetWindowClientInfoOnUI, provider_host->process_id(),
                       provider_host->route_id(), provider_host->create_time(),
                       provider_host->client_uuid()),
        base::BindOnce(std::move(callback), common::SERVICE_WORKER_OK));
    return;
  }

  // If here, it means that no provider_host was found, in which case, the
  // renderer should still be informed that the window was opened.
  std::move(callback).Run(common::SERVICE_WORKER_OK, nullptr /* client_info */);
}

}  // namespace service_worker_client_utils
}  // namespace host
