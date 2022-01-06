// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_BINDING_SET_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_BINDING_SET_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/macros.h"
#include "core/shared/common/content_export.h"
//#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/associated_interface_request.h"
#include "mojo/public/cpp/bindings/scoped_interface_endpoint_handle.h"

namespace host {

//class RenderFrameHost;
class ApplicationWindowHost;
class ApplicationContents;

// Base class for something which owns a mojo::AssociatedBindingSet on behalf
// of a WebContents. See WebContentsFrameBindingSet<T> below.
class CONTENT_EXPORT ApplicationContentsBindingSet {
 public:
  class CONTENT_EXPORT Binder {
   public:
    virtual ~Binder() {}

    virtual void OnRequestForWindow(
        //RenderFrameHost* render_frame_host,
        ApplicationWindowHost* app_window_host,
        mojo::ScopedInterfaceEndpointHandle handle);
  };

  void SetBinderForTesting(std::unique_ptr<Binder> binder) {
    binder_for_testing_ = std::move(binder);
  }

  template <typename Interface>
  static ApplicationContentsBindingSet* GetForApplicationContents(ApplicationContents* app_contents) {
    return GetForApplicationContents(app_contents, Interface::Name_);
  }

 protected:
  ApplicationContentsBindingSet(ApplicationContents* app_contents,
                        const std::string& interface_name,
                        std::unique_ptr<Binder> binder);
  ~ApplicationContentsBindingSet();

 private:
  friend class ApplicationContents;

  static ApplicationContentsBindingSet* GetForApplicationContents(
    ApplicationContents* app_contents,
    const char* interface_name);

  void CloseAllBindings();
  void OnRequestForWindow(ApplicationWindowHost* window_host,
                         mojo::ScopedInterfaceEndpointHandle handle);

  const base::Closure remove_callback_;
  std::unique_ptr<Binder> binder_;
  std::unique_ptr<Binder> binder_for_testing_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsBindingSet);
};

// Owns a set of Channel-associated interface bindings with frame context on
// message dispatch.
//
// To use this, a |mojom::Foo| implementation need only own an instance of
// WebContentsFrameBindingSet<mojom::Foo>. This allows remote RenderFrames to
// acquire handles to the |mojom::Foo| interface via
// RenderFrame::GetRemoteAssociatedInterfaces() and send messages here. When
// messages are dispatched to the implementation, the implementation can call
// GetCurrentTargetFrame() on this object (see below) to determine which
// frame sent the message.
//
// For example:
//
//   class FooImpl : public mojom::Foo {
//    public:
//     explicit FooImpl(WebContents* web_contents)
//         : web_contents_(web_contents), bindings_(web_contents, this) {}
//
//     // mojom::Foo:
//     void DoFoo() override {
//       if (bindings_.GetCurrentTargetFrame() == web_contents_->GetMainFrame())
//           ; // Do something interesting
//     }
//
//    private:
//     WebContents* web_contents_;
//     WebContentsFrameBindingSet<mojom::Foo> bindings_;
//   };
//
// When an instance of FooImpl is constructed over a WebContents, the mojom::Foo
// interface will be exposed to all remote RenderFrame objects. If the
// WebContents is destroyed at any point, the bindings will automatically reset
// and will cease to dispatch further incoming messages.
//
// If FooImpl is destroyed first, the bindings are automatically removed and
// future incoming interface requests for mojom::Foo will be rejected.
//
// Because this object uses Channel-associated interface bindings, all messages
// sent via these interfaces are ordered with respect to legacy Chrome IPC
// messages on the relevant IPC::Channel (i.e. the Channel between the browser
// and whatever render process hosts the sending frame.)
template <typename Interface>
class ApplicationContentsWindowBindingSet : public ApplicationContentsBindingSet {
 private:
  class WindowInterfaceBinder; 
 public:
  ApplicationContentsWindowBindingSet(ApplicationContents* app_contents, Interface* impl)
      : ApplicationContentsBindingSet(
            app_contents,
            Interface::Name_,
            std::make_unique<WindowInterfaceBinder>(this, app_contents, impl)) {}
  ~ApplicationContentsWindowBindingSet() {}

  // Returns the RenderFrameHost currently targeted by a message dispatch to
  // this interface. Must only be called during the extent of a message dispatch
  // for this interface.
  ApplicationWindowHost* GetCurrentTargetWindow() {
    DCHECK(current_target_window_);
    return current_target_window_;
  }

  void SetCurrentTargetWindowForTesting(ApplicationWindowHost* app_window_host) {
    current_target_window_ = app_window_host;
  }

 private:
  class WindowInterfaceBinder : public Binder, public ApplicationContentsObserver {
   public:
    WindowInterfaceBinder(ApplicationContentsWindowBindingSet* binding_set,
                          ApplicationContents* app_contents,
                          Interface* impl)
        : ApplicationContentsObserver(app_contents), impl_(impl) {
      bindings_.set_pre_dispatch_handler(
          base::Bind(&ApplicationContentsWindowBindingSet::WillDispatchForContext,
                     base::Unretained(binding_set)));
    }

    ~WindowInterfaceBinder() override {
      //DLOG(INFO) << "~WindowInterfaceBinder: " << this;     
    }

    // Binder:
    void OnRequestForWindow(
        ApplicationWindowHost* window_host,
        mojo::ScopedInterfaceEndpointHandle handle) override {
      auto id = bindings_.AddBinding(
          impl_, mojo::AssociatedInterfaceRequest<Interface>(std::move(handle)),
          window_host);
      window_to_bindings_map_[window_host].push_back(id);
    }

    // ApplicationContentsObserver:
    void ApplicationWindowDeleted(ApplicationWindowHost* app_window_host) override {
      auto it = window_to_bindings_map_.find(app_window_host);
      if (it == window_to_bindings_map_.end())
        return;
      for (auto id : it->second)
        bindings_.RemoveBinding(id);
      window_to_bindings_map_.erase(it);
    }

    Interface* const impl_;
    mojo::AssociatedBindingSet<Interface, ApplicationWindowHost*> bindings_;
    std::map<ApplicationWindowHost*, std::vector<mojo::BindingId>>
        window_to_bindings_map_;

    DISALLOW_COPY_AND_ASSIGN(WindowInterfaceBinder);
  };

  void WillDispatchForContext(ApplicationWindowHost* const& window_host) {
    current_target_window_ = window_host;
  }

  ApplicationWindowHost* current_target_window_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsWindowBindingSet);
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_CONTENTS_BINDING_SET_H_
