// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_FACTORY_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_FACTORY_H_

#include <stdint.h>

#include "base/macros.h"
#include "core/shared/common/content_export.h"

namespace host {
class ApplicationWindowHost;
class ApplicationWindowHostDelegate;
class ApplicationProcessHost;
class Application;
// A factory for creating RenderViewHosts. There is a global factory function
// that can be installed for the purposes of testing to provide a specialized
// RenderViewHost class.
class ApplicationWindowHostFactory {
 public:
  // Creates a RenderViewHost using the currently registered factory, or the
  // default one if no factory is registered. Ownership of the returned
  // pointer will be passed to the caller.
  static ApplicationWindowHost* Create(ApplicationWindowHostDelegate* delegate,
                                       Application* application,
                                       ApplicationProcessHost* process,
                                       int32_t routing_id,
                                       bool swapped_out,
                                       bool hidden);

  // Returns true if there is currently a globally-registered factory.
  static bool has_factory() {
    return !!factory_;
  }

  // Returns true if the RenderViewHost instance is not a test instance.
  CONTENT_EXPORT static bool is_real_application_window_host() {
    return is_real_application_window_host_;
  }

  // Sets the is_real_application_window_host flag which indicates that the
  // RenderViewHost instance is not a test instance.
  CONTENT_EXPORT static void set_is_real_application_window_host(
      bool is_real_application_window_host) {
    is_real_application_window_host_ = is_real_application_window_host;
  }

 protected:
  ApplicationWindowHostFactory() {}
  virtual ~ApplicationWindowHostFactory() {}

  // You can derive from this class and specify an implementation for this
  // function to create a different kind of RenderViewHost for testing.
  virtual ApplicationWindowHost* CreateApplicationWindowHost(
      ApplicationWindowHostDelegate* delegate,
      Application* application,
      ApplicationProcessHost* process,
      int32_t routing_id,
      bool swapped_out) = 0;

  // Registers your factory to be called when new RenderViewHosts are created.
  // We have only one global factory, so there must be no factory registered
  // before the call. This class does NOT take ownership of the pointer.
  CONTENT_EXPORT static void RegisterFactory(ApplicationWindowHostFactory* factory);

  // Unregister the previously registered factory. With no factory registered,
  // the default RenderViewHosts will be created.
  CONTENT_EXPORT static void UnregisterFactory();

 private:
  // The current globally registered factory. This is NULL when we should
  // create the default RenderViewHosts.
  CONTENT_EXPORT static ApplicationWindowHostFactory* factory_;

  // Set to true if the RenderViewHost is not a test instance. Defaults to
  // false.
  CONTENT_EXPORT static bool is_real_application_window_host_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHostFactory);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_RENDER_VIEW_HOST_FACTORY_H_
