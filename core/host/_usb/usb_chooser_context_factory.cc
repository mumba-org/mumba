// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/usb/usb_chooser_context_factory.h"

#include "core/host/content_settings/host_content_settings_map_factory.h"
#include "core/host/workspaces/incognito_helpers.h"
#include "core/host/workspaces/workspace.h"
#include "core/host/usb/usb_chooser_context.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"

namespace host {

UsbChooserContextFactory::UsbChooserContextFactory()
    : BrowserContextKeyedServiceFactory(
          "UsbChooserContext",
          BrowserContextDependencyManager::GetInstance()) {
  DependsOn(HostContentSettingsMapFactory::GetInstance());
}

UsbChooserContextFactory::~UsbChooserContextFactory() {}

KeyedService* UsbChooserContextFactory::BuildServiceInstanceFor(
    content::BrowserContext* context) const {
  return new UsbChooserContext(Workspace::FromBrowserContext(context));
}

// static
UsbChooserContextFactory* UsbChooserContextFactory::GetInstance() {
  return base::Singleton<UsbChooserContextFactory>::get();
}

// static
UsbChooserContext* UsbChooserContextFactory::GetForWorkspace(Workspace* workspace) {
  return static_cast<UsbChooserContext*>(
      GetInstance()->GetServiceForBrowserContext(workspace, true));
}

content::BrowserContext* UsbChooserContextFactory::GetBrowserContextToUse(
    content::BrowserContext* context) const {
  return chrome::GetBrowserContextOwnInstanceInIncognito(context);
}

}