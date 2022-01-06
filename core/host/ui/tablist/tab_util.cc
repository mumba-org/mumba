// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/tab_util.h"

//#include "chrome/browser/profiles/profile.h"
//#include "chrome/browser/ui/webui/chrome_web_ui_controller_factory.h"
#include "core/shared/common/switches.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host.h"
//#include "core/browser/site_instance.h"
#include "core/host/application/application_contents.h"
#include "url/gurl.h"

using host::ApplicationWindowHost;
using host::ApplicationContents;

namespace tab_util {

host::ApplicationContents* GetApplicationContentsByID(int render_process_id,
                                                      int render_view_id) {
  ApplicationWindowHost* render_view_host =
      ApplicationWindowHost::FromID(render_process_id, render_view_id);
  if (!render_view_host)
    return NULL;
  return ApplicationContents::FromApplicationWindowHost(render_view_host);
}

host::ApplicationContents* GetApplicationContentsByFrameID(int render_process_id,
                                                           int render_frame_id) {
  ApplicationWindowHost* render_frame_host =
      ApplicationWindowHost::FromID(render_process_id, render_frame_id);
  if (!render_frame_host)
    return NULL;
  return ApplicationContents::FromApplicationWindowHost(render_frame_host);
}

// scoped_refptr<SiteInstance> GetSiteInstanceForNewTab(Profile* profile,
//                                                      const GURL& url) {
//   // If |url| is a WebUI or extension, we set the SiteInstance up front so that
//   // we don't end up with an extra process swap on the first navigation.
//   if (ChromeWebUIControllerFactory::GetInstance()->UseWebUIForURL(profile, url))
//     return SiteInstance::CreateForURL(profile, url);

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   if (extensions::ExtensionRegistry::Get(profile)
//           ->enabled_extensions()
//           .GetHostedAppByURL(url))
//     return SiteInstance::CreateForURL(profile, url);
// #endif

//   // We used to share the SiteInstance for same-site links opened in new tabs,
//   // to leverage the in-memory cache and reduce process creation.  It now
//   // appears that it is more useful to have such links open in a new process,
//   // so we create new tabs in a new BrowsingInstance.
//   // Create a new SiteInstance for the |url| unless it is not desirable.
//   if (!SiteInstance::ShouldAssignSiteForURL(url))
//     return nullptr;

//   return SiteInstance::CreateForURL(profile, url);
// }

}  // namespace tab_util
