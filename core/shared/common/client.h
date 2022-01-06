// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_CLIENT_H__
#define COMMON_CLIENT_H__

#include <string>

#include "base/macros.h"
#include "url/gurl.h"
#include "core/shared/common/content_export.h"
#include "ui/base/layout.h"
#include "url/origin.h"

class ClientInitializer;

namespace host {
class HostClient;
}

namespace base {
class RefCountedMemory;
}

namespace application {
class ApplicationClient;
}

namespace gpu {
struct GPUInfo;
class ContentGpuClient;
}

namespace utility {
class ContentUtilityClient;  
}

namespace common {
class ServiceManagerConnection;

class CONTENT_EXPORT Client {
public:
  // Gives the embedder a chance to register its own schemes early in the
  // startup sequence.
  struct CONTENT_EXPORT Schemes {
    Schemes();
    ~Schemes();
    std::vector<std::string> standard_schemes;
    std::vector<std::string> referrer_schemes;
    std::vector<std::string> savable_schemes;
    // Additional schemes that should be allowed to register service workers.
    // Only secure and trustworthy schemes should be added.
    std::vector<std::string> service_worker_schemes;
    // Registers a URL scheme to be treated as a local scheme (i.e., with the
    // same security rules as those applied to "file" URLs). This means that
    // normal pages cannot link to or access URLs of this scheme.
    std::vector<std::string> local_schemes;
    // Registers a URL scheme to be treated as a noAccess scheme. This means
    // that pages loaded with this URL scheme always have an opaque origin.
    std::vector<std::string> no_access_schemes;
    // Registers a non-HTTP URL scheme which can be sent CORS requests.
    std::vector<std::string> cors_enabled_schemes;
    // Registers a URL scheme whose resources can be loaded regardless of a
    // page's Content Security Policy.
    std::vector<std::string> csp_bypassing_schemes;
    // See https://www.w3.org/TR/powerful-features/#is-origin-trustworthy.
    std::vector<std::string> secure_schemes;
    std::vector<url::Origin> secure_origins;
    // Registers a URL scheme as strictly empty documents, allowing them to
    // commit synchronously.
    std::vector<std::string> empty_document_schemes;
  };
  
 Client();
 ~Client();

 // TODO this is a layering violation..
 // we need to define interfaces in common
 // and the clients in each submodule should
 // implement the methods
 host::HostClient* host() const { return host_client_; }
 application::ApplicationClient* application() const { return application_client_; }
 gpu::ContentGpuClient* gpu() const { return gpu_client_; }
 utility::ContentUtilityClient* utility() const { return utility_client_; } 

 void SetGpuInfo(const gpu::GPUInfo& gpu_info);
 // Returns a string describing the embedder product name and version,
 // of the form "productname/version", with no other slashes.
 // Used as part of the user agent string.
 std::string GetProduct() const;
 std::string GetUserAgent() const;
 base::string16 GetLocalizedString(int message_id) const;
 base::StringPiece GetDataResource(
      int resource_id,
      ui::ScaleFactor scale_factor) const;
 base::RefCountedMemory* GetDataResourceBytes(int resource_id);

 void OnServiceManagerConnected(ServiceManagerConnection* connection);
 bool AllowScriptExtensionForServiceWorker(const GURL& script_url);

 virtual void AddAdditionalSchemes(Schemes* schemes) {}

private:
 friend class ::ClientInitializer;

 host::HostClient* host_client_;

 application::ApplicationClient* application_client_;

 gpu::ContentGpuClient* gpu_client_;

 utility::ContentUtilityClient* utility_client_;

 DISALLOW_COPY_AND_ASSIGN(Client);
};

CONTENT_EXPORT Client* GetClient();
CONTENT_EXPORT void SetClient(Client* client);

}

#endif