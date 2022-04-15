// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/cert_store_instance.h"

#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>

namespace arc {
namespace keymaster {

CertStoreInstance::CertStoreInstance(
    base::WeakPtr<KeymasterServer> keymaster_server)
    : keymaster_server_(keymaster_server) {}

void CertStoreInstance::Init(mojom::CertStoreHostPtr host_ptr,
                             InitCallback callback) {
  LOG(INFO) << "CertStoreInstance::Init";
  host_ptr_ = std::move(host_ptr);
  std::move(callback).Run();

  RequestSecurityTokenOperation();
}

void CertStoreInstance::UpdatePlaceholderKeys(
    std::vector<mojom::ChromeOsKeyPtr> keys,
    UpdatePlaceholderKeysCallback callback) {
  if (keymaster_server_) {
    keymaster_server_->UpdateContextPlaceholderKeys(std::move(keys),
                                                    std::move(callback));
  } else {
    std::move(callback).Run(/*success=*/false);
  }
}

void CertStoreInstance::RequestSecurityTokenOperation() {
  LOG(INFO) << "CertStoreInstance::RequestSecurityTokenOperation";
  if (is_security_token_operation_proxy_ready_)
    return;
  mojo::InterfaceRequest<mojom::SecurityTokenOperation> request =
      mojo::MakeRequest(&security_token_operation_proxy_);
  security_token_operation_proxy_.set_connection_error_handler(
      base::Bind(&CertStoreInstance::ResetSecurityTokenOperationProxy,
                 weak_ptr_factory_.GetWeakPtr()));
  host_ptr_->GetSecurityTokenOperation(
      std::move(request),
      base::Bind(&CertStoreInstance::OnSecurityTokenOperationProxyReady,
                 weak_ptr_factory_.GetWeakPtr()));
}

void CertStoreInstance::ResetSecurityTokenOperationProxy() {
  LOG(INFO) << "CertStoreInstance::ResetSecurityTokenOperationProxy";
  is_security_token_operation_proxy_ready_ = false;
}

void CertStoreInstance::OnSecurityTokenOperationProxyReady() {
  LOG(INFO) << "CertStoreInstance::OnSecurityTokenOperationProxyReady";
  is_security_token_operation_proxy_ready_ = true;
}

}  // namespace keymaster
}  // namespace arc
