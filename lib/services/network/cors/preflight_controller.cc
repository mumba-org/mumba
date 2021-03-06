// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/cors/preflight_controller.h"

#include <algorithm>

#include "base/bind.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/http/http_request_headers.h"
#include "services/network/public/cpp/cors/cors.h"
#include "services/network/public/cpp/cors/cors_error_status.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "url/gurl.h"

namespace network {

namespace cors {

namespace {

base::Optional<std::string> GetHeaderString(
    const scoped_refptr<net::HttpResponseHeaders>& headers,
    const std::string& header_name) {
  std::string header_value;
  if (!headers->GetNormalizedHeader(header_name, &header_value))
    return base::nullopt;
  return header_value;
}

// Algorithm step 3 of the CORS-preflight fetch,
// https://fetch.spec.whatwg.org/#cors-preflight-fetch-0, that requires
//  - CORS-safelisted request-headers excluded
//  - duplicates excluded
//  - sorted lexicographically
//  - byte-lowercased
std::string CreateAccessControlRequestHeadersHeader(
    const net::HttpRequestHeaders& headers) {
  std::vector<std::string> filtered_headers;
  for (const auto& header : headers.GetHeaderVector()) {
    // Exclude CORS-safelisted headers.
    if (cors::IsCORSSafelistedHeader(header.key, header.value))
      continue;
    // Exclude the forbidden headers because they may be added by the user
    // agent. They must be checked separately and rejected for
    // JavaScript-initiated requests.
    if (cors::IsForbiddenHeader(header.key))
      continue;
    filtered_headers.push_back(base::ToLowerASCII(header.key));
  }
  if (filtered_headers.empty())
    return std::string();

  // Sort header names lexicographically.
  std::sort(filtered_headers.begin(), filtered_headers.end());

  return base::JoinString(filtered_headers, ",");
}

std::unique_ptr<ResourceRequest> CreatePreflightRequest(
    const ResourceRequest& request) {
  DCHECK(!request.url.has_username());
  DCHECK(!request.url.has_password());

  std::unique_ptr<ResourceRequest> preflight_request =
      std::make_unique<ResourceRequest>();

  // Algorithm step 1 through 4 of the CORS-preflight fetch,
  // https://fetch.spec.whatwg.org/#cors-preflight-fetch-0.
  preflight_request->url = request.url;
  preflight_request->method = "OPTIONS";
  preflight_request->priority = request.priority;
  preflight_request->fetch_request_context_type =
      request.fetch_request_context_type;
  preflight_request->referrer = request.referrer;
  preflight_request->referrer_policy = request.referrer_policy;

  preflight_request->fetch_credentials_mode =
      mojom::FetchCredentialsMode::kOmit;

  preflight_request->headers.SetHeader(
      cors::header_names::kAccessControlRequestMethod, request.method);

  std::string request_headers =
      CreateAccessControlRequestHeadersHeader(request.headers);
  if (!request_headers.empty()) {
    preflight_request->headers.SetHeader(
        cors::header_names::kAccessControlRequestHeaders, request_headers);
  }

  if (request.is_external_request) {
    preflight_request->headers.SetHeader(
        cors::header_names::kAccessControlRequestExternal, "true");
  }

  DCHECK(request.request_initiator);
  preflight_request->headers.SetHeader(net::HttpRequestHeaders::kOrigin,
                                       request.request_initiator->Serialize());

  // TODO(toyoshim): Remove the following line once the network service is
  // enabled by default.
  preflight_request->skip_service_worker = true;

  return preflight_request;
}

std::unique_ptr<PreflightResult> CreatePreflightResult(
    const GURL& final_url,
    const ResourceResponseHead& head,
    const ResourceRequest& original_request,
    base::Optional<mojom::CORSError>* detected_error) {
  DCHECK(detected_error);

  // TODO(toyoshim): Reflect --allow-file-access-from-files flag.
  *detected_error = CheckAccess(
      final_url, head.headers->response_code(),
      GetHeaderString(head.headers,
                      cors::header_names::kAccessControlAllowOrigin),
      GetHeaderString(head.headers,
                      cors::header_names::kAccessControlAllowCredentials),
      original_request.fetch_credentials_mode,
      *original_request.request_initiator, false /* allow_file_origin */);
  if (*detected_error)
    return nullptr;

  *detected_error = CheckPreflight(head.headers->response_code());
  if (*detected_error)
    return nullptr;

  if (original_request.is_external_request) {
    *detected_error = CheckExternalPreflight(GetHeaderString(
        head.headers, header_names::kAccessControlAllowExternal));
    if (*detected_error)
      return nullptr;
  }

  return PreflightResult::Create(
      original_request.fetch_credentials_mode,
      GetHeaderString(head.headers, header_names::kAccessControlAllowMethods),
      GetHeaderString(head.headers, header_names::kAccessControlAllowHeaders),
      GetHeaderString(head.headers, header_names::kAccessControlMaxAge),
      detected_error);
}

base::Optional<mojom::CORSError> CheckPreflightResult(
    PreflightResult* result,
    const ResourceRequest& original_request,
    scoped_refptr<net::HttpResponseHeaders>* error_header) {
  DCHECK(error_header);

  base::Optional<mojom::CORSError> error =
      result->EnsureAllowedCrossOriginMethod(original_request.method);
  if (error)
    return error;

  std::string detected_error_header;
  error = result->EnsureAllowedCrossOriginHeaders(original_request.headers,
                                                  &detected_error_header);
  if (error) {
    // Gather information to report the error's details.
    DCHECK(!detected_error_header.empty());
    std::string header_value;
    bool found = original_request.headers.GetHeader(detected_error_header,
                                                    &header_value);
    DCHECK(found);
    // Status line below is dummy to construct a response header instance.
    *error_header =
        base::MakeRefCounted<net::HttpResponseHeaders>(base::StringPrintf(
            "HTTP/1.0 200 OK\n%s: %s", detected_error_header.c_str(),
            header_value.c_str()));
    return error;
  }

  return base::nullopt;
}

}  // namespace

class PreflightController::PreflightLoader final {
 public:
  PreflightLoader(PreflightController* controller,
                  CompletionCallback completion_callback,
                  const ResourceRequest& request,
                  const net::NetworkTrafficAnnotationTag& annotation_tag)
      : controller_(controller),
        completion_callback_(std::move(completion_callback)),
        original_request_(request) {
    loader_ = SimpleURLLoader::Create(CreatePreflightRequest(request),
                                      annotation_tag);
  }

  void Request(mojom::URLLoaderFactory* loader_factory) {
    DCHECK(loader_);

    loader_->SetOnRedirectCallback(base::BindRepeating(
        &PreflightLoader::HandleRedirect, base::Unretained(this)));
    loader_->SetOnResponseStartedCallback(base::BindRepeating(
        &PreflightLoader::HandleResponseHeader, base::Unretained(this)));
    loader_->DownloadToString(
        loader_factory,
        base::BindOnce(&PreflightLoader::HandleResponseBody,
                       base::Unretained(this)),
        0);
  }

 private:
  void HandleRedirect(const net::RedirectInfo& redirect_info,
                      const network::ResourceResponseHead& response_head) {
    // Preflight should not allow any redirect.
    FinalizeLoader();

    // TODO(toyoshim): Define kDisallowedPreflightRedirect in a separate patch.
    std::move(completion_callback_)
        .Run(CORSErrorStatus(mojom::CORSError::kPreflightInvalidStatus));

    RemoveFromController();
    // |this| is deleted here.
  }

  void HandleResponseHeader(const GURL& final_url,
                            const ResourceResponseHead& head) {
    FinalizeLoader();

    base::Optional<mojom::CORSError> detected_error;
    std::unique_ptr<PreflightResult> result = CreatePreflightResult(
        final_url, head, original_request_, &detected_error);

    scoped_refptr<net::HttpResponseHeaders> error_header;
    if (result) {
      // Preflight succeeded. Check |original_request_| with |result|.
      DCHECK(!detected_error);
      detected_error =
          CheckPreflightResult(result.get(), original_request_, &error_header);
    }

    // TODO(toyoshim): Check the spec if we cache |result| regardless of
    // following checks.
    if (!detected_error) {
      controller_->AppendToCache(*original_request_.request_initiator,
                                 original_request_.url, std::move(result));
    }

    if (detected_error) {
      std::move(completion_callback_)
          .Run(CORSErrorStatus(*detected_error, error_header));
    } else {
      std::move(completion_callback_).Run(base::nullopt);
    }

    RemoveFromController();
    // |this| is deleted here.
  }

  void HandleResponseBody(std::unique_ptr<std::string> response_body) {
    NOTREACHED();
  }

  void FinalizeLoader() {
    DCHECK(loader_);
    loader_.reset();
  }

  // Removes |this| instance from |controller_|. Once the method returns, |this|
  // is already removed.
  void RemoveFromController() { controller_->RemoveLoader(this); }

  // PreflightController owns all PreflightLoader instances, and should outlive.
  PreflightController* const controller_;

  // Holds SimpleURLLoader instance for the CORS-preflight request.
  std::unique_ptr<SimpleURLLoader> loader_;

  // Holds caller's information.
  PreflightController::CompletionCallback completion_callback_;
  const ResourceRequest original_request_;

  DISALLOW_COPY_AND_ASSIGN(PreflightLoader);
};

// static
std::unique_ptr<ResourceRequest>
PreflightController::CreatePreflightRequestForTesting(
    const ResourceRequest& request) {
  return CreatePreflightRequest(request);
}

PreflightController::PreflightController() = default;

PreflightController::~PreflightController() = default;

void PreflightController::PerformPreflightCheck(
    CompletionCallback callback,
    const ResourceRequest& request,
    const net::NetworkTrafficAnnotationTag& annotation_tag,
    mojom::URLLoaderFactory* loader_factory) {
  DCHECK(request.request_initiator);

  if (cache_.CheckIfRequestCanSkipPreflight(
          request.request_initiator->Serialize(), request.url,
          request.fetch_credentials_mode, request.method, request.headers)) {
    std::move(callback).Run(base::nullopt);
    return;
  }

  auto emplaced_pair = loaders_.emplace(std::make_unique<PreflightLoader>(
      this, std::move(callback), request, annotation_tag));
  (*emplaced_pair.first)->Request(loader_factory);
}

void PreflightController::RemoveLoader(PreflightLoader* loader) {
  auto it = loaders_.find(loader);
  DCHECK(it != loaders_.end());
  loaders_.erase(it);
}

void PreflightController::AppendToCache(
    const url::Origin& origin,
    const GURL& url,
    std::unique_ptr<PreflightResult> result) {
  cache_.AppendEntry(origin.Serialize(), url, std::move(result));
}

}  // namespace cors

}  // namespace network
