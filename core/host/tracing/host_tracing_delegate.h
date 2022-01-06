// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_TRACING_CHROME_TRACING_DELEGATE_H_
#define CHROME_BROWSER_TRACING_CHROME_TRACING_DELEGATE_H_

#include <memory>

#include "core/host/tracing_delegate.h"

class PrefRegistrySimple;

namespace host {

class HostTracingDelegate : public TracingDelegate {//,
                             // public BrowserListObserver {
 public:
  HostTracingDelegate();
  ~HostTracingDelegate() override;

  static void RegisterPrefs(PrefRegistrySimple* registry);

  std::unique_ptr<TraceUploader> GetTraceUploader(
      net::URLRequestContextGetter* request_context) override;

  bool IsAllowedToBeginBackgroundScenario(
      const BackgroundTracingConfig& config,
      bool requires_anonymized_data) override;

  bool IsAllowedToEndBackgroundScenario(
      const BackgroundTracingConfig& config,
      bool requires_anonymized_data) override;

  bool IsProfileLoaded() override;

  std::unique_ptr<base::DictionaryValue> GenerateMetadataDict() override;

  MetadataFilterPredicate GetMetadataFilterPredicate() override;

 private:
  // BrowserListObserver implementation.
  //void OnBrowserAdded(Browser* browser) override;

  //bool incognito_launched_;
};

}

#endif  // CHROME_BROWSER_TRACING_CHROME_TRACING_DELEGATE_H_
