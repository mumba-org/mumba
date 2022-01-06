// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/tracing_delegate.h"

#include "base/values.h"

namespace host {

bool TracingDelegate::IsAllowedToBeginBackgroundScenario(
    const BackgroundTracingConfig& config,
    bool requires_anonymized_data) {
  return false;
}

bool TracingDelegate::IsAllowedToEndBackgroundScenario(
    const BackgroundTracingConfig& config,
    bool requires_anonymized_data) {
  return false;
}

bool TracingDelegate::IsProfileLoaded() {
  return false;
}

std::unique_ptr<base::DictionaryValue> TracingDelegate::GenerateMetadataDict() {
  return nullptr;
}

MetadataFilterPredicate TracingDelegate::GetMetadataFilterPredicate() {
  return MetadataFilterPredicate();
}

}  // namespace host
