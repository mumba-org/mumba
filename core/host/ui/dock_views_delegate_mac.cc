// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_views_delegate.h"

#include "base/feature_list.h"
//#include "chrome/common/chrome_features.h"

views::NativeWidget* DockViewsDelegate::CreateNativeWidget(
    views::Widget::InitParams* params,
    views::internal::NativeWidgetDelegate* delegate) {
  // By returning null Widget creates the default NativeWidget implementation.
  return nullptr;
}

bool DockViewsDelegate::ShouldMirrorArrowsInRTL() const {
  //return base::FeatureList::IsEnabled(features::kMacRTL);
  return false;
}
