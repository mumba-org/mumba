// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_INPUT_DEVICE_CHANGE_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_INPUT_INPUT_DEVICE_CHANGE_OBSERVER_H_

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "ui/events/devices/input_device_event_observer.h"

// This class monitors input changes on all platforms.
//
// It is responsible to instantiate the various platforms observers
// and it gets notified whenever the input capabilities change. Whenever
// a change is detected the WebKit preferences are getting updated so the
// interactions media-queries can be updated.
namespace host {
class ApplicationWindowHost;

class CONTENT_EXPORT InputDeviceChangeObserver
    : public ui::InputDeviceEventObserver {
 public:
  InputDeviceChangeObserver(ApplicationWindowHost* rvh);
  ~InputDeviceChangeObserver() override;

  // InputDeviceEventObserver public overrides.
  void OnTouchscreenDeviceConfigurationChanged() override;
  void OnKeyboardDeviceConfigurationChanged() override;
  void OnMouseDeviceConfigurationChanged() override;
  void OnTouchpadDeviceConfigurationChanged() override;

 private:
  
  ApplicationWindowHost* application_window_host_;
  
  void NotifyRenderViewHost();
  
  DISALLOW_COPY_AND_ASSIGN(InputDeviceChangeObserver);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_INPUT_DEVICE_CHANGE_OBSERVER_H_
