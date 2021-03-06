// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UI_OZONE_DEMO_SIMPLE_RENDERER_FACTORY_H_
#define UI_OZONE_DEMO_SIMPLE_RENDERER_FACTORY_H_

#include "ui/ozone/demo/renderer_factory.h"
#include "ui/ozone/public/ozone_gpu_test_helper.h"

namespace ui {

class SimpleRendererFactory : public RendererFactory {
 public:
  enum RendererType {
    GL,
    SOFTWARE,
  };

  SimpleRendererFactory();
  ~SimpleRendererFactory() override;

  bool Initialize() override;
  std::unique_ptr<Renderer> CreateRenderer(gfx::AcceleratedWidget widget,
                                           const gfx::Size& size) override;

 private:
  RendererType type_ = SOFTWARE;

  // Helper for applications that do GL on main thread.
  OzoneGpuTestHelper gpu_helper_;

  DISALLOW_COPY_AND_ASSIGN(SimpleRendererFactory);
};

}  // namespace ui

#endif  // UI_OZONE_DEMO_SIMPLE_RENDERER_FACTORY_H_
