// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/ozone/demo/simple_renderer_factory.h"

#include <memory>

#include "base/command_line.h"
#include "ui/gl/gl_surface.h"
#include "ui/gl/init/gl_factory.h"
#include "ui/ozone/demo/gl_renderer.h"
#include "ui/ozone/demo/software_renderer.h"
#include "ui/ozone/demo/surfaceless_gl_renderer.h"
#include "ui/ozone/public/ozone_platform.h"

namespace ui {
namespace {

const char kDisableSurfaceless[] = "disable-surfaceless";
const char kDisableGpu[] = "disable-gpu";

scoped_refptr<gl::GLSurface> CreateGLSurface(gfx::AcceleratedWidget widget) {
  scoped_refptr<gl::GLSurface> surface;
  if (!base::CommandLine::ForCurrentProcess()->HasSwitch(kDisableSurfaceless))
    surface = gl::init::CreateSurfacelessViewGLSurface(widget);
  if (!surface)
    surface = gl::init::CreateViewGLSurface(widget);
  return surface;
}

}  // namespace

SimpleRendererFactory::SimpleRendererFactory() {}

SimpleRendererFactory::~SimpleRendererFactory() {}

bool SimpleRendererFactory::Initialize() {
  OzonePlatform::InitParams params;
  params.single_process = true;
  OzonePlatform::InitializeForGPU(params);
  OzonePlatform::GetInstance()->AfterSandboxEntry();

  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  if (!command_line->HasSwitch(kDisableGpu) && gl::init::InitializeGLOneOff() &&
      gpu_helper_.Initialize(base::ThreadTaskRunnerHandle::Get())) {
    type_ = GL;
  } else {
    type_ = SOFTWARE;
  }

  return true;
}

std::unique_ptr<Renderer> SimpleRendererFactory::CreateRenderer(
    gfx::AcceleratedWidget widget,
    const gfx::Size& size) {
  switch (type_) {
    case GL: {
      scoped_refptr<gl::GLSurface> surface = CreateGLSurface(widget);
      if (!surface)
        LOG(FATAL) << "Failed to create GL surface";
      if (surface->IsSurfaceless()) {
        return std::make_unique<SurfacelessGlRenderer>(widget, surface, size);
      }
      return std::make_unique<GlRenderer>(widget, surface, size);
    }
    case SOFTWARE:
      return std::make_unique<SoftwareRenderer>(widget, size);
  }

  return nullptr;
}

}  // namespace ui
