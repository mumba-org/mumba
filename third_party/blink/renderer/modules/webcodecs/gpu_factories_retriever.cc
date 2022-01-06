// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"

#include "media/video/gpu_video_accelerator_factories.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_thread.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/public/platform/web_common.h"
#include "third_party/blink/renderer/platform/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/cross_thread_functional.h"

namespace blink {

namespace {

void GetGpuFactoriesOnMainThread(OutputCB result_callback) {
  DCHECK(IsMainThread());
  std::move(result_callback).Run(Platform::Current()->GetGpuFactories());
}

void RetrieveGpuFactories(OutputCB result_callback) {
  if (IsMainThread()) {
    GetGpuFactoriesOnMainThread(std::move(result_callback));
    return;
  }

  Platform::Current()->MainThread()->GetTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&GetGpuFactoriesOnMainThread, base::Passed(std::move(result_callback))));
}

// void OnSupportKnown(OutputCB result_cb,
//                     media::GpuVideoAcceleratorFactories* factories) {
//   std::move(result_cb).Run(factories);
// }

}  // namespace

void RetrieveGpuFactoriesWithKnownEncoderSupport(OutputCB callback) {
  // auto on_factories_received =
  //     [](OutputCB result_cb, media::GpuVideoAcceleratorFactories* factories) {
  //       if (!factories) {// || factories->IsEncoderSupportKnown()) {
  //         std::move(result_cb).Run(factories);
  //       } else {
  //         factories->NotifyEncoderSupportKnown(ConvertToBaseOnceCallback(
  //             CrossThreadBind(OnSupportKnown, std::move(result_cb),
  //                             CrossThreadUnretained(factories))));
  //       }
  //     };

  // auto factories_callback =
  //     CrossThreadBind(on_factories_received, std::move(callback));

  // RetrieveGpuFactories(std::move(factories_callback));
  RetrieveGpuFactories(std::move(callback));
}

void RetrieveGpuFactoriesWithKnownDecoderSupport(OutputCB callback) {
  // auto on_factories_received =
  //     [](OutputCB result_cb, media::GpuVideoAcceleratorFactories* factories) {
  //       if (!factories || factories->IsDecoderSupportKnown()) {
  //         std::move(result_cb).Run(factories);
  //       } else {
  //         factories->NotifyDecoderSupportKnown(ConvertToBaseOnceCallback(
  //             CrossThreadBind(OnSupportKnown, std::move(result_cb),
  //                                 CrossThreadUnretained(factories))));
  //       }
  //     };

  // auto factories_callback =
  //     CrossThreadBind(on_factories_received, std::move(callback));

  // RetrieveGpuFactories(std::move(factories_callback));
  RetrieveGpuFactories(std::move(callback));
}

}  // namespace blink
