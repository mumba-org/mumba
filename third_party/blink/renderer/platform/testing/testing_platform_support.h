/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_TESTING_TESTING_PLATFORM_SUPPORT_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_TESTING_TESTING_PLATFORM_SUPPORT_H_

#include <memory>
#include <utility>

#include "base/macros.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_compositor_support.h"
#include "third_party/blink/renderer/platform/platform_export.h"
#include "third_party/blink/renderer/platform/wtf/allocator.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"

namespace base {
class TestDiscardableMemoryAllocator;
}

namespace cc_blink {
class WebCompositorSupportImpl;
}  // namespace cc_blink

namespace blink {
class WebCompositorSupport;
class WebThread;

class TestingCompositorSupport : public WebCompositorSupport {
  std::unique_ptr<WebLayer> CreateLayer() override;
  std::unique_ptr<WebLayer> CreateLayerFromCCLayer(cc::Layer*) override;
  std::unique_ptr<WebContentLayer> CreateContentLayer(
      WebContentLayerClient*) override;
  std::unique_ptr<WebExternalTextureLayer> CreateExternalTextureLayer(
      cc::TextureLayerClient*) override;
  std::unique_ptr<WebImageLayer> CreateImageLayer() override;
  std::unique_ptr<WebScrollbarLayer> CreateScrollbarLayer(
      std::unique_ptr<WebScrollbar>,
      WebScrollbarThemePainter,
      std::unique_ptr<WebScrollbarThemeGeometry>) override;
  std::unique_ptr<WebScrollbarLayer> CreateOverlayScrollbarLayer(
      std::unique_ptr<WebScrollbar>,
      WebScrollbarThemePainter,
      std::unique_ptr<WebScrollbarThemeGeometry>) override;
  std::unique_ptr<WebScrollbarLayer> CreateSolidColorScrollbarLayer(
      WebScrollbar::Orientation,
      int thumb_thickness,
      int track_start,
      bool is_left_side_vertical_scrollbar) override;
};

// A base class to override Platform methods for testing.  You can override the
// behavior by subclassing TestingPlatformSupport or using
// ScopedTestingPlatformSupport (see below).
class TestingPlatformSupport : public Platform {
 public:
  struct Config {
    WebCompositorSupport* compositor_support = nullptr;
  };

  TestingPlatformSupport();
  explicit TestingPlatformSupport(const Config&);

  ~TestingPlatformSupport() override;

  // Platform:
  WebString DefaultLocale() override;
  WebCompositorSupport* CompositorSupport() override;
  WebThread* CurrentThread() override;
  WebBlobRegistry* GetBlobRegistry() override;
  WebClipboard* Clipboard() override;
  WebIDBFactory* IdbFactory() override;
  WebURLLoaderMockFactory* GetURLLoaderMockFactory() override;
  std::unique_ptr<blink::WebURLLoaderFactory> CreateDefaultURLLoaderFactory()
      override;
  WebData GetDataResource(const char* name) override;
  InterfaceProvider* GetInterfaceProvider() override;

  virtual void RunUntilIdle();

 protected:
  class TestingInterfaceProvider;

  const Config config_;
  Platform* const old_platform_;
  std::unique_ptr<TestingInterfaceProvider> interface_provider_;

  DISALLOW_COPY_AND_ASSIGN(TestingPlatformSupport);
};

// ScopedTestingPlatformSupport<MyTestingPlatformSupport> can be used to
// override Platform::current() with MyTestingPlatformSupport, like this:
//
// #include
// "third_party/blink/renderer/platform/testing/testing_platform_support.h"
//
// TEST_F(SampleTest, sampleTest) {
//   ScopedTestingPlatformSupport<MyTestingPlatformSupport> platform;
//   ...
//   // You can call methods of MyTestingPlatformSupport.
//   EXPECT_TRUE(platform->myMethodIsCalled());
//
//   // Another instance can be nested.
//   {
//     // Constructor's arguments can be passed like this.
//     Arg arg;
//     ScopedTestingPlatformSupport<MyAnotherTestingPlatformSupport, const Arg&>
//         another_platform(args);
//     ...
//   }
//
//   // Here the original MyTestingPlatformSupport should be restored.
// }
template <class T, typename... Args>
class ScopedTestingPlatformSupport final {
  DISALLOW_COPY_AND_ASSIGN(ScopedTestingPlatformSupport);

 public:
  explicit ScopedTestingPlatformSupport(Args&&... args) {
    testing_platform_support_ =
        std::make_unique<T>(std::forward<Args>(args)...);
    original_platform_ = Platform::Current();
    DCHECK(original_platform_);
    Platform::SetCurrentPlatformForTesting(testing_platform_support_.get());
  }
  ~ScopedTestingPlatformSupport() {
    DCHECK_EQ(testing_platform_support_.get(), Platform::Current());
    testing_platform_support_.reset();
    Platform::SetCurrentPlatformForTesting(original_platform_);
  }

  const T* operator->() const { return testing_platform_support_.get(); }
  T* operator->() { return testing_platform_support_.get(); }

  T* GetTestingPlatformSupport() { return testing_platform_support_.get(); }

 private:
  std::unique_ptr<T> testing_platform_support_;
  Platform* original_platform_;
};

class ScopedUnittestsEnvironmentSetup final {
  DISALLOW_COPY_AND_ASSIGN(ScopedUnittestsEnvironmentSetup);

 public:
  ScopedUnittestsEnvironmentSetup(int argc, char** argv);
  ~ScopedUnittestsEnvironmentSetup();

 private:
  class DummyPlatform;
  class DummyRendererResourceCoordinator;
  std::unique_ptr<base::TestDiscardableMemoryAllocator>
      discardable_memory_allocator_;
  std::unique_ptr<DummyPlatform> dummy_platform_;
  std::unique_ptr<DummyRendererResourceCoordinator>
      dummy_renderer_resource_coordinator_;
  std::unique_ptr<cc_blink::WebCompositorSupportImpl> compositor_support_;
  TestingPlatformSupport::Config testing_platform_config_;
  std::unique_ptr<TestingPlatformSupport> testing_platform_support_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_PLATFORM_TESTING_TESTING_PLATFORM_SUPPORT_H_
