// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_TEXT_INPUT_CLIENT_MAC_H_
#define MUMBA_HOST_APPLICATION_TEXT_INPUT_CLIENT_MAC_H_

#import <Cocoa/Cocoa.h>

#include "base/mac/scoped_block.h"
#include "base/mac/scoped_nsobject.h"
#include "base/macros.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "core/shared/common/content_export.h"
#include "core/common/mac/attributed_string_coder.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"

namespace base {
template <typename T>
struct DefaultSingletonTraits;
}  // namespace base

namespace gfx {
class Range;
}

namespace host {
class ApplicationWindowHost;

// This class helps with the Mac OS X dictionary popup. For the design overview,
// look at this document:
//   http://dev.chromium.org/developers/design-documents/system-dictionary-pop-up-architecture
//
// This service is used to marshall information for these three methods that are
// implemented in ApplicationWindowHostViewMac:
//   -[NSTextInput characterIndexForPoint:]
//   -[NSTextInput attributedSubstringFromRange:]
//   -[NSTextInput firstRectForCharacterRange:]
//
// Because these methods are part of a synchronous system API, implementing them
// requires getting information from the renderer synchronously. Rather than
// using an actual sync IPC message, a normal async ViewMsg is used with a lock
// and condition (managed by this service).
//
// Mac OS 10.8 introduced -[NSResponder quickLookWithEvent:].
// We can use it to implement asynchronous dictionary lookup when the user
// taps a word using three fingers.
// But currently the "Look Up in Dictionary" context menu item still goes
// through the above synchronous IPC.
class CONTENT_EXPORT TextInputClientMac {
 public:
  // Returns the singleton instance.
  static TextInputClientMac* GetInstance();

  // Each of the three methods mentioned above has an associated pair of methods
  // to get data from the renderer. The Get*() methods block the calling thread
  // (always the UI thread) with a short timeout after the async message has
  // been sent to the renderer to lookup the information needed to respond to
  // the system. The Set*AndSignal() methods store the looked up information in
  // this service and signal the condition to allow the Get*() methods to
  // unlock and return that stored value.
  //
  // Returns UINT32_MAX if the request times out or is not completed.
  uint32_t GetCharacterIndexAtPoint(ApplicationWindowHost* rwh,
                                    const gfx::Point& point);
  // Returns NSZeroRect if the request times out or is not completed. The result
  // is in WebKit coordinates.
  gfx::Rect GetFirstRectForRange(ApplicationWindowHost* rwh,
                                 const gfx::Range& range);

  // When the renderer sends the ViewHostMsg reply, the RenderMessageFilter will
  // call the corresponding method on the IO thread to unlock the condition and
  // allow the Get*() methods to continue/return.
  void SetCharacterIndexAndSignal(uint32_t index);
  void SetFirstRectAndSignal(const gfx::Rect& first_rect);

  typedef base::OnceCallback<
      void(const mac::AttributedStringCoder::EncodedString&, gfx::Point)>
      GetStringCallback;

  // This async method is invoked from ApplicationWindowHostViewCocoa's
  // -quickLookWithEvent:, when the user taps a word using 3 fingers.
  // The reply callback will be invoked from the IO thread; the caller is
  // responsible for bouncing to the main thread if necessary.
  // The callback parameters provide the attributed word under the point and
  // the lower left baseline point of the text.
  void GetStringAtPoint(ApplicationWindowHost* rwh,
                        const gfx::Point& point,
                        GetStringCallback callback);

  // This is called on the IO thread when we get the renderer's reply for
  // GetStringAtPoint.
  void GetStringAtPointReply(
      const mac::AttributedStringCoder::EncodedString& string,
      const gfx::Point& point);

  // This async method is invoked when browser tries to retreive the text for
  // certain range and doesn't want to wait for the reply from blink.
  // The reply callback will be invoked from the IO thread; the caller is
  // responsible for bouncing to the main thread if necessary.
  // The callback parameters provide the attributed word under the point and
  // the lower left baseline point of the text.
  void GetStringFromRange(ApplicationWindowHost* rwh,
                          const gfx::Range& range,
                          GetStringCallback callback);

  // This is called on the IO thread when we get the renderer's reply for
  // GetStringFromRange.
  void GetStringFromRangeReply(
      const mac::AttributedStringCoder::EncodedString& string,
      const gfx::Point& point);

 private:
  friend struct base::DefaultSingletonTraits<TextInputClientMac>;
  TextInputClientMac();
  ~TextInputClientMac();

  // The critical sections that the Condition guards are in Get*() methods.
  // These methods lock the internal condition for use before the asynchronous
  // message is sent to the renderer to lookup the required information. These
  // are only used on the UI thread.
  void BeforeRequest();
  // Called at the end of a critical section. This will release the lock and
  // condition.
  void AfterRequest();

  uint32_t character_index_;
  gfx::Rect first_rect_;

  base::Lock lock_;
  base::ConditionVariable condition_;

  // The callback when received IPC TextInputClientReplyMsg_GotStringAtPoint.
  GetStringCallback replyForPointHandler_;

  // The callback when received IPC TextInputClientReplyMsg_GotStringForRange.
  GetStringCallback replyForRangeHandler_;

  DISALLOW_COPY_AND_ASSIGN(TextInputClientMac);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_TEXT_INPUT_CLIENT_MAC_H_
