// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "core/host/renderer_host/text_input_client_mac.h"

#include "base/memory/singleton.h"
#include "base/metrics/histogram_macros.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host.h"
#include "core/common/text_input_client_messages.h"

namespace host {

namespace {

// TODO(ekaramad): TextInputClientObserver, the renderer side of
// TextInputClientMac for each ApplicationWindowHost, expects to have a
// WebFrameWidget to use for handling these IPCs. However, for fullscreen flash,
// we end up with a PepperWidget. For those scenarios, do not send the IPCs. We
// need to figure out what features are properly supported and perhaps send the
// IPC to the parent widget of the plugin (https://crbug.com/663384).
bool SendMessageToRenderWidget(ApplicationWindowHost* widget,
                               IPC::Message* message) {
  if (!widget->delegate() ||
      widget == widget->delegate()->GetFullscreenApplicationWindowHost()) {
    delete message;
    return false;
  }

  DCHECK_EQ(widget->GetRoutingID(), message->routing_id());
  return widget->Send(message);
}
}

// The amount of time in milliseconds that the browser process will wait for a
// response from the renderer.
// TODO(rsesek): Using the histogram data, find the best upper-bound for this
// value.
const float kWaitTimeout = 1500;

TextInputClientMac::TextInputClientMac()
    : character_index_(UINT32_MAX), lock_(), condition_(&lock_) {}

TextInputClientMac::~TextInputClientMac() {
}

// static
TextInputClientMac* TextInputClientMac::GetInstance() {
  return base::Singleton<TextInputClientMac>::get();
}

void TextInputClientMac::GetStringAtPoint(ApplicationWindowHost* rwh,
                                          const gfx::Point& point,
                                          GetStringCallback callback) {
  // TODO(ekaramad): In principle, we are using the same handler regardless of
  // the |rwh| which requested this. We should track the callbacks for each
  // |rwh| individually so that one slow RWH will not end up clearing the
  // callback for another (https://crbug.com/643233).
  DCHECK(!replyForPointHandler_);
  replyForPointHandler_ = std::move(callback);
  ApplicationWindowHost* rwhi = ApplicationWindowHost::From(rwh);
  SendMessageToRenderWidget(
      rwhi, new TextInputClientMsg_StringAtPoint(rwhi->GetRoutingID(), point));
}

void TextInputClientMac::GetStringAtPointReply(
    const mac::AttributedStringCoder::EncodedString& string,
    const gfx::Point& point) {
  if (replyForPointHandler_) {
    std::move(replyForPointHandler_).Run(string, point);
  }
}

void TextInputClientMac::GetStringFromRange(ApplicationWindowHost* rwh,
                                            const gfx::Range& range,
                                            GetStringCallback callback) {
  DCHECK(!replyForRangeHandler_);
  replyForRangeHandler_ = std::move(callback);
  ApplicationWindowHost* rwhi = ApplicationWindowHost::From(rwh);
  SendMessageToRenderWidget(
      rwhi, new TextInputClientMsg_StringForRange(rwhi->GetRoutingID(), range));
}

void TextInputClientMac::GetStringFromRangeReply(
    const mac::AttributedStringCoder::EncodedString& string,
    const gfx::Point& point) {
  if (replyForRangeHandler_) {
    std::move(replyForRangeHandler_).Run(string, point);
  }
}

uint32_t TextInputClientMac::GetCharacterIndexAtPoint(ApplicationWindowHost* rwh,
                                                      const gfx::Point& point) {
  ApplicationWindowHost* rwhi = ApplicationWindowHost::From(rwh);
  if (!SendMessageToRenderWidget(rwhi,
                                 new TextInputClientMsg_CharacterIndexForPoint(
                                     rwhi->GetRoutingID(), point))) {
    return UINT32_MAX;
  }

  base::TimeTicks start = base::TimeTicks::Now();

  BeforeRequest();

  // http://crbug.com/121917
  base::ThreadRestrictions::ScopedAllowWait allow_wait;
  condition_.TimedWait(base::TimeDelta::FromMilliseconds(kWaitTimeout));
  AfterRequest();

  base::TimeDelta delta(base::TimeTicks::Now() - start);
  UMA_HISTOGRAM_LONG_TIMES("TextInputClient.CharacterIndex",
                           delta * base::Time::kMicrosecondsPerMillisecond);

  return character_index_;
}

gfx::Rect TextInputClientMac::GetFirstRectForRange(ApplicationWindowHost* rwh,
                                                   const gfx::Range& range) {
  ApplicationWindowHost* rwhi = ApplicationWindowHost::From(rwh);
  if (!SendMessageToRenderWidget(
          rwhi, new TextInputClientMsg_FirstRectForCharacterRange(
                    rwhi->GetRoutingID(), range))) {
    return gfx::Rect();
  }

  base::TimeTicks start = base::TimeTicks::Now();

  BeforeRequest();

  // http://crbug.com/121917
  base::ThreadRestrictions::ScopedAllowWait allow_wait;
  condition_.TimedWait(base::TimeDelta::FromMilliseconds(kWaitTimeout));
  AfterRequest();

  base::TimeDelta delta(base::TimeTicks::Now() - start);
  UMA_HISTOGRAM_LONG_TIMES("TextInputClient.FirstRect",
                           delta * base::Time::kMicrosecondsPerMillisecond);

  return first_rect_;
}

void TextInputClientMac::SetCharacterIndexAndSignal(uint32_t index) {
  lock_.Acquire();
  character_index_ = index;
  lock_.Release();
  condition_.Signal();
}

void TextInputClientMac::SetFirstRectAndSignal(const gfx::Rect& first_rect) {
  lock_.Acquire();
  first_rect_ = first_rect;
  lock_.Release();
  condition_.Signal();
}

void TextInputClientMac::BeforeRequest() {
  base::TimeTicks start = base::TimeTicks::Now();

  lock_.Acquire();

  base::TimeDelta delta(base::TimeTicks::Now() - start);
  UMA_HISTOGRAM_LONG_TIMES("TextInputClient.LockWait",
                           delta * base::Time::kMicrosecondsPerMillisecond);

  character_index_ = UINT32_MAX;
  first_rect_ = gfx::Rect();
}

void TextInputClientMac::AfterRequest() {
  lock_.Release();
}

}  // namespace host
