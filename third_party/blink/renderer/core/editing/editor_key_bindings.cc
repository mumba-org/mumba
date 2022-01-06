/*
 * Copyright (C) 2006, 2007 Apple, Inc.  All rights reserved.
 * Copyright (C) 2012 Google, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/editor.h"

#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/renderer/core/editing/commands/editor_command.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"

namespace blink {

bool Editor::HandleEditingKeyboardEvent(KeyboardEvent* evt) {
  DLOG(INFO) << "Editor::HandleEditingKeyboardEvent";
  const WebKeyboardEvent* key_event = evt->KeyEvent();
  // do not treat this as text input if it's a system key event
  if (!key_event || key_event->is_system_key) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: !key_event = " << key_event << " OR key_event->is_system_key = " << key_event->is_system_key << ". cancelling";
    return false;
  }

  String command_name = Behavior().InterpretKeyEvent(*evt);
  DLOG(INFO) << "HandleEditingKeyboardEvent: command_name = '" << command_name << "'";
  const EditorCommand command = this->CreateCommand(command_name);

  if (key_event->GetType() == WebInputEvent::kRawKeyDown) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: key_event.type == RawKeyDown";
    // WebKit doesn't have enough information about mode to decide how
    // commands that just insert text if executed via Editor should be treated,
    // so we leave it upon WebCore to either handle them immediately
    // (e.g. Tab that changes focus) or let a keypress event be generated
    // (e.g. Tab that inserts a Tab character, or Enter).
    if (command.IsTextInsertion() || command_name.IsEmpty()) {
      DLOG(INFO) << "HandleEditingKeyboardEvent: command.IsTextInsertion() = " << command.IsTextInsertion() << " OR command_name.IsEmpty() = " << command_name.IsEmpty() << ". cancelling";  
      return false;
    }
    DLOG(INFO) << "HandleEditingKeyboardEvent: executing command '" << command_name << "'";
    return command.Execute(evt);
  }

  DLOG(INFO) << "HandleEditingKeyboardEvent: executing command '" << command_name << "'";
  if (command.Execute(evt)) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: command '" << command_name << "' executed ok. returning true";
    return true;
  }

  if (!Behavior().ShouldInsertCharacter(*evt) || !CanEdit()) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: CanEdit() ? " << CanEdit() << " Behavior().ShouldInsertCharacter(*evt) ? " << Behavior().ShouldInsertCharacter(*evt) << ". returning false";
    return false;
  }

  const Element* const focused_element =
      frame_->GetDocument()->FocusedElement();
  if (!focused_element) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: focused_element = null. returning false";
    // We may lose focused element by |command.execute(evt)|.
    return false;
  }
  // We should not insert text at selection start if selection doesn't have
  // focus.
  if (!frame_->Selection().SelectionHasFocus()) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: frame_->Selection().SelectionHasFocus() = false. returning false";
    return false;
  }

  // Return true to prevent default action. e.g. Space key scroll.
  if (DispatchBeforeInputInsertText(evt->target()->ToNode(), key_event->text) !=
      DispatchEventResult::kNotCanceled) {
    DLOG(INFO) << "HandleEditingKeyboardEvent: DispatchBeforeInputInsertText != NotCancelled. returning true";
    return true;
  }

  DLOG(INFO) << "returning InsertText(key_event->text)";  
  return InsertText(key_event->text, evt);
}

void Editor::HandleKeyboardEvent(KeyboardEvent* evt) {
  // Give the embedder a chance to handle the keyboard event.
  if (frame_->Client()->HandleCurrentKeyboardEvent() ||
      HandleEditingKeyboardEvent(evt)) {
    evt->SetDefaultHandled();
  }
}

}  // namespace blink
