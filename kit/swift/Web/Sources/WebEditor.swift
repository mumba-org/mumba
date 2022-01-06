// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct WebEditor {

    public var canEdit: Bool {
        return _WebEditorCanEdit(reference) != 0
    }

    internal var reference: WebEditorRef
    internal weak var frame: WebLocalFrame!

    internal init(frame: WebLocalFrame, reference: WebEditorRef) {
        self.reference = reference
        self.frame = frame
    }

    public func handleKeyboardEvent(_ ev: WebKeyboardEvent) {
        _WebEditorHandleKeyboardEvent(reference, frame.reference, ev.reference)
    }
}