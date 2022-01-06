// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public struct WebFrameCaret {
  
    public var isActive: Bool {
        return _WebFrameCaretGetIsActive(reference) != 0 
    }

    public var isCaretBlinkingSuspended: Bool {
        get {
            return _WebFrameCaretGetIsCaretBlinkingSuspended(reference) != 0 
        }
        set {
            _WebFrameCaretSetIsCaretBlinkingSuspended(reference, newValue ? 1 : 0)
        }
    }

    public var absoluteCaretBounds: IntRect {
        var x: CInt = 0
        var y: CInt = 0
        var w: CInt = 0
        var h: CInt = 0
        _WebFrameCaretGetAbsoluteCaretBounds(reference, &x, &y, &w, &h)
        return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
    }

    public var shouldShowBlockCursor: Bool {
        get {
            return _WebFrameCaretGetShouldShowBlockCursor(reference) != 0 
        }
        set {
            _WebFrameCaretSetShouldShowBlockCursor(reference, newValue ? 1 : 0)
        }
    }

    internal var reference: WebFrameCaretRef

    internal init(reference: WebFrameCaretRef) {
        self.reference = reference
    }
  
    public func stopCaretBlinkTimer() {
        _WebFrameCaretStopCaretBlinkTimer(reference)
    }

    public func startBlinkCaret() {
        _WebFrameCaretStartBlinkCaret(reference)
    }

    public func setCaretVisibility(_ visibility: CaretVisibility) {
        _WebFrameCaretSetCaretVisibility(reference, CInt(visibility.rawValue))
    }

}