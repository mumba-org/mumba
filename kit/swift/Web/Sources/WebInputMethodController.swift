// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public enum WebConfirmCompositionBehavior : Int {
    case DoNotKeepSelection = 0
    case KeepSelection = 1
}

public struct WebInputMethodController {

    public var textInputInfo: WebTextInputInfo {
        var type: CInt = 0
        var flags: CInt = 0
        var value: UnsafeMutablePointer<Int8>?
        var valueLen: CInt = 0
        var sstart: CInt = 0
        var send: CInt = 0
        var cstart: CInt = 0
        var cend: CInt = 0
        var inputMode: CInt = 0

        _WebInputMethodControllerGetTextInputInfo(reference, &type, &flags, &value, &valueLen, &sstart, &send, &cstart, &cend, &inputMode)

        return WebTextInputInfo(
            type: WebTextInputType(rawValue: Int(type))!,
            flags: Int(flags),
            value: value != nil ? String(bytesNoCopy: value!, length: Int(valueLen), encoding: String.Encoding.utf8, freeWhenDone: true)! : String(),
            selectionStart: Int(sstart),
            selectionEnd: Int(send),
            compositionStart: Int(cstart),
            compositionEnd: Int(cend),
            inputMode: WebTextInputMode(rawValue: Int(inputMode))!
        )
    }

    public var computeWebTextInputNextPreviousFlags: Int {
        return Int(_WebInputMethodControllerComputeWebTextInputNextPreviousFlags(reference))
    }

    public var textInputType: WebTextInputType {
        return WebTextInputType(rawValue: Int(_WebInputMethodControllerGetTextInputType(reference)))!
    }

    public var selectionOffsets: TextRange {
        var start: CInt = 0
        var end: CInt = 0
        _WebInputMethodControllerGetSelectionOffsets(reference, &start, &end)
        return TextRange(start: Int(start), end: Int(end))
    }

    public var compositionRange: TextRange {
        let range = compositionEphemeralRange
        guard !range.isNull else {
            return TextRange()
        }
        let textRange = TextRange(start: Int(range.startOffset), end: Int(range.endOffset))
        let editable = frame.frameSelection.rootEditableElementOrDocumentElement
        editable.document!.updateStyleAndLayoutTreeIgnorePendingStylesheets()
        return TextRange.create(node: editable, range: textRange)
    }

    public var compositionEphemeralRange: WebRange {
        let ref = _WebInputMethodControllerGetCompositionEphemeralRange(reference, frame.reference)
        return WebRange(reference: ref!)
    }

    public var hasComposition: Bool {
        return _WebInputMethodControllerHasComposition(reference) != 0
    }
    
    public var compositionCharacterBounds: [IntRect]? {
        var result: [IntRect] = []
        let range = compositionRange
        if range.isEmpty {
            return nil
        }
        let characterCount = range.length
        let offset = range.start
        for i in 0..<characterCount {
            var rect = IntRect()
            guard frame.firstRectForCharacterRange(location: offset + i, length: 1, rect: &rect) else {
                print("Could not retrieve character rectangle at \(i)")
                return nil
            }
            result.append(rect)
        }
        return result
    }
    
    internal var reference: WebInputMethodControllerRef
    private weak var frame: WebLocalFrame!

    public init(frame: WebLocalFrame, reference: WebInputMethodControllerRef) {
        self.frame = frame
        self.reference = reference
    }

    public func setComposition(
        text: String,
        spans: [WebImeTextSpan],
        replacement: TextRange,
        selectionStart: Int,
        selectionEnd: Int) -> Bool {
        
        if frame.editor.canEdit && !hasComposition {
            return false
        }

        // Select the range to be replaced with the composition later.
        if !replacement.isNull {
            frame.selectRange(range: replacement, hide: true)
        }

        // We should verify the parent node of this IME composition node are
        // editable because JavaScript may delete a parent node of the composition
        // node. In this case, WebKit crashes while deleting texts from the parent
        // node, which doesn't exist any longer.
        let range = compositionEphemeralRange
        if !range.isNull {
            let node = range.startContainer
            frame.document.updateStyleAndLayoutTree()
            if node == nil || !WebNode.hasEditableStyle(node!) {
                return false
            }
        }

        frame.notifyUserActivation()

        setCompositionInternal(
            text: text, 
            spans: spans,
            selectionStart: selectionStart, 
            selectionEnd: selectionEnd)

        return text.isEmpty || hasComposition
    }

    public func commitText(text: String,
                           spans: [WebImeTextSpan],
                           replacement: TextRange,
                           caretPosition: Int) -> Bool {
        //WebLocalFrame.notifyUserActivation(frame, userActivationNotificationType.interaction)
        frame.notifyUserActivation()
        // if isEditContextActive {
        //     return activeEditContext.commitText(
        //         text, spans, replacement, caretPosition)
        // }
        // if let plugin = focusedPluginIfInputMethodSupported {
        //     return plugin.commitText(text, spans, replacement,
        //                              caretPosition)
        // }
        frame.document.updateStyleAndLayout()//DocumentUpdateReason.input)
        if !replacement.isNull {
            return replaceText(text, range: replacement)
        }
        return commitTextInternal(
            text: text,
            spans: spans,
            caretPosition: caretPosition)
    }

    public func replaceText(_ text: String, range: TextRange) -> Bool {
        text.withCString {
            return _WebInputMethodControllerReplaceText(reference, $0, CInt(range.start), CInt(range.end)) != 0
        }
    }

    public func finishComposingText(
        selectionBehavior: WebConfirmCompositionBehavior) -> Bool {
      return _WebInputMethodControllerFinishComposingText(reference, CInt(selectionBehavior.rawValue)) != 0
    }

    public func deleteSurroundingText(before: Int, after: Int) {
        _WebInputMethodControllerDeleteSurroundingText(reference, CInt(before), CInt(after))
    }

    public func deleteSurroundingTextInCodePoints(before: Int, after: Int) {
        _WebInputMethodControllerDeleteSurroundingTextInCodePoints(reference, CInt(before), CInt(after))
    }

    public func setCompositionFromExistingText(
        spans: [WebImeTextSpan],
        compositionStart: Int,
        compositionEnd: Int) {
        var type = ContiguousArray<CInt>()
        var start = ContiguousArray<CInt>()
        var end = ContiguousArray<CInt>()
        var thick = ContiguousArray<CInt>()
        var ucolor = ContiguousArray<CInt>()
        var bg = ContiguousArray<CInt>()

        for span in spans {
            type.append(CInt(span.type.rawValue))
            start.append(CInt(span.startOffset))
            end.append(CInt(span.endOffset))
            ucolor.append(CInt(span.underlineColor.value))
            bg.append(CInt(span.backgroundColor.value))
            thick.append(CInt(span.thickness.rawValue))
        }

        var typePtr: UnsafeMutableBufferPointer<CInt>?
        var startPtr: UnsafeMutableBufferPointer<CInt>?
        var endPtr: UnsafeMutableBufferPointer<CInt>?
        var ucolorPtr: UnsafeMutableBufferPointer<CInt>?
        var thickPtr: UnsafeMutableBufferPointer<CInt>?
        var bgPtr: UnsafeMutableBufferPointer<CInt>?

        type.withUnsafeMutableBufferPointer { typePtr = $0}
        start.withUnsafeMutableBufferPointer { startPtr = $0}
        end.withUnsafeMutableBufferPointer { endPtr = $0 }
        ucolor.withUnsafeMutableBufferPointer { ucolorPtr = $0 }
        thick.withUnsafeMutableBufferPointer { thickPtr = $0 }
        bg.withUnsafeMutableBufferPointer { bgPtr = $0 }

        _WebInputMethodControllerSetCompositionFromExistingText(
                reference, 
                typePtr!.baseAddress,
                startPtr!.baseAddress,
                endPtr!.baseAddress,
                ucolorPtr!.baseAddress,
                thickPtr!.baseAddress,
                bgPtr!.baseAddress,
                CInt(spans.count),
                CInt(compositionStart),
                CInt(compositionEnd))
    }

    public func cancelComposition() {
        _WebInputMethodControllerCancelComposition(reference)
    }

    public func setEditableSelectionOffsets(range: TextRange) -> Bool {
        return _WebInputMethodControllerSetEditableSelectionOffsets(reference, CInt(range.start), CInt(range.end)) != 0;
    }

    public func extendSelectionAndDelete(before: Int, after: Int) {
        _WebInputMethodControllerExtendSelectionAndDelete(reference, CInt(before), CInt(after))
    }

    public func createRangeForSelection(start: Int,
                                        end: Int,
                                        textLength: Int) -> TextRange {
        var s: CInt = 0
        var e: CInt = 0
        _WebInputMethodControllerCreateRangeForSelection(reference, CInt(start), CInt(end), CInt(textLength), &s, &e)
        return TextRange(start: Int(s), end: Int(e))
    }

    private func setCompositionInternal(
        text: String,
        spans: [WebImeTextSpan],
        selectionStart: Int,
        selectionEnd: Int) {
        var type = ContiguousArray<CInt>()
        var start = ContiguousArray<CInt>()
        var end = ContiguousArray<CInt>()
        var thick = ContiguousArray<CInt>()
        var ucolor = ContiguousArray<CInt>()
        var bg = ContiguousArray<CInt>()

        for span in spans {
            type.append(CInt(span.type.rawValue))
            start.append(CInt(span.startOffset))
            end.append(CInt(span.endOffset))
            ucolor.append(CInt(span.underlineColor.value))
            bg.append(CInt(span.backgroundColor.value))
            thick.append(CInt(span.thickness.rawValue))
        }

        var typePtr: UnsafeMutableBufferPointer<CInt>?
        var startPtr: UnsafeMutableBufferPointer<CInt>?
        var endPtr: UnsafeMutableBufferPointer<CInt>?
        var ucolorPtr: UnsafeMutableBufferPointer<CInt>?
        var thickPtr: UnsafeMutableBufferPointer<CInt>?
        var bgPtr: UnsafeMutableBufferPointer<CInt>?

        type.withUnsafeMutableBufferPointer { typePtr = $0}
        start.withUnsafeMutableBufferPointer { startPtr = $0}
        end.withUnsafeMutableBufferPointer { endPtr = $0 }
        ucolor.withUnsafeMutableBufferPointer { ucolorPtr = $0 }
        thick.withUnsafeMutableBufferPointer { thickPtr = $0 }
        bg.withUnsafeMutableBufferPointer { bgPtr = $0 }

        text.withCString {
            _WebInputMethodControllerSetComposition(
                reference, 
                $0,
                typePtr!.baseAddress,
                startPtr!.baseAddress,
                endPtr!.baseAddress,
                ucolorPtr!.baseAddress,
                thickPtr!.baseAddress,
                bgPtr!.baseAddress,
                CInt(spans.count),
                //CInt(replacement.start),
                //CInt(replacement.length),
                CInt(selectionStart),
                CInt(selectionEnd))
        }           
    }

    private func commitTextInternal(
        text: String,
        spans: [WebImeTextSpan],
        caretPosition: Int) -> Bool {
        var type = ContiguousArray<CInt>()
        var start = ContiguousArray<CInt>()
        var end = ContiguousArray<CInt>()
        var thick = ContiguousArray<CInt>()
        var ucolor = ContiguousArray<CInt>()
        var bg = ContiguousArray<CInt>()

        for span in spans {
            type.append(CInt(span.type.rawValue))
            start.append(CInt(span.startOffset))
            end.append(CInt(span.endOffset))
            ucolor.append(CInt(span.underlineColor.value))
            bg.append(CInt(span.backgroundColor.value))
            thick.append(CInt(span.thickness.rawValue))
        }

        var typePtr: UnsafeMutableBufferPointer<CInt>?
        var startPtr: UnsafeMutableBufferPointer<CInt>?
        var endPtr: UnsafeMutableBufferPointer<CInt>?
        var ucolorPtr: UnsafeMutableBufferPointer<CInt>?
        var thickPtr: UnsafeMutableBufferPointer<CInt>?
        var bgPtr: UnsafeMutableBufferPointer<CInt>?

        type.withUnsafeMutableBufferPointer { typePtr = $0}
        start.withUnsafeMutableBufferPointer { startPtr = $0}
        end.withUnsafeMutableBufferPointer { endPtr = $0 }
        ucolor.withUnsafeMutableBufferPointer { ucolorPtr = $0 }
        thick.withUnsafeMutableBufferPointer { thickPtr = $0 }
        bg.withUnsafeMutableBufferPointer { bgPtr = $0 }

        let result = text.withCString {
            return  _WebInputMethodControllerCommitText(
                reference, 
                $0,
                typePtr!.baseAddress,
                startPtr!.baseAddress,
                endPtr!.baseAddress,
                ucolorPtr!.baseAddress,
                thickPtr!.baseAddress,
                bgPtr!.baseAddress,
                CInt(spans.count),
                CInt(caretPosition)) == 0 ? false : true
        }
        return result    
    }
}

extension TextRange {

    public static func create(node: WebElement, range: TextRange) -> TextRange {
        var s: CInt = 0
        var e: CInt = 0
        _WebTextRangeCreateFromNodeAndRange(node.reference, CInt(range.start), CInt(range.end), &s, &e)
        return TextRange(start: Int(s), end: Int(e))
    }

}