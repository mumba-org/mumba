// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

/*
 Note: Giving Oilpan is the norm in modern webkit/blink
 all the classes can now become structs giving we dont need 
 the RAII behaviour
 We should get ride of some wrappers on the C++ side too

 This is a big TODO for Web package and one that will make it more
 light on Swift and C++ side
*/

public enum CursorAlignOnScroll : Int { 
    case ifNeeded = 0
    case always = 1
}

public enum SetSelectionBy : Int { 
    case system = 0
    case user = 1
}

public enum ScrollAlignment : Int {
    case alignCenterIfNeeded = 0
    case alignToEdgeIfNeeded = 1
    case alignCenterAlways = 2
    case alignTopAlways = 3
    case alignBottomAlways = 4
    case alignLeftAlways = 5
    case alignRightAlways = 6
}

public enum RevealExtentOption : Int { 
    case revealExtent = 0
    case doNotRevealExtent = 1
}

public enum SelectionModifyAlteration : Int { 
    case Move
    case Extend 
}

public enum SelectionModifyVerticalDirection : Int { 
    case Up
    case Down 
}

public enum SelectionModifyDirection : Int { 
    case Backward 
    case Forward 
    case Left 
    case Right 
}

public struct SetSelectionOptions {
    public var cursorAlignOnScroll = CursorAlignOnScroll.ifNeeded
    public var doNotClearStrategy: Bool = false
    public var doNotSetFocus: Bool = false
    public var granularity: TextGranularity = TextGranularity.Character
    public var setSelectionBy: SetSelectionBy = SetSelectionBy.system
    public var shouldClearTypingStyle: Bool = false
    public var shouldCloseTyping: Bool = false
    public var shouldShowHandle: Bool = false
    public var shouldShrinkNextTap: Bool = false
    public var isDirectional: Bool = false
}

public struct TextIteratorBehavior {
    public var collapseTrailingSpace: Bool
    public var doesNotBreakAtReplacedElement: Bool
    public var emitsCharactersBetweenAllVisiblePositions: Bool
    public var emitsImageAltText: Bool
    public var emitsSpaceForNbsp: Bool
    public var emitsObjectReplacementcharacter: Bool
    public var emitsOriginalText: Bool
    public var emitsSmallXForTextSecurity: Bool
    public var entersOpenShadowRoots: Bool
    public var entersTextControls: Bool
    public var excludeAutofilledValue: Bool
    public var forInnerText: Bool
    public var forSelectionToString: Bool
    public var forWindowFind: Bool
    public var ignoresStyleVisibility: Bool
    public var stopsOnFormControls: Bool
    public var doesNotEmitSpaceBeyondRangeEnd: Bool
    public var skipsUnselectableContent: Bool
    public var suppressesNewlineEmission: Bool  
}

public struct WebFrameSelection {

    public var layoutSelectionStart: UInt? {
        var result: UInt32 = 0
        if _WebFrameSelectionGetLayoutSelectionStart(reference, &result) == 1 {
            return UInt(result)
        }
        return nil
    }

    public var layoutSelectionEnd: UInt? {
        var result: UInt32 = 0
        if _WebFrameSelectionGetLayoutSelectionEnd(reference, &result) == 1 {
            return UInt(result)
        }
        return nil
    }

    public var isAvailable: Bool {
        return _WebFrameSelectionGetIsAvailable(reference) != 0
    }

    public var document: WebDocument {
        let ref = _WebFrameSelectionGetDocument(reference)
        return WebDocument(reference: ref!)
    }

    public var frame: WebLocalFrame {
        let ref = _WebFrameSelectionGetLocalFrame(reference)
        return WebLocalFrame(reference: ref!)
    }

    public var rootEditableElementOrDocumentElement: WebElement {
        let ref = _WebFrameSelectionGetRootEditableElementOrDocumentElement(reference)
        return WebElement(reference: ref!)
    }

    public var frameCaret : WebFrameCaret {
        let ref = _WebFrameSelectionGetFrameCaret(reference)
        return WebFrameCaret(reference: ref!)
    }

    public var needsLayoutSelectionUpdate: Bool {
        return _WebFrameSelectionNeedsLayoutSelectionUpdate(reference) != 0
    }

    public var absoluteCaretBounds: IntRect {
        var x: CInt = 0
        var y: CInt = 0
        var w: CInt = 0
        var h: CInt = 0
        _WebFrameSelectionGetAbsoluteCaretBounds(reference, &x, &y, &w, &h)
        return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
    }

    public var granularity: TextGranularity {
        return TextGranularity(rawValue: Int(_WebFrameSelectionGetGranularity(reference)))!
    }

    public var selection: WebSelection {
        let ref = _WebFrameSelectionGetSelection(reference)
        return WebSelection(reference: ref!)
    }

    public var isDirectional: Bool {
        return _WebFrameSelectionGetIsDirectional(reference) != 0
    }

    public var selectionHasFocus: Bool {
        return _WebFrameSelectionGetSelectionHasFocus(reference) != 0
    }

    public var frameIsFocused: Bool {
        get {
            return _WebFrameSelectionGetFrameIsFocused(reference) != 0
        }
        set {
            _WebFrameSelectionSetFrameIsFocused(reference, newValue ? 1 : 0)
        }
    }
    
    public var frameIsFocusedAndActive: Bool {
        return _WebFrameSelectionGetFrameIsFocusedAndActive(reference) != 0
    }

    public var documentCachedRange: WebRange? {
        let ref = _WebFrameSelectionGetDocumentCachedRange(reference)
        if ref == nil {
            return nil
        }
        return WebRange(reference: ref!)
    }

    public var isHidden: Bool {
        return _WebFrameSelectionGetIsHidden(reference) != 0
    }

    public var isHandleVisible: Bool {
        return _WebFrameSelectionGetIsHandleVisible(reference) != 0
    }

    public var shouldShrinkNextTap: Bool {
        return _WebFrameSelectionGetShouldShrinkNextTap(reference) != 0
    }

    public var shouldShowBlockCursor: Bool {
        get {
            return _WebFrameSelectionGetShouldShowBlockCursor(reference) != 0
        }
        set {
            _WebFrameSelectionSetShouldShowBlockCursor(reference, newValue ? 1 : 0)
        }
    }

    public var isCaretBlinkingSuspended: Bool {
        get {
            return _WebFrameSelectionGetIsCaretBlinkingSuspended(reference) != 0
        }
        set {
            _WebFrameSelectionSetIsCaretBlinkingSuspended(reference, newValue ? 1: 0)
        }
    }

    public var selectedHTMLForClipboard: String {
        var len: CInt = 0
        let cstr = _WebFrameSelectionGetSelectedHTMLForClipboard(reference, &len)
        return cstr == nil ? 
            String() : 
            String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }
  
    public var selectedText: String {
        var len: CInt = 0
        let cstr = _WebFrameSelectionGetSelectedText(reference, &len)
        return cstr == nil ? 
            String() : 
            String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!        
    }

    public var selectedTextForClipboard: String {
        var len: CInt = 0
        let cstr = _WebFrameSelectionGetSelectedTextForClipboard(reference, &len)
        return cstr == nil ? 
            String() : 
            String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }


    // This returns last layouted selection bounds of LayoutSelection rather than
    // SelectionEditor keeps.
    public var absoluteUnclippedBounds: IntRect {
        var x: CInt = 0
        var y: CInt = 0
        var w: CInt = 0
        var h: CInt = 0
        _WebFrameSelectionGetAbsoluteUnclippedBounds(reference, &x, &y, &w, &h)
        return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
    }

    internal var reference: WebFrameSelectionRef

    internal init(reference: WebFrameSelectionRef) {
        self.reference = reference
    }

    public func characterIndexForPoint(_ point: IntPoint) -> Int {
        return Int(_WebFrameSelectionGetCharacterIndexForPoint(reference, CInt(point.x), CInt(point.y)))
    }

    public func moveCaretSelection(point p: IntPoint) {
        _WebFrameSelectionMoveCaretSelection(reference, CInt(p.x), CInt(p.y))
    }

    public func setSelection(_ selection: WebSelection, options: SetSelectionOptions) {
        _WebFrameSelectionSetSelection(reference, 
            selection.reference,
            CInt(options.cursorAlignOnScroll.rawValue),
            options.doNotClearStrategy ? 1 : 0,
            options.doNotSetFocus ? 1 : 0,
            CInt(options.granularity.rawValue),
            CInt(options.setSelectionBy.rawValue),
            options.shouldClearTypingStyle ? 1 : 0,
            options.shouldCloseTyping ? 1 : 0,
            options.shouldShowHandle ? 1 : 0,
            options.shouldShrinkNextTap ? 1 : 0,
            options.isDirectional ? 1 : 0)
    }
    
    public func setSelectionAndEndTyping(_ selection: WebSelection) {
        _WebFrameSelectionSetSelectionAndEndTyping(reference, selection.reference)
    }
    
    public func selectAll(by: SetSelectionBy) {
        _WebFrameSelectionSelectAllBy(reference, CInt(by.rawValue))
    }
    
    public func selectAll() {
        _WebFrameSelectionSelectAll(reference)
    }
    
    public func selectSubString(element: WebElement, offset: Int, count: Int) {
        _WebFrameSelectionSelectSubString(reference, element.reference, CInt(offset), CInt(count))
    }
    
    public func clear() {
        _WebFrameSelectionClear(reference)
    }

    public func selectFrameElementInParentIfFullySelected() {
        _WebFrameSelectionSelectFrameElementInParentIfFullySelected(reference)
    }

    public func contains(point p: IntPoint) -> Bool {
        return _WebFrameSelectionContains(reference, CInt(p.x), CInt(p.y)) != 0
    }

    public func modify(
        alteration: SelectionModifyAlteration,
        direction: SelectionModifyDirection,
        granularity: TextGranularity,
        by: SetSelectionBy) -> Bool {
        return _WebFrameSelectionModify(reference,
            CInt(alteration.rawValue),
            CInt(direction.rawValue),
            CInt(granularity.rawValue),
            CInt(by.rawValue)) != 0
    }

    public func moveRangeSelectionExtent(point: IntPoint) {
        _WebFrameSelectionMoveRangeSelectionExtent(reference, CInt(point.x), CInt(point.y))
    }

    public func moveRangeSelection(basePoint: IntPoint,
                                   extentPoint: IntPoint,
                                   granularity: TextGranularity) {
        _WebFrameSelectionMoveRangeSelection(reference,
            CInt(basePoint.x), 
            CInt(basePoint.y),
            CInt(extentPoint.x), 
            CInt(extentPoint.y),
            CInt(granularity.rawValue))
    }

    public func commitAppearanceIfNeeded() {
        _WebFrameSelectionCommitAppearanceIfNeeded(reference)
    }

    public func setCaretVisible(_ visible: Bool) {
        _WebFrameSelectionSetCaretVisible(reference, visible ? 1 : 0)
    }

    // Focus
    public func pageActivationChanged() {
        _WebFrameSelectionPageActivationChanged(reference)
    }

    public func selectWordAroundCaret() -> Bool {
        return _WebFrameSelectionSelectWordAroundCaret(reference) != 0
    }

    public func setFocusedNodeIfNeeded() {
        _WebFrameSelectionSetFocusedNodeIfNeeded(reference)
    }

    public func notifyTextControlOfSelectionChange(by: SetSelectionBy) {
        _WebFrameSelectionNotifyTextControlOfSelectionChange(reference, CInt(by.rawValue))
    }

    public func selectedText(behavior: TextIteratorBehavior) -> String {
        var len: CInt = 0
        let cstr = _WebFrameSelectionGetSelectedTextWithOptions(reference, 
            behavior.collapseTrailingSpace ? 1 : 0,
            behavior.doesNotBreakAtReplacedElement ? 1 : 0,
            behavior.emitsCharactersBetweenAllVisiblePositions ? 1 : 0,
            behavior.emitsImageAltText ? 1 : 0,
            behavior.emitsSpaceForNbsp ? 1 : 0,
            behavior.emitsObjectReplacementcharacter ? 1 : 0,
            behavior.emitsOriginalText ? 1 : 0,
            behavior.emitsSmallXForTextSecurity ? 1 : 0,
            behavior.entersOpenShadowRoots ? 1 : 0,
            behavior.entersTextControls ? 1 : 0,
            behavior.excludeAutofilledValue ? 1 : 0,
            behavior.forInnerText ? 1 : 0,
            behavior.forSelectionToString ? 1 : 0,
            behavior.forWindowFind ? 1 : 0,
            behavior.ignoresStyleVisibility ? 1 : 0,
            behavior.stopsOnFormControls ? 1 : 0,
            behavior.doesNotEmitSpaceBeyondRangeEnd ? 1 : 0,
            behavior.skipsUnselectableContent ? 1 : 0,
            behavior.suppressesNewlineEmission ? 1 : 0,
            &len)
        if cstr == nil {
            return String()
        }
        return String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    // TODO(tkent): This function has a bug that scrolling doesn't work well in
    // a case of RangeSelection. crbug.com/443061
    public func revealSelection(
        alignment: ScrollAlignment = .alignCenterIfNeeded,
        revealExtent: RevealExtentOption = .doNotRevealExtent) {
        _WebFrameSelectionRevealSelection(reference, CInt(alignment.rawValue), CInt(revealExtent.rawValue))
    }

    public func setSelectionFromNone() {
        _WebFrameSelectionSetSelectionFromNone(reference)
    }

    public func updateAppearance() {
        _WebFrameSelectionUpdateAppearance(reference)
    }

    public func cacheRangeOfDocument(range: WebRange) {
        _WebFrameSelectionCacheRangeOfDocument(reference, range.reference)
    }

    public func clearDocumentCachedRange() {
        _WebFrameSelectionClearDocumentCachedRange(reference)
    }

    public func clearLayoutSelection() {
        _WebFrameSelectionClearLayoutSelection(reference)
    }
}