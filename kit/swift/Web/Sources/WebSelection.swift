// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public enum WebSelectionType : Int { 
    case noSelection = 0
    case caret = 1
    case range = 2
}

public struct WebSelection {

    public var anchorNode: WebNode? {
        let ref = _WebSelectionGetAnchorNode(reference)
        if ref == nil {
            return nil
        }
        return WebNode(reference: ref!)
    }

    public var anchorOffset: UInt64 {
        return _WebSelectionGetAnchorOffset(reference)
    }

    public var focusNode: WebNode? {
        let ref = _WebSelectionGetFocusNode(reference)
        if ref == nil {
            return nil
        }
        return WebNode(reference: ref!)
    }

    public var focusOffset: UInt64 {
        return _WebSelectionGetFocusOffset(reference)
    }

    public var baseNode: WebNode? {
        let ref = _WebSelectionGetBaseNode(reference)
        if ref == nil {
            return nil
        }
        return WebNode(reference: ref!)
    }
    
    public var baseOffset: UInt64 {
        return _WebSelectionGetBaseOffset(reference)
    }
    
    public var extentNode: WebNode? {
        let ref = _WebSelectionGetExtentNode(reference)
        if ref == nil {
            return nil
        }
        return WebNode(reference: ref!)
    }

    public var extentOffset: UInt64 {
        return _WebSelectionGetExtentOffset(reference)
    }

    public var rangeCount: UInt64 {
        return UInt64(_WebSelectionGetRangeCount(reference))
    }
    
    public var isCollapsed: Bool {
        return _WebSelectionGetIsCollapsed(reference) != 0
    }

    public var type: String {
        var len: CInt = 0
        let cstr = _WebSelectionGetType(reference, &len)
        return cstr == nil ? 
            String() : 
            String(bytesNoCopy: cstr!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    internal var reference: WebSelectionRef

    internal init(reference: WebSelectionRef) {
        self.reference = reference
    }

    public func getRangeAt(index: Int) -> WebRange? {
        let ref = _WebSelectionGetRangeAt(reference, CInt(index))
        if ref == nil {
            return nil
        }
        return WebRange(reference: ref!)
    }

    public func addRange(_ range: WebRange) {
        _WebSelectionAddRange(reference, range.reference)
    }

    public func removeRange(_ range: WebRange) {
        _WebSelectionRemoveRange(reference, range.reference)
    }

    public func removeAllRanges() {
        _WebSelectionRemoveAllRanges(reference)
    }

    public func empty() {
        _WebSelectionEmpty(reference)
    }

    public func collapse(node: WebNode, offset: UInt64 = 0) {
        _WebSelectionCollapse(reference, node.reference, offset)
    }

    //public func setPosition(node: WebNode, offset: UInt64 = 0) {
    //    _WebSelectionSetPosition(reference, node.reference, offset)
    //}

    public func collapseToStart() {
        _WebSelectionCollapseToStart(reference)
    }

    public func collapseToEnd() { 
        _WebSelectionCollapseToEnd(reference)
    }

    public func extend(node: WebNode, offset: UInt64 = 0) {
        _WebSelectionExtend(reference, node.reference, offset)
    }

    public func setBaseAndExtent(baseNode: WebNode, baseOffset: UInt64,
                                 extentNode: WebNode, extentOffset: UInt64) {
        _WebSelectionSetBaseAndExtent(reference, baseNode.reference, baseOffset,
            extentNode.reference, extentOffset)
    }

    public func selectAllChildren(node: WebNode) {
        _WebSelectionSelectAllChildren(reference, node.reference)
    }

    public func deleteFromDocument() {
        _WebSelectionDeleteFromDocument(reference)
    }

    public func containsNode(node: WebNode, allowPartialContainment: Bool = false) -> Bool {
        return _WebSelectionContainsNode(reference, node.reference, allowPartialContainment ? 1 : 0) != 0
    }

}