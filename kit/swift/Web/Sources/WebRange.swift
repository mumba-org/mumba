// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class WebRange {

    static let startToStart: UInt16 = 0
    static let startToEnd: UInt16 = 1
    static let endToEnd: UInt16 = 2
    static let endToStart: UInt16 = 3

    public var startContainer: WebNode? {
        let ref = _WebRangeGetStartContainer(reference)
        return ref == nil ? nil : WebNode(reference: ref!)
    }

    public var endContainer: WebNode? {
        let ref = _WebRangeGetEndContainer(reference)
        return ref == nil ? nil : WebNode(reference: ref!)
    }

    public var startOffset: UInt64 {
        return _WebRangeGetStartOffset(reference)
    }

    public var endOffset: UInt64 {
        return _WebRangeGetEndOffset(reference)
    }

    public var collapsed: Bool {
        return _WebRangeIsCollapsed(reference) != 0
    }

    public var commonAncestorContainer: WebNode? {
        let ref = _WebRangeGetCommonAncestorContainer(reference)
        return ref == nil ? nil : WebNode(reference: ref!)
    }

    public var clientRects: [IntRect] {
        var result: [IntRect] = []
        var x: UnsafeMutablePointer<CInt>?
        var y: UnsafeMutablePointer<CInt>?
        var w: UnsafeMutablePointer<CInt>?
        var h: UnsafeMutablePointer<CInt>?
        var count: CInt = 0
        _WebRangeGetClientRects(reference, &x, &y, &w, &h, &count)
        for i in 0..<Int(count) {
            result.append(IntRect(x: Int(x![i]), y: Int(y![i]), width: Int(w![i]), height: Int(h![i])))
        }
        free(x)
        free(y)
        free(w)
        free(h)
        return result
    }

    public var boundingClientRect: IntRect {
        var x: CInt = 0
        var y: CInt = 0
        var w: CInt = 0
        var h: CInt = 0
        _WebRangeGetBoundingClientRect(reference, &x, &y, &w, &h)
        return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
    }

    public var isNull: Bool {
        return _WebRangeGetStartContainer(reference) == nil
    }

    public static func create(document: WebDocument) -> WebRange {
        let ref = _WebRangeCreateWithDocument(document.reference)
        return WebRange(reference: ref!)
    }

    public static func create(
        document: WebDocument,
        startContainer: WebNode,
        startOffset: UInt16,
        endContainer: WebNode,
        endOffset: UInt16) -> WebRange {
      let ref = _WebRangeCreate(
        document.reference,
        startContainer.reference,
        startOffset,
        endContainer.reference,
        endOffset)
      return WebRange(reference: ref!)
    }

    internal var reference: WebRangeRef

    init(reference: WebRangeRef) {
        self.reference = reference
    }
  
    deinit {
        _WebRangeDestroy(reference)
    }

    public func setStart(node: WebNode, offset: UInt64) {
        _WebRangeSetStart(reference, node.reference, offset)
    }
    
    public func setEnd(node: WebNode, offset: UInt64) {
        _WebRangeSetEnd(reference, node.reference, offset)
    }
    
    public func setStartBefore(node: WebNode) {
        _WebRangeSetStartBefore(reference, node.reference)
    }
    
    public func setStartAfter(node: WebNode) {
        _WebRangeSetStartAfter(reference, node.reference)
    }
    
    public func setEndBefore(node: WebNode) {
        _WebRangeSetEndBefore(reference, node.reference)
    }
    
    public func setEndAfter(node: WebNode) {
        _WebRangeSetEndAfter(reference, node.reference)
    }
    
    public func collapse(toStart: Bool = false) {
        _WebRangeCollapse(reference, toStart ? 1 : 0)
    }
    
    public func selectNode(node: WebNode) {
        _WebRangeSelectNode(reference, node.reference)
    }
    
    public func selectNodeContents(node: WebNode) {
        _WebRangeSelectNodeContents(reference, node.reference)
    }

    public func compareBoundaryPoints(how: UInt16, sourceRange: WebRange) -> Int16 {
        return _WebRangeCompareBoundaryPoints(reference, how, sourceRange.reference)
    }

    public func deleteContents() {
        _WebRangeDeleteContents(reference)
    }

    public func extractContents() -> WebDocumentFragment {
        let ref = _WebRangeExtractContents(reference)
        return WebDocumentFragment(reference: ref!)
    }

    public func cloneContents() -> WebDocumentFragment {
        let ref = _WebRangeCloneContents(reference)
        return WebDocumentFragment(reference: ref!)
    }

    public func insertNode(node: WebNode) {
        _WebRangeInsertNode(reference, node.reference)
    }

    public func surroundContents(parent newParent: WebNode) {
        _WebRangeSurroundContents(reference, newParent.reference)
    }

    public func cloneRange() -> WebRange {
        let ref = _WebRangeCloneRange(reference)
        return WebRange(reference: ref!)
    }

    public func detach() {
        _WebRangeDetach(reference)
    }

    public func isPointInRange(node: WebNode, offset: UInt64) -> Bool {
        return _WebRangeIsPointInRange(reference, node.reference, offset) != 0
    }

    public func comparePoint(node: WebNode, offset: UInt64) -> Int16 {
        return _WebRangeComparePoint(reference, node.reference, offset)
    }

    public func intersectsNode(node: WebNode) -> Bool {
        return _WebRangeIntersectsNode(reference, node.reference) != 0
    }

    public func createContextualFragment(fragment: String) -> WebDocumentFragment {
        let ref = fragment.withCString {
            return _WebRangeCreateContextualFragment(reference, $0)
        }
        return WebDocumentFragment(reference: ref!)
    }

    public func expand(unit: String? = nil) {
        guard let unitStr = unit else {
            _WebRangeExpand(reference, nil)
            return
        }
        unitStr.withCString {
            _WebRangeExpand(reference, $0)
        }
    }
}