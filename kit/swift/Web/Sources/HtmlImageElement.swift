// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public enum ImageDecodeState : Int {
    case Init
    case PendingLoad
    case Dispatched
    case DecodingError
}

public typealias ImageDecodeCallback = (_: ImageDecodeState) -> Void

public class HtmlImageElement : HtmlElement {

    public var x: Int {
        return Int(_HTMLImageElementGetX(reference))
    }

    public var y: Int {
        return Int(_HTMLImageElementGetY(reference))
    }
    
    public var width: Int {
        get {
            return Int(_HTMLImageElementGetWidth(reference))
        } 
        set {
            _HTMLImageElementSetWidth(reference, CInt(newValue))
        }
    }

    public var height: Int {
        get {
            return Int(_HTMLImageElementGetHeight(reference))
        }
        set {
            _HTMLImageElementSetHeight(reference, CInt(newValue))
        }
    }
    
    public var naturalWidth: Int {
        return Int(_HTMLImageElementGetNaturalWidth(reference))
    }
    
    public var naturalHeight: Int {
        return Int(_HTMLImageElementGetNaturalHeight(reference))
    }

    public var layoutBoxWidth: Int {
        return Int(_HTMLImageElementGetLayoutBoxWidth(reference))
    }

    public var layoutBoxHeight: Int {
        return Int(_HTMLImageElementGetLayoutBoxHeight(reference))
    }

    public var currentSrc: String {
        var len: CInt = 0
        guard let ref = _HTMLImageElementGetCurrentSrc(reference, &len) else {
            return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var isServerMap: Bool {
        return _HTMLImageElementIsServerMap(reference) != 0
    }

    public var altText: String {
        var len: CInt = 0
        guard let ref = _HTMLImageElementGetAltText(reference, &len) else {
            return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var image: ImageSkia? {
        get {
            let ref = _HTMLImageElementGetImage(reference)
            return ref == nil ? nil : ImageSkia(reference: ref!)
        } 
        set {
            _HTMLImageElementSetImage(reference, newValue!.reference)
        }
    }

    public var isLoaded: Bool {
        return _HTMLImageElementIsLoaded(reference) != 0
    }

    public var isLoading: Bool {
        return _HTMLImageElementIsLoading(reference) != 0
    }

    public var errorOccurred: Bool {
        return _HTMLImageElementErrorOccurred(reference) != 0
    }

    public var loadFailedOrCancelled: Bool {
        return _HTMLImageElementLoadFailedOrCancelled(reference) != 0
    }

    public var src: String {
        get {
            var len: CInt = 0
            guard let ref = _HTMLImageElementGetSrc(reference, &len) else {
                return String()
            }
            return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
        }
        set {
            newValue.withCString { 
                _HTMLImageElementSetSrc(reference, $0)
            }
        }
    }

    public var complete: Bool {
        return _HTMLImageIsComplete(reference) != 0
    }

    public var hasPendingActivity: Bool {
        return _HTMLImageHasPendingActivity(reference) != 0
    }

    public var canContainRangeEndPoint: Bool {
        return _HTMLImageCanContainRangeEndPoint(reference) != 0
    }

    public var isCollapsed: Bool {
        return _HTMLImageIsCollapsed(reference) != 0
    }

    public var formOwner: HtmlFormElement? {
        let ref = _HTMLImageElementGetFormOwner(reference)
        return ref == nil ? nil : HtmlFormElement(reference: ref!)
    }

    public func setIsFallbackImage() {
        _HTMLImageSetIsFallbackImage(reference)
    }

    public func forceReload() {
        _HTMLImageForceReload(reference)
    }

    public func decode(_ decodeCallback: @escaping ImageDecodeCallback) {

    }

    public init(document: WebDocument) {
        super.init(reference: _HTMLImageElementCreate(document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }

}

extension WebElement {

  public func asHtmlImage() -> HtmlImageElement? {
    return asHtmlElement(to: HtmlImageElement.self)
  }

}