// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Javascript
import Base
import Compositor
import MumbaShims

public enum WebFrameLoadType : Int {
    case Standard = 0
    case BackForward = 1
    case Reload = 2
    case Same = 3
    case ReplaceCurrentItem = 4
    case InitialInChildFrame = 5
    case InitialHistoryLoad = 6
    case ReloadBypassingCache = 7
}

public enum ClientRedirectPolicy : Int {
  case NotClientRedirect = 0
  case ClientRedirect = 1
}

public struct WebFrameOwnerProperties {
    
    public enum ScrollingMode : Int {
        case Auto = 0 
        case AlwaysOff = 1
        case AlwaysOn = 2
    }

    public var scrollingMode: ScrollingMode = .Auto
    public var marginWidth: Int = -1
    public var marginHeight: Int = -1
    public var allowFullscreen: Bool = false
    public var allowPaymentRequest: Bool = false
    public var isDisplayNone: Bool = false

    public init() {}
}

public enum WebFrameStopFindAction : Int {
    case ClearSelection = 0
    case KeepSelection = 1
    case ActivateSelection = 2
}

public enum TextGranularity: Int {
    case `Character` = 0
    case Word = 1
    case Sentence = 2
    case Line = 3
    case Paragraph = 4
    case SentenceBoundary = 5
    case LineBoundary = 6
    case ParagraphBoundary = 7
    case DocumentBoundary = 8
}

public enum CaretVisibility : Int { 
    case Visible = 0
    case Hidden = 1
}

public class WebFrame {

    public enum LayoutAsTextControl: Int {
        case Normal = 0
        case Debug = 1
        case Printing = 2
        case TextWithLineTrees = 4
    }

	public var inShadowTree: Bool {
		return _WebFrameInShadowTree(reference) == 0 ? false : true
	}
    
    public var view: WebView {
        let ref = _WebFrameView(reference)
        return WebView(reference: ref!)
    }
    
    public var opener: WebFrame? { 
        
        get {
            let ref = _WebFrameGetOpener(reference)
            if ref == nil {
                return nil
            }
            return WebFrame(reference: ref!)
        }
        
        set {
            if let frame = newValue {
               _WebFrameSetOpener(reference, frame.reference)     
            } else {
               _WebFrameSetOpener(reference, nil) 
            }
        }

    }

    public var parent: WebFrame? {
        let ref = _WebFrameGetParent(reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    }
    
    public var top: WebFrame? { 
        let ref = _WebFrameGetTop(reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    }
    
    public var firstChild: WebFrame? { 
        let ref = _WebFrameGetFirstChild(reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    } 
    
    public var nextSibling: WebFrame? { 
        let ref = _WebFrameGetNextSibling(reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    }

    public var isLocalFrame: Bool {
        return _WebFrameIsWebLocalFrame(reference) == 0 ? false : true
    }
    
    public var isRemoteFrame: Bool {
        return _WebFrameIsWebRemoteFrame(reference) == 0 ? false : true
    }
        
    public internal(set) var reference: WebFrameRef!
    
    public static func createLocalMainFrame(view: WebView, client: WebLocalFrameClient, interfaceRegistry: WebInterfaceRegistry?) -> WebLocalFrame {
        return WebLocalFrame.createMainFrame(view: view, client: client, interfaceRegistry: interfaceRegistry)
    }

    public static func createRemote(scope: WebTreeScopeType, client: WebRemoteFrameClient) -> WebRemoteFrame {
        return WebRemoteFrame(scope: scope, client: client)
    }

    public static func scriptCanAccess(frame: WebFrame) -> Bool {
        return _WebFrameScriptCanAccess(frame.reference) == 0 ? false : true 
    }
    
    public static func fromFrameOwnerElement(element: WebElement) -> WebFrame? {
        let ref = _WebFrameFromFrameOwnerElement(element.reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    }
    
    internal init() {
        self.reference = nil
    }

    internal init(reference: WebFrameRef) {
        self.reference = reference
    }

    public func swap(frame: WebFrame) -> Bool {
        return _WebFrameSwap(reference, frame.reference) == 0 ? false : true
    }

    public func close() {
        _WebFrameClose(reference)
    }

    public func detach() {
        _WebFrameDetach(reference)
    }
        
    public func traverseNext() -> WebFrame? {
        let ref = _WebFrameTraverseNext(reference)
        return ref == nil ? nil : WebFrame(reference: ref!)
    }

}

extension WebFrame : Equatable {

    public static func ==(left: WebFrame, right: WebFrame) -> Bool {
        return _WebFrameIsEqual(left.reference, right.reference) != 0
    }

    public static func !=(left: WebFrame, right: WebFrame) -> Bool {
        return !(left == right)
    }
}