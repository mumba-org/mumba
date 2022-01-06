// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims
import Foundation

public enum NavigationReason : Int {
  case formSubmissionGet
  case formSubmissionPost
  case httpHeaderRefresh
  case scriptInitiated
  case metaTagRefresh
  case pageBlockInterstitial
  case reload
}

public enum DialogType : Int {
  case alert
  case confirm
  case prompt
  case beforeUnload
}

public enum ResourceType : Int {
  case document
  case stylesheet
  case image
  case media
  case font
  case script
  case texttrack
  case xhr
  case fetch
  case eventsource
  case websocket
  case manifest
  case other
}

public enum TransitionType : Int {
  case link
  case typed
  case autoBookmark
  case autoSubframe
  case manualFrame
  case generated
  case autoToplevel
  case formSubmit
  case reload
  case keyword
  case keywordGenerated
  case other
}

public enum ScreenOrientationType : Int {
  case portraitPrimary
  case portraitSecondary
  case landscapePrimary
  case landscapeSecondary
}

public enum CookieSameSite : Int {
  case strict
  case lax
}

public enum WindowState : Int {
  case normal
  case minimized
  case maximized
  case fullscreen
}

public enum FrameFormat : Int {
  case jpeg
  case png
}

public enum InspectMode : Int {
  case searchForNode
  case searchForUAShadowDom
  case none
}

public enum PseudoType : Int {
  case firstLine
  case firstLetter
  case before
  case after
  case backdrop
  case selection
  case firstLineInherited
  case scrollbar
  case scrollbarThumb
  case scrollbarButton
  case scrollbarTrack
  case scrollbarTrackPiece
  case scrollbarCorner
  case resizer
  case inputListButton
}

public enum ShadowRootType : Int {
  case userAgent
  case open
  case closed
}

public enum ServiceWorkerVersionRunningStatus : Int {
  case stopped
  case starting
  case running
  case stopping
}

public enum ServiceWorkerVersionStatus : Int {
  case new
  case installing
  case installed
  case activating
  case activated
  case redundant
}

public enum StorageType : Int {
  case appcache
  case cookies
  case fileSystems
  case indexedDB
  case localStorage
  case shaderCache
  case websql
  case serviceWorkers
  case cacheStorage
  case torrent
  case all
  case other
}

public enum ErrorReason : Int {
  case failed
  case aborted
  case timedout
  case accessDenied
  case connectionClosed
  case connectionReset
  case connectionRefused
  case connectionAbort
  case connectionFailed
  case nameNotResolved
  case internetDisconnected
  case addressUnreacheable
}

// The underlying connection technology that the browser is supposedly using.
public enum ConnectionType : Int {
  case none
  case cellular2g
  case cellular3g
  case cellular4g
  case bluetooth
  case ethernet
  case wifi
  case wimax
  case other
}

public enum ResourcePriority : Int {
  case verylow
  case low
  case medium
  case high
  case veryhigh
}

public enum ReferrerPolicy : Int {
  case unsafeUrl
  case noReferrerWhenDowngrade
  case noReferrer
  case origin
  case originWhenCrossOrigin
  case sameOrigin
  case strictOrigin
  case strictOriginWhenCrossOrigin
}

public enum MixedContentType : Int {
  case blockable
  case optionallyBlockable
  case none
}

public enum CSSMediaSource : Int {
  case mediaRule
  case importRule
  case linkedSheet
  case inlineSheet
}

public enum CertificateTransparencyCompliance : Int {
  case complianceUnknown
  case complianceNotCompliant
  case complianceCompliant
}

public enum BlockedReason : Int {
  case csp
  case mixedContent
  case origin
  case inspector
  case subresourceFilter
  case other
}

public enum SecurityState : Int {
  case unknown
  case neutral
  case insecure
  case secure
  case info
}

public enum InitiatorType : Int {
  case parser
  case script
  case preload
  case other
}

public enum AuthChallengeSource : Int {
  case server
  case proxy
}

public enum AuthChallengeResponseType : Int {
  case `default`
  case cancelAuth
  case provideCredentials
}

public enum KeyEventType : Int {
  case keyDown
  case keyUp
  case rawKeyDown
  case char
}

public enum MouseEventType : Int {
  case pressed
  case released
  case moved
  case wheel
}

public enum MouseButton : Int {
  case none
  case left
  case middle
  case right
}

public enum TouchEventType : Int {
  case start
  case end
  case move
  case cancel
}

public enum AXValueType : Int {
  case boolean
  case tristate
  case booleanOrUndefined
  case idref
  case idrefList
  case integer
  case node
  case nodeList
  case number
  case string
  case computedString
  case token
  case tokenList
  case domRelation
  case role
  case internalRole
  case valueUndefined
}

public enum AXValueSourceType : Int {
  case attribute
  case implicit
  case style
  case contents
  case placeholder
  case relatedElement
}

public enum AXValueNativeSourceType : Int {
  case figCaption
  case label
  case labelFor
  case labelWrapped
  case legend
  case tableCaption
  case tittle
  case other
}

public enum InterceptionStage : Int {
  case request
  case headersReceived
}

public enum GestureSourceType : Int {
  case `default`
  case touch
  case mouse
}

public enum AXPropertyName : Int {
  case busy
  case disabled
  case hidden
  case hiddenRoot
  case invalid
  case keyshortcuts
  case roleDescription
  case live
  case atomic
  case relevant
  case root
  case autocomplete
  case hasPopup
  case level
  case multiSelectable
  case orientation
  case multiline
  case readonly
  case `required`
  case valuemin
  case valuemax
  case valuetext
  case checked
  case expanded
  case modal
  case pressed
  case selected
  case activeDescendant
  case controls
  case describedBy
  case details
  case errorMessage
  case flowto
  case labelledBy
  case owns
}

public enum KeyType : Int {
  case number
  case string
  case date
  case array
}

public enum VirtualTimePolicy : Int {
  case advance
  case pause
  case pauseIfNetworkFetchesPending
}

public enum ScreenshotFormat : Int {
  case jpeg
  case png
}

public enum KeyPathType : Int {
  case null
  case string
  case array
}

public enum ScrollRectType : Int {
  case repaintsOnScroll
  case touchEventHandler
  case wheelEventHandler
}

// type StyleSheetId extends string
public enum StyleSheetOrigin : Int {
  case originInjected
  case originUserAgent
  case originInspector
  case originRegular
}

public enum AnimationType : Int {
  case cssTransition
  case cssAnimation
  case webAnimation
}

public enum TouchEventForMouseConfiguration : Int {
  case mobile
  case desktop
}

public enum Value {
  case null
  case bool(Bool)
  case int(Int32)
  case double(Double)
  case string(String)
  case binary([UInt8])
  case dictionary(Dictionary<AnyHashable,Any>)
  case list(Array<Any>)
}

public struct NavigationEntry {
  public var id: Int = 0
  public var url: String = String()
  public var userTypedUrl: String = String()
  public var title: String = String()
  public var transitionType: TransitionType = .other

  public mutating func decode(_ ptr: NavigationEntryPtrRef) {
    var cid: CInt = 0
    var curl: UnsafePointer<CChar>?
    var cuserTypedUrl: UnsafePointer<CChar>?
    var ctitle: UnsafePointer<CChar>?
    var ctransitionType: CInt = 0

    _NavigationEntryRead(
      ptr,
      &cid,
      &curl,
      &cuserTypedUrl,
      &ctitle,
      &ctransitionType)

    id = Int(cid)
    url = String(cString: curl!)
    userTypedUrl = String(cString: cuserTypedUrl!)
    title = String(cString: ctitle!)
    transitionType = TransitionType(rawValue: Int(ctransitionType))!
  }
}

public class Cookie {
  public var name: String = String()
  public var value: String = String()
  public var domain: String = String()
  public var path: String = String()
  public var expires: TimeTicks = TimeTicks()
  public var size: Int = 0
  public var httpOnly: Bool = false
  public var secure: Bool = false
  public var session: Bool = false
  public var sameSite: CookieSameSite = .strict

  public init() {}

  public func decode(_ ptr: CookiePtrRef) {
    var cname: UnsafePointer<CChar>?
    var cvalue: UnsafePointer<CChar>?
    var cdomain: UnsafePointer<CChar>?
    var cpath: UnsafePointer<CChar>?
    var cexpires: Int64 = 0
    var csize: CInt = 0
    var chttpOnly: CInt = 0
    var csecure: CInt = 0
    var csession: CInt = 0
    var csameSite: CInt = 0

    _CookieRead(
      ptr,
      &cname,
      &cvalue,
      &cdomain,
      &cpath,
      &cexpires,
      &csize,
      &chttpOnly,
      &csecure,
      &csession,
      &csameSite)

    self.name = String(cString: cname!)
    self.value = String(cString: cvalue!)
    self.domain = String(cString: cdomain!)
    self.path = String(cString: cpath!)
    self.expires = TimeTicks(microseconds: cexpires)
    self.size = Int(csize)
    self.httpOnly = chttpOnly != 0
    self.secure = csecure != 0
    self.session = csession != 0
    self.sameSite = CookieSameSite(rawValue: Int(csameSite))!
  }

}

public class CookieParam {
  public var name: String = String()
  public var value: String = String()
  public var url: String?
  public var domain: String?
  public var path: String?
  public var secure: Bool = false
  public var httpOnly: Bool = false
  public var sameSite: CookieSameSite = .strict
  public var expires: TimeTicks = TimeTicks()

  public init() {}
}

public class Frame {
  public var id: String = String()
  public var parentId: String = String()
  public var loaderId: String = String()
  public var name: String = String()
  public var url: String = String()
  public var securityOrigin: String = String()
  public var mimeType: String = String()
  public var unreachableUrl: String = String()

  public init() {}

  public func decode(_ ptr: FramePtrRef) {
    var cid: UnsafePointer<CChar>?
    var pid: UnsafePointer<CChar>?
    var lid: UnsafePointer<CChar>?
    var cname: UnsafePointer<CChar>?
    var curl: UnsafePointer<CChar>?
    var csecurityOrigin: UnsafePointer<CChar>?
    var cmimeType: UnsafePointer<CChar>?
    var cunreachableUrl: UnsafePointer<CChar>?

    _FrameRead(
      ptr,
      &cid,
      &pid,
      &lid,
      &cname,
      &curl,
      &csecurityOrigin,
      &cmimeType,
      &cunreachableUrl)
    
    self.id = String(cString: cid!)
    self.parentId = String(cString: pid!)
    self.loaderId = String(cString: lid!)
    self.name = String(cString: cname!)
    self.url = String(cString: curl!)
    self.securityOrigin = String(cString: csecurityOrigin!)
    self.mimeType = String(cString: cmimeType!)
    self.unreachableUrl = String(cString: cunreachableUrl!)
  }
}

public class FrameResource {
  public var url: String = String()
  public var type: ResourceType = .other
  public var mimeType: String = String()
  public var lastModified: Int = -1
  public var contentSize: Int = -1
  public var failed: Bool = false
  public var canceled: Bool = false

  public init() {}


  public func decode(_ ptr: FrameResourcePtrRef) {
    var curl: UnsafePointer<CChar>?
    var ctype: CInt = 0
    var cmimeType: UnsafePointer<CChar>?
    var clastModified: CInt = 0
    var ccontentSize: CInt = 0
    var cfailed: CInt = 0
    var ccanceled: CInt = 0

    _FrameResourceRead(
      ptr,
      &curl,
      &ctype,
      &cmimeType,
      &clastModified,
      &ccontentSize,
      &cfailed,
      &ccanceled)

    url = String(cString: curl!)
    type = ResourceType(rawValue: Int(ctype))!
    mimeType = String(cString: cmimeType!)
    lastModified = Int(clastModified)
    contentSize = Int(ccontentSize)
    failed = cfailed != 0
    canceled = ccanceled != 0
  }

}

public class FrameTree {
  public var frame: Frame = Frame()
  public var childFrames: [FrameTree] = []

  public init() {}

  public func decode(_ ptr: FrameTreePtrRef) {
    var cframe: FramePtrRef?
    var cchildFrames: UnsafeMutablePointer<FrameTreePtrRef?>?
    var cchildFramesCount: CInt = 0
    
    _FrameTreeRead(
      ptr,
      &cframe,
      &cchildFrames,
      &cchildFramesCount)
    
    if cframe != nil {
      frame.decode(cframe!)
    }

    if cchildFramesCount > 0 {
      for i in 0..<Int(cchildFramesCount) {
        let child = FrameTree()
        child.decode(cchildFrames![i]!)
        childFrames.append(child)
      }
    }

    _FrameTreeCleanup(
      ptr,
      cchildFrames,
      cchildFramesCount)
  }
}

public class FrameResourceTree {
  public var frame: Frame = Frame()
  public var childFrames: [FrameTree] = []
  public var resources: [FrameResource] = []

  public init() {}

  public func decode(_ ptr: FrameResourceTreePtrRef) {
    var cframe: FramePtrRef?
    var cchildFrames: UnsafeMutablePointer<FrameTreePtrRef?>?
    var cchildFramesCount: CInt = 0
    var cresources: UnsafeMutablePointer<FrameResourcePtrRef?>?
    var cresourcesCount: CInt = 0
    
    _FrameResourceTreeRead(
      ptr,
      &cframe,
      &cchildFrames,
      &cchildFramesCount,
      &cresources,
      &cresourcesCount)
    
    if cframe != nil {
      frame.decode(cframe!)
    }

    if cchildFramesCount > 0 {
      for i in 0..<Int(cchildFramesCount) {
        let child = FrameTree()
        child.decode(cchildFrames![i]!)
        childFrames.append(child)
      }
    }

    if cresourcesCount > 0 {
      for i in 0..<Int(cresourcesCount) {
        let resource = FrameResource()
        resource.decode(cresources![i]!)
        resources.append(resource)
      }
    }

    _FrameResourceTreeCleanup(
      ptr,
      cchildFrames,
      cchildFramesCount,
      cresources,
      cresourcesCount)
  }
}

public struct SearchMatch {
  public var lineNumber: Int = 0
  public var lineContent: String = String()

  public mutating func decode(_ ptr: SearchMatchPtrRef) {
    var clineNumber: CInt = 0
    var clineContent: UnsafePointer<CChar>?
    _SearchMatchRead(
      ptr,
      &clineNumber,
      &clineContent)
    self.lineNumber = Int(clineNumber)
    self.lineContent = String(cString: clineContent!)
  }
}

public struct Viewport {
  public var x: Int = 0
  public var y: Int = 0
  public var width: Int = 0
  public var height: Int = 0
  public var scale: Float = 0.0

  public mutating func decode(_ ptr: ViewportPtrRef) {
    var cx: CInt = 0
    var cy: CInt = 0
    var cw: CInt = 0
    var ch: CInt = 0
    _ViewportRead(ptr, &cx, &cy, &cw, &ch, &scale)
    x = Int(cx)
    y = Int(cy)
    width = Int(cw)
    height = Int(ch)
  }

}

public struct VisualViewport {
  public var offsetX: Int = 0
  public var offsetY: Int = 0
  public var pageX: Int = 0
  public var pageY: Int = 0
  public var clientWidth: Int = 0
  public var clientHeight: Int = 0
  public var scale: Float = 0.0

  public mutating func decode(_ ptr: VisualViewportPtrRef) {
    var ox: CInt = 0
    var oy: CInt = 0
    var px: CInt = 0
    var py: CInt = 0
    var cw: CInt = 0
    var ch: CInt = 0
    var sc: Float = 0.0

    _VisualViewportRead(
      ptr,
      &ox,
      &oy,
      &px,
      &py,
      &cw,
      &ch,
      &sc)
    self.offsetX = Int(ox)
    self.offsetY = Int(oy)
    self.pageX = Int(px)
    self.pageY = Int(py)
    self.clientWidth = Int(cw)
    self.clientHeight = Int(ch)
    self.scale = sc
  }
}

public struct LayoutViewport {
  public var pageX: Int = 0
  public var pageY: Int = 0
  public var clientWidth: Int = 0
  public var clientHeight: Int = 0

  public mutating func decode(_ ptr: LayoutViewportPtrRef) {
    var cx: CInt = 0
    var cy: CInt = 0
    var cw: CInt = 0
    var ch: CInt = 0
    
    _LayoutViewportRead(
      ptr,
      &cx,
      &cy,
      &cw,
      &ch)
    self.pageX = Int(cx)
    self.pageY = Int(cy)
    self.clientWidth = Int(cw)
    self.clientHeight = Int(ch)
  }
}

public struct ScreenOrientation {
  public var type: ScreenOrientationType = .portraitPrimary
  public var angle: Int = 0
}

public struct Bounds {
  public var left: Int = 0
  public var top: Int = 0
  public var width: Int = 0
  public var height: Int = 0
  public var windowState: WindowState = .normal

  public mutating func decode(_ ref: BoundsPtrRef) {
    var cl: CInt = 0
    var ct: CInt = 0
    var cw: CInt = 0
    var ch: CInt = 0
    var cs: CInt = 0

    _BoundsRead(
      ref,
      &cl,
      &ct,
      &cw,
      &ch,
      &cs)

    left = Int(cl)
    top = Int(ct)
    width = Int(cw)
    height = Int(ch)
    windowState = WindowState(rawValue: Int(cs))!
  }
}

public struct ScreencastFrameMetadata {
  public var offsetTop: Int = 0
  public var pageScaleFactor: Float = 0.0
  public var deviceWidth: Int = 0
  public var deviceHeight: Int = 0
  public var scrollOffsetX: Int = 0
  public var scrollOffsetY: Int = 0
  public var timestamp: Int = 0

  public mutating func decode(_ ptr: ScreencastFrameMetadataPtrRef) {
    var coffsetTop: CInt = 0
    var cdeviceWidth: CInt = 0
    var cdeviceHeight: CInt = 0
    var cscrollOffsetX: CInt = 0
    var cscrollOffsetY: CInt = 0
    var ctimestamp: CInt = 0

    _ScreencastFrameMetadataRead(
      ptr,
      &coffsetTop,
      &pageScaleFactor,
      &cdeviceWidth,
      &cdeviceHeight,
      &cscrollOffsetX,
      &cscrollOffsetY,
      &ctimestamp)

    offsetTop = Int(coffsetTop)
    deviceHeight = Int(cdeviceHeight)
    deviceWidth = Int(cdeviceWidth)
    scrollOffsetX = Int(cscrollOffsetX)
    scrollOffsetY = Int(cscrollOffsetY)
    timestamp = Int(timestamp)
  }
}

public struct RGBA {
  public var r: Int = 0
  public var g: Int = 0
  public var b: Int = 0
  public var a: Float = 0.0

  public init(r: Int, g: Int, b: Int, a: Float) {
    self.r = r
    self.g = g
    self.b = b
    self.a = a
  }
}

public class HighlightConfig {
  public var showInfo: Bool = false
  public var showRulers: Bool = false
  public var showExtensionLines: Bool = false
  public var displayAsMaterial: Bool = false
  public var contentColor: RGBA?
  public var paddingColor: RGBA?
  public var borderColor: RGBA?
  public var marginColor: RGBA?
  public var eventTargetColor: RGBA?
  public var shapeColor: RGBA?
  public var shapeMarginColor: RGBA?
  public var selectorList: String?
  public var cssGridColor: RGBA?

  public init() {}
}

public struct BackendNode {
  public var nodeType: Int = 0
  public var nodeName: String = String()
  public var backendNodeId: Int = 0

  public mutating func decode(_ ptr: BackendNodePtrRef) {
    var cnodeType: CInt = 0
    var cnodeName: UnsafePointer<CChar>?
    var cbackendNodeId: CInt = 0
    _BackendNodeRead(
      ptr, 
      &cnodeType,
      &cnodeName,
      &cbackendNodeId)
    self.nodeType = Int(cnodeType)
    self.nodeName = String(cString: cnodeName!)
    self.backendNodeId = Int(cbackendNodeId)
  }
}

public class DOMNode {
  public var nodeId: Int = -1
  public var parentId: Int = -1
  public var backendNodeId: Int = -1
  public var nodeType: Int = -1
  public var nodeName: Int = -1
  public var localName: Int = -1
  public var nodeValue: String = String()
  public var childNodeCount: Int = -1
  public var children: [DOMNode]?
  public var attributes: [String] = []
  public var documentUrl: String?
  public var baseUrl: String?
  public var publicId: String?
  public var systemId: String?
  public var internalSubset: String?
  public var xmlVersion: String?
  public var name: String?
  public var value: String?
  public var pseudoType: PseudoType = .firstLine
  public var shadowRootType: ShadowRootType = .userAgent
  public var frameId: String?
  public var contentDocument: DOMNode?
  public var shadowRoots: [DOMNode]?
  public var templateContent: DOMNode?
  public var pseudoElements: [DOMNode]?
  public var importedDocument: DOMNode?
  public var distributedNodes: [BackendNode]?
  public var isSvg: Bool = false

  public init() {}

  public func decode(_ ptr: DOMNodePtrRef) {
    var cnodeId: CInt = -1
    var cparentId: CInt = -1
    var cbackendNodeId: CInt = -1
    var cnodeType: CInt = -1
    var cnodeName: UnsafePointer<CChar>?
    var clocalName: UnsafePointer<CChar>?
    var cnodeValue: UnsafePointer<CChar>?
    var cchildNodeCount: CInt = -1
    var cattributes: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cattributesCount: CInt = -1
    var cdocumentUrl: UnsafePointer<CChar>?
    var cbaseUrl: UnsafePointer<CChar>?
    var cpublicId: UnsafePointer<CChar>?
    var csystemId: UnsafePointer<CChar>?
    var cinternalSubset: UnsafePointer<CChar>?
    var cxmlVersion: UnsafePointer<CChar>?
    var cname: UnsafePointer<CChar>?
    var cvalue: UnsafePointer<CChar>?
    var cpseudoType: CInt = -1
    var cshadowRootType: CInt = -1
    var cframeId: UnsafePointer<CChar>?
    var cisSvg: CInt = -1
    var cdnNodeTypes: UnsafeMutablePointer<CInt>?
    var cdnNodeNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cdnNodeIds: UnsafeMutablePointer<CInt>?
    var cdnNodesCount: CInt = -1

    _DOMNodeRead(
      ptr,
      &cnodeId,
      &cparentId,
      &cbackendNodeId,
      &cnodeType,
      &cnodeName,
      &clocalName,
      &cnodeValue,
      &cchildNodeCount,
      &cattributes,
      &cattributesCount,
      &cdocumentUrl,
      &cbaseUrl,
      &cpublicId,
      &csystemId,
      &cinternalSubset,
      &cxmlVersion,
      &cname,
      &cvalue,
      &cpseudoType,
      &cshadowRootType,
      &cframeId,
      &cisSvg,
      &cdnNodeTypes,
      &cdnNodeNames,
      &cdnNodeIds,
      &cdnNodesCount)
    //ccontentDocument: DOMNode?
    //cchildren: [DOMNode]?
    //cshadowRoots: [DOMNode]?
    //ctemplateContent: DOMNode?
    //cpseudoElements: [DOMNode]?
    //cimportedDocument: DOMNode?
  }
}

public class DOMSnapshotNode {
  public var nodeType: Int = -1
  public var nodeName: String = String()
  public var nodeValue: String = String()
  public var textValue: String?
  public var inputValue: String?
  public var inputChecked: Bool = false
  public var optionSelected: Bool = false
  public var backendNodeId: Int = -1
  public var childNodeIndexes: [Int]?
  public var attributes: [NameValue]?
  public var pseudoElementIndexes: [Int]?
  public var layoutNodeIndex: Int32 = -1
  public var documentUrl: String?
  public var baseUrl: String?
  public var contentLanguage: String?
  public var documentEncoding: String?
  public var publicId: String?
  public var systemId: String?
  public var frameId: String?
  public var contentDocumentIndex: Int = -1
  public var importedDocumentIndex: Int = -1
  public var templateContentIndex: Int = -1
  public var pseudoType: PseudoType = .firstLine
  public var shadowRootType: ShadowRootType = .userAgent
  public var isClickable: Bool = false
  public var eventListeners: [EventListener]?
  public var currentSourceUrl: String?

  public init() {

  }

  public func decode(_ ptr: DOMSnapshotNodePtrRef) {
    var cnodeType: CInt = 0
    var cnodeName: UnsafePointer<CChar>?
    var cnodeValue: UnsafePointer<CChar>?
    var ctextValue: UnsafePointer<CChar>?
    var cinputValue: UnsafePointer<CChar>?
    var cinputChecked: CInt = 0
    var coptionSelected: CInt = 0
    var cbackendNodeId: CInt = 0
    var cchildNodeIndexes: UnsafeMutablePointer<CInt>?
    var cchildNodeIndexesCount: CInt = 0
    var cattributesName: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cattributesValue: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cattributesCount: CInt = 0
    var cpseudoElementIndexes: UnsafeMutablePointer<CInt>?
    var cpseudoElementIndexesCount: CInt = 0
    var clayoutNodeIndex: CInt = 0
    var cdocumentUrl: UnsafePointer<CChar>?
    var cbaseUrl: UnsafePointer<CChar>?
    var ccontentLanguage: UnsafePointer<CChar>?
    var cdocumentEncoding: UnsafePointer<CChar>?
    var cpublicId: UnsafePointer<CChar>?
    var csystemId: UnsafePointer<CChar>?
    var cframeId: UnsafePointer<CChar>?
    var ccontentDocumentIndex: CInt = 0
    var cimportedDocumentIndex: CInt = 0
    var ctemplateContentIndex: CInt = 0
    var cpseudoType: CInt = 0
    var cshadowRootType: CInt = 0
    var cisClickable: CInt = 0
    var ccurrentSourceUrl: UnsafePointer<CChar>?

    _DOMSnapshotNodeRead(ptr, 
      &cnodeType,
      &cnodeName,
      &cnodeValue,
      &ctextValue,
      &cinputValue,
      &cinputChecked,
      &coptionSelected,
      &cbackendNodeId,
      &cchildNodeIndexes,
      &cchildNodeIndexesCount,
      &cattributesName,
      &cattributesValue,
      &cattributesCount,
      &cpseudoElementIndexes,
      &cpseudoElementIndexesCount,
      &clayoutNodeIndex,
      &cdocumentUrl,
      &cbaseUrl,
      &ccontentLanguage,
      &cdocumentEncoding,
      &cpublicId,
      &csystemId,
      &cframeId,
      &ccontentDocumentIndex,
      &cimportedDocumentIndex,
      &ctemplateContentIndex,
      &cpseudoType,
      &cshadowRootType,
      &cisClickable,
      &ccurrentSourceUrl)

    self.nodeType = Int(cnodeType)
    self.nodeName = String(cString: cnodeName!)
    self.nodeValue = String(cString: cnodeValue!)
    self.textValue = String(cString: ctextValue!)
    self.inputValue = String(cString: cinputValue!)

    self.inputChecked = cinputChecked != 0
    self.optionSelected = coptionSelected != 0
    self.backendNodeId = Int(cbackendNodeId)

    if cchildNodeIndexesCount > 0 {
      self.childNodeIndexes = []
      for i in 0..<Int(cchildNodeIndexesCount) {
        self.childNodeIndexes!.append(Int(cchildNodeIndexes![i]))
      }
    }

    if cattributesCount > 0 {
      self.attributes = []
      for i in 0..<Int(cattributesCount) {
        var value = NameValue()
        value.name = String(cString: cattributesName![i]!)
        value.value = String(cString: cattributesValue![i]!)
        self.attributes!.append(value)
      }
    }

    if cpseudoElementIndexesCount > 0 {
      self.pseudoElementIndexes = []
      for i in 0..<Int(cpseudoElementIndexesCount) {
        self.pseudoElementIndexes!.append(Int(cpseudoElementIndexes![i]))
      }
    }

    self.layoutNodeIndex = Int32(clayoutNodeIndex)
    self.documentUrl = cdocumentUrl == nil ? nil : String(cString: cdocumentUrl!)
    self.baseUrl = cbaseUrl == nil ? nil : String(cString: cbaseUrl!)
    self.contentLanguage = ccontentLanguage == nil ? nil : String(cString: ccontentLanguage!)
    self.documentEncoding = cdocumentEncoding == nil ? nil : String(cString: cdocumentEncoding!)
    self.publicId = cpublicId == nil ? nil : String(cString: cpublicId!)
    self.systemId = csystemId == nil ? nil : String(cString: csystemId!)
    self.frameId = cframeId == nil ? nil : String(cString: cframeId!)
    self.contentDocumentIndex = Int(ccontentDocumentIndex)
    self.importedDocumentIndex = Int(cimportedDocumentIndex)
    self.templateContentIndex = Int(ctemplateContentIndex)
    self.pseudoType = PseudoType(rawValue: Int(cpseudoType))!
    self.shadowRootType = ShadowRootType(rawValue: Int(cshadowRootType))!
    self.isClickable = cisClickable != 0
    self.currentSourceUrl = String(cString: ccurrentSourceUrl!)

    _DOMSnapshotNodeCleanup(ptr, cchildNodeIndexes, cattributesName, cattributesValue, cpseudoElementIndexes)
  }
}

public class ServiceWorkerRegistration {
  var registrationId: String = String()
  var scopeUrl: String = String()
  var isDeleted: Bool = false

  public init() {}

  public func decode(_ ptr: ServiceWorkerRegistrationPtrRef) {
    var id: UnsafePointer<CChar>?
    var url: UnsafePointer<CChar>?
    var deleted: CInt = 0
    _ServiceWorkerRegistrationRead(
      ptr, 
      &id,
      &url,
      &deleted)
    self.registrationId = String(cString: id!)
    self.scopeUrl = String(cString: url!)
    self.isDeleted = deleted != 0
  }
}

public class ServiceWorkerVersion {
  public var versionId: String = String()
  public var registrationId: String = String()
  public var scriptUrl: String = String()
  public var runningStatus: ServiceWorkerVersionRunningStatus = .stopped
  public var status: ServiceWorkerVersionStatus = .new
  public var scriptLastModified: Int = -1
  public var scriptResponseTime: Int64 = -1
  public var controlledClients: [Int]?
  public var targetId: Int = -1

  public init() {}

  public func decode(_ ptr: ServiceWorkerRegistrationPtrRef) {
    var vid: UnsafePointer<CChar>?
    var rid: UnsafePointer<CChar>?
    var url: UnsafePointer<CChar>?
    var crunningStatus: CInt = 0
    var cstatus: CInt = 0
    var cscriptLastModified: CInt = 0
    var cscriptResponseTime: Int64 = 0
    var ccontrolledClients: UnsafeMutablePointer<CInt>?
    var ccontrolledClientsCount: CInt = 0
    var ctargetId: CInt = 0
    
    _ServiceWorkerVersionRead(
      ptr, 
      &vid,
      &rid,
      &url,
      &crunningStatus,
      &cstatus,
      &cscriptLastModified,
      &cscriptResponseTime,
      &ccontrolledClients,
      &ccontrolledClientsCount,
      &ctargetId)

    self.versionId = String(cString: vid!)
    self.registrationId = String(cString: rid!)
    self.scriptUrl = String(cString: url!)
    self.runningStatus = ServiceWorkerVersionRunningStatus(rawValue: Int(crunningStatus))!
    self.status = ServiceWorkerVersionStatus(rawValue: Int(cstatus))!
    self.scriptLastModified = Int(cscriptLastModified)
    self.scriptResponseTime = cscriptResponseTime
    if ccontrolledClientsCount > 0 {
      self.controlledClients = []
      for i in 0..<Int(ccontrolledClientsCount) {
        self.controlledClients!.append(Int(ccontrolledClients![i]))
      }
    }
    self.targetId = Int(ctargetId)

    _ServiceWorkerVersionCleanup(
      ptr,
      ccontrolledClients)
  }
}

public class ServiceWorkerErrorMessage {
  public var errorMessage: String = String()
  public var registrationId: String = String()
  public var versionId: String = String()
  public var sourceUrl: String = String()
  public var lineNumber: Int = -1
  public var columnNumber: Int = -1

  public init() {}

  public func decode(_ ptr: ServiceWorkerErrorMessagePtrRef) {
    var msg: UnsafePointer<CChar>?
    var rid: UnsafePointer<CChar>?
    var vid: UnsafePointer<CChar>?
    var surl: UnsafePointer<CChar>?
    var line: CInt = 0
    var column: CInt = 0

    _ServiceWorkerErrorMessageRead(
      ptr, 
      &msg,
      &rid,
      &surl,
      &line,
      &column)

    self.errorMessage = String(cString: msg!)
    self.registrationId = String(cString: rid!)
    self.versionId = String(cString: vid!)
    self.sourceUrl = String(cString: surl!)
    self.lineNumber = Int(line)
    self.columnNumber = Int(column)
  }
}

public struct UsageForType {
  var storageType: StorageType
  var usage: Int
}

public struct GPUDevice {
  var vendorId: Int = -1
  var deviceId: Int = -1
  var vendorString: String = String()
  var deviceString: String = String()
}

public class GPUInfo {
  public var devices: [GPUDevice] = []
  public var auxAttributes: [String: String]?
  public var featureStatus: [String: String]?
  public var driverBugWorkarounds: [String] = []

  public init() {

  }

  public func decode(_ ref: GPUInfoPtrRef) {
    var vendors: UnsafeMutablePointer<CInt>?
    var devs: UnsafeMutablePointer<CInt>?
    var vendorStrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var devStrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var devCount: CInt = 0
    var auxStrKeys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var auxStrVals: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var auxStrKeysCount: CInt = 0
    var auxStrValsCount: CInt = 0
    var featStrKeys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var featStrVals: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var featStrKeysCount: CInt = 0
    var featStrValsCount: CInt = 0
    var workarounds: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var workaroundsCount: CInt = 0

    _GpuInfoRead(ref, 
                 vendors, 
                 devs, 
                 vendorStrs,
                 devStrs,  
                 &devCount, 
                 auxStrKeys,
                 &auxStrKeysCount,
                 auxStrVals, 
                 &auxStrValsCount, 
                 featStrKeys, 
                 &featStrKeysCount,
                 featStrVals,  
                 &featStrValsCount,
                 workarounds,
                 &workaroundsCount)

    for i in 0..<Int(devCount) {
      var dev = GPUDevice()
      dev.vendorId = Int(vendors![i])
      dev.deviceId = Int(vendors![i])
      dev.vendorString = String()
      devices.append(dev)
    }

    for i in 0..<Int(workaroundsCount) {
      driverBugWorkarounds.append(String(cString: workarounds![i]!))
    }

    for i in 0..<Int(auxStrKeysCount) {
      auxAttributes = [:]
      let key = String(cString: auxStrKeys![i]!)
      let value = String(cString: auxStrVals![i]!)
      auxAttributes![key] = value
    }

    for i in 0..<Int(featStrKeysCount) {
      featureStatus = [:]
      let key = String(cString: featStrKeys![i]!)
      let value = String(cString: featStrVals![i]!)
      featureStatus![key] = value
    }

    _GpuInfoClean(ref, vendors, devs)
  }
}

public class TargetInfo {
  public var targetId: String = String()
  public var type: String = String()
  public var title: String = String()
  public var url: String = String()
  public var attached: Bool = false
  public var openerId: String?
  public var browserContextId: String?

  public init() {}

  public func decode(_ ptr: TargetInfoPtrRef) {
    var ctargetId: UnsafePointer<CChar>?
    var ctype: UnsafePointer<CChar>?
    var ctitle: UnsafePointer<CChar>?
    var curl: UnsafePointer<CChar>?
    var cattached: CInt = 0
    var copenerId: UnsafePointer<CChar>?
    var cbrowserContextId: UnsafePointer<CChar>?
    
    _TargetInfoRead(ptr, &ctargetId, &ctype, &ctitle, &curl, &cattached, &copenerId, &cbrowserContextId)

    self.targetId = String(cString: ctargetId!)
    self.type = String(cString: ctype!)
    self.title = String(cString: ctitle!)
    self.url = String(cString: curl!)
    self.attached = cattached != 0
    self.openerId = String(cString: copenerId!)
    self.browserContextId = String(cString: cbrowserContextId!)
  }

}

public struct RemoteLocation {
  var host: String
  var port: Int
}

// Timing information for the request.
public struct ResourceTiming {
  var requestTime: Int64 = -1
  var proxyStart: Int64 = -1
  var proxyEnd: Int64 = -1
  var dnsStart: Int64 = -1
  var dnsEnd: Int64 = -1
  var connectStart: Int64 = -1
  var connectEnd: Int64 = -1
  var sslStart: Int64 = -1
  var sslEnd: Int64 = -1
  var workerStart: Int64 = -1
  var workerReady: Int64 = -1
  var sendStart: Int64 = -1
  var sendEnd: Int64 = -1
  var pushStart: Int64 = -1
  var pushEnd: Int64 = -1
  var receiveHeadersEnd: Int64 = -1
}

public class Request {
  public var url: String = String()
  public var method: String = String()
  public var headers: [String: String] = [:]
  public var postData: String?
  public var hasPostData: Bool = false
  public var mixedContentType: MixedContentType = .none
  public var initialPriority: ResourcePriority = .verylow
  public var referrerPolicy: ReferrerPolicy = .unsafeUrl
  public var isLinkPreload: Bool = false

  public init() {}
}

public class SignedCertificateTimestamp {
  public var status: String = String()
  public var origin: String = String()
  public var logDescription: String = String()
  public var logId: String = String()
  public var timestamp: Int64 = -1
  public var hashAlgorithm: String = String()
  public var signatureAlgorithm: String = String()
  public var signatureData: String = String()

  public init() {}
}

public class SecurityDetails {
  public var `protocol`: String = String()
  public var keyExchange: String = String()
  public var keyExchangeGroup: String?
  public var cipher: String = String()
  public var mac: String?
  public var certificateId: Int = -1
  public var subjectName: String = String()
  public var sanList: [String] = []
  public var issuer: String = String()
  public var validFrom: Int64 = -1
  public var validTo: Int64 = -1
  public var signedCertificateTimestampList: [SignedCertificateTimestamp] = []
  public var certificateTransparencyCompliance: CertificateTransparencyCompliance = .complianceUnknown

  public init() {}
}

public class Response {
  public var url: String = String()
  public var status: Int = -1
  public var statusText: String = String()
  public var headers: [String: String] = [:]
  public var headersText: String?
  public var mimeType: String = String()
  public var requestHeaders: [String: String]?
  public var requestHeadersText: String?
  public var connectionReused: Bool = false
  public var connectionId: Int = -1
  public var remoteIpAddress: String?
  public var remotePort: Int16 = -1
  public var fromDiskCache: Bool = false
  public var fromServiceWorker: Bool = false
  public var encodedDataLength: Int64 = -1
  public var timing: ResourceTiming = ResourceTiming()
  public var `protocol`: String?
  public var securityState: SecurityState = .unknown
  public var securityDetails: SecurityDetails?

  public init() {}
}

public class WebSocketRequest {
  public var headers: [String: String] = [:]

  public init() {}

  public func decode(_ ptr: WebSocketRequestPtrRef) {
    var cheadersKeys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cheadersValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cheadersCount: CInt = 0
    
    _WebSocketRequestRead(
      ptr, 
      &cheadersKeys,
      &cheadersValues,
      &cheadersCount)

    for i in 0..<Int(cheadersCount) {
      headers[String(cString: cheadersKeys![i]!)] = String(cString: cheadersValues![i]!)
    }
    
    _WebSocketRequestCleanup(
      ptr, 
      cheadersKeys,
      cheadersValues)
  
  }
}

public class WebSocketResponse {    
  public var status: Int = -1
  public var statusText: String = String()
  public var headers: [String: String] = [:]
  public var headersText: String?
  public var requestHeaders: [String: String]?
  public var requestHeadersText: String?

  public init() {}

  public func decode(_ ptr: WebSocketResponsePtrRef) {
    var cstatus: CInt = 0
    var cstatusText: UnsafePointer<CChar>?
    var cheadersText: UnsafePointer<CChar>?
    var crequestHeadersText: UnsafePointer<CChar>?
    var cheadersKeys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cheadersValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cheadersCount: CInt = 0
    var crequestHeadersKeys: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var crequestHeadersValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var crequestHeadersCount: CInt = 0
    
    _WebSocketResponseRead(
      ptr, 
      &cstatus,
      &cstatusText,
      &cheadersKeys,
      &cheadersValues,
      &cheadersCount,
      &cheadersText,
      &crequestHeadersKeys,
      &crequestHeadersValues,
      &crequestHeadersCount,
      &crequestHeadersText)

    status = Int(cstatus)
    statusText = String(cString: cstatusText!)
    if cheadersText != nil {
      headersText = String(cString: cheadersText!)
    }

    if crequestHeadersText != nil {
      requestHeadersText = String(cString: crequestHeadersText!)
    }

    for i in 0..<Int(cheadersCount) {
      headers[String(cString: cheadersKeys![i]!)] = String(cString: cheadersValues![i]!)
    }

    if crequestHeadersCount > 0 {
      requestHeaders = [:]
      for i in 0..<Int(crequestHeadersCount) {
        requestHeaders![String(cString: crequestHeadersKeys![i]!)] = String(cString: crequestHeadersValues![i]!)
      }
    }
    
    _WebSocketResponseCleanup(
      ptr, 
      cheadersKeys,
      cheadersValues,
      crequestHeadersKeys,
      crequestHeadersValues)
  }

}

public struct WebSocketFrame {
  public var opcode: Int = -1
  public var mask: Bool = false
  public var payloadData: String = String()

  public mutating func decode(_ ptr: WebSocketFramePtrRef) {
    var copcode: CInt = 0
    var cmask: CInt = 0
    var cpayloadData: UnsafePointer<CChar>?

    _WebSocketFrameRead(
      ptr, 
      &copcode,
      &cmask,
      &cpayloadData)
    self.opcode = Int(copcode)
    self.mask = cmask != 0
    self.payloadData = String(cString: cpayloadData!)
  }
}

public struct CachedResource {
  public var url: String = String()
  public var type: ResourceType = .other
  public var response: Response?
  public var bodySize: Int64 = -1
}

public struct Initiator {
  public var type: InitiatorType = .other
  //Runtime.StackTrace stack?;
  public var url: String?
  public var lineNumber: Int32 = -1

  public mutating func decode(_ ptr: InitiatorPtrRef) {
    var ctype: CInt = 0
    var curl: UnsafePointer<CChar>?
  
    _InitiatorRead(
      ptr, 
      &ctype,
      &curl,
      &lineNumber)
    self.type = InitiatorType(rawValue: Int(ctype))!
    self.url = curl == nil ? nil : String(cString: curl!)
  }
}

public class AuthChallenge {
  public var source: AuthChallengeSource = .server
  public var origin: String = String()
  public var scheme: String = String()
  public var realm: String = String()

  public init() {}

  public func decode(_ ptr: TargetInfoPtrRef) {
    var csource: CInt = 0
    var corigin: UnsafePointer<CChar>?
    var cscheme: UnsafePointer<CChar>?
    var crealm: UnsafePointer<CChar>?

    _AuthChallengeRead(ptr, &csource, &corigin, &cscheme, &crealm)

    self.source = AuthChallengeSource(rawValue: Int(csource))!
    self.origin = String(cString: corigin!)
    self.scheme = String(cString: cscheme!)
    self.realm = String(cString: crealm!)
  }

}

public class AuthChallengeResponse {
  public var respose: AuthChallengeResponseType = .default
  public var username: String?
  public var password: String?

  public init() {}
}

public struct RequestPattern {
  // Wildcards ('*' -> zero or more, '?' -> exactly one) are allowed. Escape character is
  // backslash. Omitting is equivalent to "*".
  public var urlPattern: String?
  // If set, only requests for matching resource types will be intercepted.
  public var resourceType: ResourceType
  // Stage at wich to begin intercepting requests. Default is Request.
  public var interceptionStage: InterceptionStage
}

public struct TouchPoint {
  public var x: Int
  public var y: Int
  public var radius_x: Int
  public var radius_y: Int
  public var rotation_angle: Int
  public var force: Int
  public var id: Int
}

public struct Bucket {
  public var low: Int = 0
  public var high: Int = 0
  public var count: Int = 0
}

public struct Histogram {
  public var name: String = String()
  public var sum: Int = 0
  public var count: Int = 0
  public var buckets: [Bucket] = []

  public mutating func decode(_ ref: HistogramPtrRef) {
    var cname: UnsafePointer<CChar>?
    var csum: CInt = 0
    var ccount: CInt = 0
    var lows: UnsafeMutablePointer<CInt>?
    var highs: UnsafeMutablePointer<CInt>?
    var counts: UnsafeMutablePointer<CInt>?
    var bucketCount: CInt = 0

    _HistogramRead(
      ref,
      &cname,
      &csum,
      &ccount,
      &lows,
      &highs,
      &counts,
      &bucketCount)

    for i in 0..<Int(bucketCount) {
      var b = Bucket()
      b.low = Int(lows![i])
      b.high = Int(highs![i])
      b.count = Int(counts![i])
      buckets.append(b)
    }

    name = String(cString: cname!)
    sum = Int(csum)
    count = Int(ccount)

    _HistogramClean(
      ref,
      lows,
      highs,
      counts)
  }

}

public class AXValueSource {
  public var type: AXValueSourceType = .attribute
  public var value: AXValue?
  public var attribute: String?
  public var attributeValue: AXValue?
  public var superseded: Bool = false
  public var nativeSource: AXValueNativeSourceType = .other
  public var nativeSourceValue: AXValue?
  public var invalid: Bool = false
  public var invalidReason: String?

  public init() {}
}

public struct AXRelatedNode {
  public var backendDomNodeId: String
  public var idref: String?
  public var text: String?
}
                          
public class AXProperty {
  public var name: AXPropertyName = .disabled
  public var value: AXValue = AXValue()

  public init() {}
}
                          
public class AXValue {
  public var value: Value = Value.null
  public var relateNodes: [AXRelatedNode]?
  public var sources: [AXValueSource]?

  public init() {}
}
                          
public class AXNode {
  public var nodeId: String = String()
  public var ignored: Bool = false
  public var ignoredReasons: [AXProperty]?
  public var role: AXValue?
  public var name: AXValue?
  public var description: AXValue?
  public var value: AXValue?
  public var properties: [AXProperty]?
  public var childIds: [String]?
  public var backendDomNodeId: String?

  public init() {}

  // FIXME: implement
  public func decode(_ ptr: AXNodePtrRef) {

  }
}

public class Key {
  public var type: KeyType = .number
  public var number: Int64 = -1
  public var str: String?
  public var date: Int64 = -1
  public var arr: [Key]?

  public init() {}
}

public class KeyRange {
  public var lower: Key?
  public var upper: Key?
  public var lowerOpen: Bool = false
  public var upperOpen: Bool = false

  public init() {}
}

// FIXME: this is fake
public struct RemoteObject {
  public var type: Int = 0
}

// values are serialized V8 types
public class IndexedDBDataEntry {
  public var key: String = String()
  public var primaryKey: String = String()
  public var value: String = String()

  public init() {}
  var ckey: UnsafePointer<CChar>?
  var cpkey: UnsafePointer<CChar>?
  var cvalue: UnsafePointer<CChar>?
    
  public func decode(_ ptr: IndexedDBDataEntryPtrRef) {
    _IndexedDBDataEntryRead(
      ptr,
      &ckey,
      &cpkey,
      &cvalue)
    self.key = String(cString: ckey!)
    self.primaryKey = String(cString: cpkey!)
    self.value = String(cString: cvalue!)
  }
}

public class KeyPath {
  public var type: KeyPathType = .null
  public var str: String?
  public var arr: [String] = []

  public init() {}
}

public class ObjectStoreIndex {
  public var name: String = String()
  public var keyPath: KeyPath = KeyPath()
  public var unique: Bool = false
  public var multiEntry: Bool = false

  public init() {}
}

public class ObjectStore {
  public var name: String = String()
  public var keyPath: KeyPath = KeyPath()
  public var autoIncrement: Bool = false
  public var indexes: [ObjectStoreIndex] = []

  public init() {}
}

public class DatabaseWithObjectStores {
  public var name: String = String()
  public var version: Int = -1
  public var objectStores: [ObjectStore] = []

  public init() {}

  public func decode(_ ptr: DatabaseWithObjectStoresPtrRef) {
    var cname: UnsafePointer<CChar>?
    var cversion: CInt = 0
    var objectNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var objectAutoIncrements: UnsafeMutablePointer<CInt>?
    var objectCount: CInt = 0
    var objectKeyPathTypes: UnsafeMutablePointer<CInt>?
    var objectKeyPathStrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var indexNames: UnsafeMutablePointer<UnsafeMutablePointer<UnsafePointer<CChar>?>?>?
    var indexUniques: UnsafeMutablePointer<UnsafeMutablePointer<CInt>?>?
    var indexMultientries: UnsafeMutablePointer<UnsafeMutablePointer<CInt>?>?
    var indexKeyPathTypes: UnsafeMutablePointer<UnsafeMutablePointer<CInt>?>?
    var indexKeyPathStrs: UnsafeMutablePointer<UnsafeMutablePointer<UnsafePointer<CChar>?>?>?
    var indexCount: UnsafeMutablePointer<CInt>?
    
    _DatabaseWithObjectStoresRead(
      ptr,
      &cname,
      &cversion,
      &objectNames,
      &objectAutoIncrements,
      &objectKeyPathTypes,
      &objectKeyPathStrs,
      &objectCount,
      &indexNames,
      &indexUniques,
      &indexMultientries,
      &indexKeyPathTypes,
      &indexKeyPathStrs,
      &indexCount)  

    self.name = String(cString: cname!)
    self.version = Int(cversion)

    for i in 0..<Int(objectCount) {
      let store = ObjectStore()
      store.name = String(cString: objectNames![i]!) 
      store.keyPath.type = KeyPathType(rawValue: Int(objectKeyPathTypes![i]))!
      if let cstr = objectKeyPathStrs![i] {
        store.keyPath.str = String(cString: cstr)
      }
      store.autoIncrement = objectAutoIncrements![i] != 0
      for x in 0..<Int(indexCount![i]) {
        let index = ObjectStoreIndex()
        index.name = String(cString: indexNames![i]![x]!)
        index.keyPath.type = KeyPathType(rawValue: Int(indexKeyPathTypes![i]![x]))!
        if let cstr = indexKeyPathStrs![i]![x] {
          index.keyPath.str = String(cString: cstr)
        }
        index.unique = indexUniques![i]![x] != 0
        index.multiEntry = indexMultientries![i]![x] != 0
        store.indexes.append(index)
      }
      self.objectStores.append(store)
    }

    _DatabaseWithObjectStoresClean(
      ptr,
      objectNames,
      objectAutoIncrements,
      objectKeyPathTypes,
      objectKeyPathStrs,
      indexNames,
      indexUniques,
      indexMultientries,
      indexKeyPathTypes,
      indexKeyPathStrs)
  }
}

public struct StorageId {
  public var securityOrigin: String = String()
  public var isLocalStorage: Bool = false

  public mutating func decode(_ ptr: StorageIdPtrRef) {
    var csecurityOrigin: UnsafePointer<CChar>?
    var clocalStorage: CInt = 0
    _StorageIdRead(ptr,
      &csecurityOrigin,
      &clocalStorage)
    self.securityOrigin = String(cString: csecurityOrigin!)
    self.isLocalStorage = clocalStorage != 0
  }
}

public class PictureTile {
  public var x: Int = 0
  public var y: Int = 0
  public var picture: String = String()

  public init() {}
}

public struct ScrollRect {
  public var rect: IntRect = IntRect()
  public var type: ScrollRectType = .repaintsOnScroll
}

public class StickyPositionConstraint {
  public var stickyBoxRect: IntRect = IntRect()
  public var containingBlockRect: IntRect = IntRect()
  public var nearestLayerShiftingStickyBox: String = String()
  public var nearestLayerShiftingContainingBlock: String = String()

  public init() {}
}

public class Layer {
  public var layerId: String = String()
  public var parentLayerId: String?
  public var backendNodeId: Int = 0
  public var offsetX: Int = 0
  public var offsetY: Int = 0
  public var width: Int = 0
  public var height: Int = 0
  public var transform: [Double]?
  public var anchorX: Int = 0
  public var anchorY: Int = 0
  public var anchorZ: Int = 0
  public var paintCount: Int = 0
  public var drawsContent: Bool = false
  public var invisible: Bool = false
  public var scrollRects: [ScrollRect]?
  public var stickyPositionConstraint: StickyPositionConstraint?

  public init() {}

  public func decode(_ ptr: LayerPtrRef) {
    var clayerId: UnsafePointer<CChar>?
    var playerId: UnsafePointer<CChar>?
    var cbackendNode: CInt = 0
    var coffsetx: CInt = 0
    var coffsety: CInt = 0
    var cwidth: CInt = 0
    var cheight: CInt = 0
    var ctransform: UnsafeMutablePointer<Double>?
    var ctransformCount: CInt = 0
    var canchorX: CInt = 0
    var canchorY: CInt = 0
    var canchorZ: CInt = 0
    var cpaintCount: CInt = 0
    var cdrawsContent: CInt = 0
    var cinvisible: CInt = 0
    // scrollRect
    var csx: UnsafeMutablePointer<CInt>?
    var csy: UnsafeMutablePointer<CInt>?
    var csw: UnsafeMutablePointer<CInt>?
    var csh: UnsafeMutablePointer<CInt>?
    var cstype: UnsafeMutablePointer<CInt>?
    var scrollRectCount: CInt = 0
    // StickyPosition
    var cspx: CInt = -1
    var cspy: CInt = -1
    var cspw: CInt = -1
    var csph: CInt = -1

    var cspcx: CInt = -1
    var cspcy: CInt = -1 
    var cspcw: CInt = -1
    var cspch: CInt = -1

    var cspStickyBox: UnsafePointer<CChar>?
    var cspContainingBlock: UnsafePointer<CChar>?

    _LayerRead(
      ptr,
      &clayerId,
      &playerId,
      &cbackendNode,
      &coffsetx,
      &coffsety,
      &cwidth,
      &cheight,
      &ctransform,
      &ctransformCount,
      &canchorX,
      &canchorY,
      &canchorZ,
      &cpaintCount,
      &cdrawsContent,
      &cinvisible,
      &csx,
      &csy,
      &csw,
      &csh,
      &cstype,
      &scrollRectCount,
      &cspx,
      &cspy,
      &cspw,
      &csph,
      &cspcx,
      &cspcy,
      &cspcw,
      &cspch,
      &cspStickyBox,
      &cspContainingBlock)

    self.layerId = String(cString: clayerId!)
    if playerId != nil {
      self.parentLayerId = String(cString: playerId!)
    }
    self.backendNodeId = Int(cbackendNode)
    self.offsetX = Int(coffsetx)
    self.offsetY = Int(coffsety)
    self.width = Int(cwidth)
    self.height = Int(cheight)
    if ctransformCount > 0 {
      self.transform = []
      for i in 0..<Int(ctransformCount) {
        self.transform!.append(ctransform![i])
      }
    }
    self.anchorX = Int(canchorX)
    self.anchorY = Int(canchorY)
    self.anchorZ = Int(canchorZ)
    self.paintCount = Int(cpaintCount)
    self.drawsContent = cdrawsContent != 0
    self.invisible = cinvisible != 0
    if scrollRectCount > 0 {
      self.scrollRects = []
      for i in 0..<Int(scrollRectCount) {
        var sr = ScrollRect()
        sr.rect.x = Int(csx![i])
        sr.rect.y = Int(csy![i])
        sr.rect.width = Int(csw![i])
        sr.rect.height = Int(csh![i])
        sr.type = ScrollRectType(rawValue: Int(cstype![i]))!
        self.scrollRects!.append(sr)
      }
    }
    if cspx != -1 {
      self.stickyPositionConstraint = StickyPositionConstraint()
      self.stickyPositionConstraint!.stickyBoxRect.x = Int(cspx)
      self.stickyPositionConstraint!.stickyBoxRect.y = Int(cspy)
      self.stickyPositionConstraint!.stickyBoxRect.width = Int(cspw)
      self.stickyPositionConstraint!.stickyBoxRect.height = Int(csph)
      self.stickyPositionConstraint!.containingBlockRect.x = Int(cspcx)
      self.stickyPositionConstraint!.containingBlockRect.y = Int(cspcy)
      self.stickyPositionConstraint!.containingBlockRect.width = Int(cspcw)
      self.stickyPositionConstraint!.containingBlockRect.height = Int(cspch)
      self.stickyPositionConstraint!.nearestLayerShiftingStickyBox = String(cString: cspStickyBox!)
      self.stickyPositionConstraint!.nearestLayerShiftingContainingBlock = String(cString: cspContainingBlock!)
    }

    _LayerCleanup(
      ptr,
      ctransform,
      ctransformCount,
      csx,
      csy,
      csw,
      csh,
      cstype,
      scrollRectCount)
  }

}

public struct ScreenshotParams {
  public var format: ScreenshotFormat = .png
  public var quality: Int32 = -1
}

public class KeyframesRule {
  public var name: String?
  public var keyframes: [KeyframeStyle] = []

  public init() {}

  public func decode(_ ptr: CSSKeyframesRulePtrRef) {
    var cname: UnsafePointer<CChar>?
    var coffsets: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var ceasing: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var stylesCount: CInt = 0
    _KeyframesRuleRead(
      ptr,
      &cname,
      &coffsets,
      &ceasing,
      &stylesCount)
    for i in 0..<Int(stylesCount) {
      let keyframe = KeyframeStyle()
      keyframe.offset = String(cString: coffsets![i]!)
      keyframe.easing = String(cString: ceasing![i]!)
      keyframes.append(keyframe)
    }
    if cname != nil {
      name = String(cString: cname!)
    }

    _KeyframesRuleCleanup(ptr, coffsets, ceasing, stylesCount)
  }
}

public class KeyframeStyle {
  public var offset: String = String()
  public var easing: String = String()

  public init() {

  }
}

public class AnimationEffect {
  public var delay: Int = -1
  public var endDelay: Int = -1
  public var iterationStart: Int = -1
  public var iterations: Int = -1
  public var duration: Int = -1
  public var direction: String = String()
  public var fill: String = String()
  public var backendNodeId: Int = -1
  public var keyframesRule: KeyframesRule?
  public var easing: String = String()

  public init() {}

  public func decode(_ ptr: AnimationEffectPtrRef) {
    var cdelay: CInt = -1
    var cendDelay: CInt = -1
    var citerationStart: CInt = -1
    var citerations: CInt = -1
    var cduration: CInt = -1
    var cdirection: UnsafePointer<CChar>?
    var cfill: UnsafePointer<CChar>?
    var cbackendNodeId: CInt = -1
    var ckeyframesRule: CSSKeyframesRulePtrRef?
    var ceasing: UnsafePointer<CChar>?

    _AnimationEffectRead(
      ptr, 
      &cdelay,
      &cendDelay,
      &citerationStart,
      &citerations,
      &cduration,
      &cdirection,
      &cfill,
      &cbackendNodeId,
      &ckeyframesRule,
      &ceasing)

    delay = Int(cdelay)
    endDelay = Int(cendDelay)
    iterationStart = Int(citerationStart)
    iterations = Int(citerations)
    duration = Int(cduration)
    direction = String(cString: cdirection!)
    fill = String(cString: cfill!)
    backendNodeId = Int(cbackendNodeId)
    if ckeyframesRule != nil {
      keyframesRule = KeyframesRule()
      keyframesRule!.decode(ckeyframesRule!)
    }
    easing = String(cString: ceasing!)
  }
}

public class Animation {
  public var id: String = String()
  public var name: String = String()
  public var pausedState: Bool = false
  public var playState: String = String()
  public var playbackRate: Int = -1
  public var startTime: TimeTicks = TimeTicks()
  public var currentTime: TimeTicks = TimeTicks()
  public var type: AnimationType = .webAnimation
  public var source: AnimationEffect?
  public var cssId: String?

  public init() {

  }

  public func decode(_ ptr: AnimationPtrRef) {
    var cid: UnsafePointer<CChar>?
    var cname: UnsafePointer<CChar>?
    var cpausedState: CInt = 0
    var cplayState: UnsafePointer<CChar>?
    var cplaybackRate: CInt = -1
    var cstartTime: Int64 = 0
    var ccurrentTime: Int64 = 0
    var ctype: CInt = 0
    var csource: AnimationEffectPtrRef?
    var ccssId: UnsafePointer<CChar>?

    _AnimationRead(
      ptr, 
      &cid,
      &cname,
      &cpausedState,
      &cplayState,
      &cplaybackRate,
      &cstartTime,
      &ccurrentTime,
      &ctype,
      &csource,
      &ccssId)

    id = String(cString: cid!)
    name = String(cString: cname!)
    pausedState = cpausedState != 0
    playState = String(cString: cplayState!)
    playbackRate = Int(cplaybackRate)
    startTime = TimeTicks(microseconds: cstartTime)
    currentTime = TimeTicks(microseconds: ccurrentTime)
    type = AnimationType(rawValue: Int(ctype))!
    if csource != nil {
      source = AnimationEffect()
      source!.decode(csource!)
    }
    if ccssId != nil {
      cssId = String(cString: ccssId!)
    }
  }
}

public class Database {
  public var id: String = String()
  public var domain: String = String()
  public var name: String = String()
  public var version: String = String()

  public init() {}

  public func decode(_ ptr: DatabasePtrRef) {
    var cid: UnsafePointer<CChar>?
    var cdom: UnsafePointer<CChar>?
    var cname: UnsafePointer<CChar>?
    var cversion: UnsafePointer<CChar>?

    _DatabaseRead(
      ptr, 
      &cid,
      &cdom,
      &cname,
      &cversion)
    
    self.id = String(cString: cid!)
    self.domain = String(cString: cdom!)
    self.name = String(cString: cname!)
    self.version = String(cString: cversion!)
  }
}

public struct SQLError {
  public var message: String = String()
  public var code: Int = -1

  public mutating func decode(_ ptr: ErrorPtrRef) {
    var cmessage: UnsafePointer<CChar>?
    var ccode: CInt = 0
    _SQLErrorRead(ptr, &cmessage, &ccode)
    message = String(cString: cmessage!)
    code = Int(ccode)
  }
}

public struct InlineTextBox {
  public var boundingBox: IntRect = IntRect()
  public var startCharacterIndex: Int = 0
  public var numCharacters: Int = 0
}

public class LayoutTreeNode {
  public var domNodeIndex: Int = -1
  public var boundingBox: IntRect = IntRect()
  public var layoutText: String?
  public var inlineTextNodes: [InlineTextBox]?
  public var styleIndex: Int = -1
  public var paintOrder: Int = -1

  public init() {}

  public func decode(_ ptr: LayoutTreeNodePtrRef) {
     var cdomNodeIndex: CInt = 0
     var cbbx: CInt = 0
     var cbby: CInt = 0
     var cbbw: CInt = 0
     var cbbh: CInt = 0
     var clayoutText: UnsafePointer<CChar>?
     var itbbx: UnsafeMutablePointer<CInt>?
     var itbby: UnsafeMutablePointer<CInt>?
     var itbbw: UnsafeMutablePointer<CInt>?
     var itbbh: UnsafeMutablePointer<CInt>?
     var itsci: UnsafeMutablePointer<CInt>?
     var itnc: UnsafeMutablePointer<CInt>?
     var itCount: CInt = 0
     var cstyleIndex: CInt = 0
     var cpaintOrder: CInt = 0

    _LayoutTreeNodeRead(
      ptr,
      &cdomNodeIndex,
      &cbbx,
      &cbby,
      &cbbw,
      &cbbh,
      &clayoutText,
      &itbbx,
      &itbby,
      &itbbw,
      &itbbh,
      &itsci,
      &itnc,
      &itCount,
      &cstyleIndex,
      &cpaintOrder)

    self.domNodeIndex = Int(cdomNodeIndex)
    self.boundingBox = IntRect(x: Int(cbbx), y: Int(cbby), width: Int(cbbw), height: Int(cbbh))
    if clayoutText != nil {
      self.layoutText = String(cString: clayoutText!)
    }
    self.styleIndex = Int(cstyleIndex)
    self.paintOrder = Int(cpaintOrder)

    if itCount > 0 {
      self.inlineTextNodes = []
      for i in 0..<Int(itCount) {
        var box = InlineTextBox()
        box.boundingBox = IntRect(x: Int(itbbx![i]), y: Int(itbby![i]), width: Int(itbbw![i]), height: Int(itbbh![i]))
        box.startCharacterIndex = Int(itsci![i])
        box.numCharacters = Int(itnc![i])
        self.inlineTextNodes!.append(box)
      }  
    }

    _LayoutTreeNodeCleanup(
      ptr,
      itbbx,
      itbby,
      itbbw,
      itbbh,
      itsci,
      itnc)
  }
}

public class ComputedStyle {
  public var properties: [NameValue] = []

  public init() {}

  public func decode(_ ptr: ComputedStylePtrRef) {
    var nameStrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var valuesStrs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var count: CInt = 0
    
    _ComputedStyleRead(
      ptr,
      &nameStrs,
      &valuesStrs,
      &count)

    for i in 0..<Int(count) {
      self.properties.append(NameValue(name: String(cString: nameStrs![i]!), value: String(cString: valuesStrs![i]!)))
    }
    
    _ComputedStyleCleanup(
      ptr,
      nameStrs,
      valuesStrs)
  }
}

public struct NameValue {
  public var name: String = String()
  public var value: String = String()
}

public class EventListener {
  public var type: String = String()
  public var useCapture: Bool = false
  public var passive: Bool = false
  public var once: Bool = false
  public var scriptId: String = String()
  public var lineNumber: Int = -1
  public var columnNumber: Int = -1
  public var handler: RemoteObject?
  public var originalHandler: RemoteObject?
  public var backendNodeId: Int = -1

  public init() {}
}

public class BoxModel {
  public var content: [Double] = []
  public var padding: [Double] = []
  public var border: [Double] = []
  public var margin: [Double] = []
  public var width: Int = -1
  public var height: Int = -1
  public var shapeOutside: ShapeOutsideInfo?

  public init() {}

  public func decode(_ ptr: BoxModelPtrRef) {
    var ccontent: UnsafeMutablePointer<Double>?
    var ccontentCount: CInt = 0
    var cpadding: UnsafeMutablePointer<Double>?
    var cpaddingCount: CInt = 0
    var cborder: UnsafeMutablePointer<Double>?
    var cborderCount: CInt = 0
    var cmargin: UnsafeMutablePointer<Double>?
    var cmarginCount: CInt = 0
    var cwidth: CInt = 0
    var cheight: CInt = 0
    var cshapeBounds: UnsafeMutablePointer<Double>?
    var cshapeBoundsCount: CInt = 0

    _BoxModelRead(
      ptr,
      &ccontent,
      &ccontentCount,
      &cpadding,
      &cpaddingCount,
      &cborder,
      &cborderCount,
      &cmargin,
      &cmarginCount,
      &cwidth,
      &cheight,
      &cshapeBounds,
      &cshapeBoundsCount)
    
    for i in 0..<Int(ccontentCount) {
      content.append(ccontent![i])
    }

    for i in 0..<Int(cpaddingCount) {
      padding.append(cpadding![i])
    }

    for i in 0..<Int(cborderCount) {
      border.append(cborder![i])
    }

    for i in 0..<Int(cmarginCount) {
      margin.append(cmargin![i])
    }

    self.width = Int(cwidth)
    self.height = Int(cheight)

    if cshapeBoundsCount > 0 {
      shapeOutside = ShapeOutsideInfo()
      for i in 0..<Int(cshapeBoundsCount) {
        shapeOutside!.bounds.append(cshapeBounds![i])
      }
    }
    
    _BoxModelCleanup(
      ptr,
      ccontent,
      ccontentCount,
      cpadding,
      cpaddingCount,
      cborder,
      cborderCount,
      cmargin,
      cmarginCount,
      cshapeBounds,
      cshapeBoundsCount)
  }
}

public class ShapeOutsideInfo {
  public var bounds: [Double] = []
  // FIXME: not deserializing these on BoxModel
  public var shape: [Value] = []
  public var marginShape: [Value] = []

  public init() {}
}
  
public class PseudoElementMatches {
  public var pseudoType: PseudoType = .firstLine
  public var matches: [RuleMatch] = []

  public init() {}

  public func decode(_ ptr: PseudoElementMatchesPtrRef) {
    var cpseudoType: CInt = 0
    var cmatchesCount: CInt = 0
    var cmatches: UnsafeMutablePointer<RuleMatchPtrRef?>?
    _PseudoElementMatchesRead(
      ptr,
      &cpseudoType,
      &cmatches,
      &cmatchesCount)
    for i in 0..<Int(cmatchesCount) {
      let match = RuleMatch()
      match.decode(cmatches![i]!)
      matches.append(match)
    }
    pseudoType = PseudoType(rawValue: Int(cpseudoType))!
    
    _PseudoElementMatchesCleanup(
      ptr, 
      cmatches,
      cmatchesCount)
  }
}
  
public class InheritedStyleEntry {
  public var inlineStyle: CSSStyle?
  public var matchedCssRules: [RuleMatch] = []

  public init() {}

  public func decode(_ ptr: PseudoElementMatchesPtrRef) {
    var cinlineStyle: CSSStylePtrRef?
    var cmatchesCount: CInt = 0
    var cmatches: UnsafeMutablePointer<RuleMatchPtrRef?>?
    _InheritedStyleEntryRead(
      ptr,
      &cinlineStyle,
      &cmatches,
      &cmatchesCount)
    for i in 0..<Int(cmatchesCount) {
      let match = RuleMatch()
      match.decode(cmatches![i]!)
      matchedCssRules.append(match)
    }
    if cinlineStyle != nil {
      inlineStyle = CSSStyle()
      inlineStyle!.decode(cinlineStyle!)
    }
    _InheritedStyleEntryCleanup(
      ptr, 
      cmatches,
      cmatchesCount)
  }
}
  
public class RuleMatch {
  public var rule: CSSRule = CSSRule()
  public var matchingSelectors: [Int] = []

  public init() {}

  public func decode(_ ptr: RuleMatchPtrRef) {
    var crule: CSSRulePtrRef?
    var csels: UnsafeMutablePointer<CInt>?
    var cselsCount: CInt = 0

    _RuleMatchRead(
      ptr, 
      &crule,
      &csels,
      &cselsCount)
    
    for i in 0..<Int(cselsCount) {
      matchingSelectors.append(Int(csels![i]))
    }
    if crule != nil {
      rule.decode(crule!)
    }

    _RuleMatchCleanup(
      ptr,
      csels,
      cselsCount)
  }
}
  
public struct CSSValue {
  public var text: String = String()
  public var range: SourceRange?

  public mutating func decode(_ ptr: CSSValuePtrRef) {
    var ctext: UnsafePointer<CChar>?
    var startLine: CInt = -1
    var startColumn: CInt = -1
    var endLine: CInt = -1
    var endColumn: CInt = -1

    _CSSValueRead(
      ptr,
      &ctext,
      &startLine,
      &startColumn,
      &endLine,
      &endColumn)

    text = String(cString: ctext!)
    if startLine != -1 {
      range = SourceRange()
      range!.startLine = Int(startLine)
      range!.startColumn = Int(startColumn)
      range!.endLine = Int(endLine)
      range!.endColumn = Int(endColumn)
    }
  }
}
  
public class SelectorList {
  public var selectors: [CSSValue] = []
  public var text: String = String()

  public init() {}

  public func decode(_ ptr: SelectorListPtrRef) {
    var csel: UnsafeMutablePointer<CSSValuePtrRef?>?
    var cselCount: CInt = 0
    var ctext: UnsafePointer<CChar>?
    
    _SelectorListRead(
      ptr, 
      &csel,
      &cselCount,
      &ctext)

    for i in 0..<Int(cselCount) {
      var value = CSSValue()
      value.decode(csel![i]!)
      selectors.append(value)
    }

    text = String(cString: ctext!)

    _SelectorListCleanup(ptr, csel, cselCount)
  }
}
  
public class CSSStyleSheetHeader {
  public var styleSheetId: String = String()
  public var frameId: String = String()
  public var sourceUrl: String = String()
  public var sourceMapUrl: String?
  public var origin: StyleSheetOrigin = .originInjected
  public var title: String = String()
  public var ownerNode: Int = 0
  public var disabled: Bool = false
  public var hasSourceUrl: Bool = false
  public var isInline: Bool = false
  public var startLine: Int = 0
  public var startColumn: Int = 0
  public var length: Int = 0

  public init() {}

  public func decode(_ ptr: CSSStyleSheetHeaderPtrRef) {
    var cstyleSheetId: UnsafePointer<CChar>?
    var cframeId: UnsafePointer<CChar>?
    var csourceUrl: UnsafePointer<CChar>?
    var csourceMapUrl: UnsafePointer<CChar>?
    var corigin: CInt = 0
    var ctitle: UnsafePointer<CChar>?
    var cownerNode: CInt = 0
    var cdisabled: CInt = 0
    var chasSourceUrl: CInt = 0
    var cisInline: CInt = 0
    var cstartLine: CInt = 0
    var cstartColumn: CInt = 0
    var clength: CInt = 0
    _CSSStyleSheetHeaderRead(
      ptr,
      &cstyleSheetId,
      &cframeId,
      &csourceUrl,
      &csourceMapUrl,
      &corigin,
      &ctitle,
      &cownerNode,
      &cdisabled,
      &chasSourceUrl,
      &cisInline,
      &cstartLine,
      &cstartColumn,
      &clength)

    styleSheetId = String(cString: cstyleSheetId!)
    frameId = String(cString: cframeId!)
    sourceUrl = String(cString: csourceUrl!)
    if csourceMapUrl != nil {
      sourceMapUrl = String(cString: csourceMapUrl!)
    }
    origin = StyleSheetOrigin(rawValue: Int(corigin))!
    title = String(cString: ctitle!)
    ownerNode = Int(cownerNode)
    disabled = cdisabled != 0
    hasSourceUrl = chasSourceUrl != 0
    isInline = cisInline != 0
    startLine = Int(cstartLine)
    startColumn = Int(cstartColumn)
    length = Int(clength)
  }
}
  
public class CSSRule {
  public var styleSheetId: String?
  public var selectorList: SelectorList = SelectorList()
  public var origin: StyleSheetOrigin = .originInjected
  public var style: CSSStyle = CSSStyle()
  public var media: [CSSMedia]?

  public init() {}

  public func decode(_ ptr: CSSRulePtrRef) {
    var cstylesheetId: UnsafePointer<CChar>?
    var cselectorListText: UnsafePointer<CChar>?
    var cselectorListValuesCount: CInt = 0
    var cselectorListValuesTexts: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cselectorListValuesStartLine: UnsafeMutablePointer<CInt>?
    var cselectorListValuesStartColumn: UnsafeMutablePointer<CInt>?
    var cselectorListValuesEndLine: UnsafeMutablePointer<CInt>?
    var cselectorListValuesEndColumn: UnsafeMutablePointer<CInt>?
    var corigin: CInt = 0

    var cssPropertiesCount: CInt = 0
    var cssPropertiesNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesImportants: UnsafeMutablePointer<CInt>?
    var cssPropertiesImplicits: UnsafeMutablePointer<CInt>?
    var cssPropertiesTexts: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesParsedOk: UnsafeMutablePointer<CInt>?
    var cssPropertiesDisabled: UnsafeMutablePointer<CInt>?
    var cssPropertiesStartLine: UnsafeMutablePointer<CInt>?
    var cssPropertiesStartColumn: UnsafeMutablePointer<CInt>?
    var cssPropertiesEndLine: UnsafeMutablePointer<CInt>?
    var cssPropertiesEndColumn: UnsafeMutablePointer<CInt>?
    
    var shorthandEntriesCount: CInt = 0
    var shorthandEntriesNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var shorthandEntriesValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var shorthandEntriesImportants: UnsafeMutablePointer<CInt>?
    
    var cstyleStyleSheetId: UnsafePointer<CChar>?
    var cstyleStyleCssText: UnsafePointer<CChar>?
    var cstyleStyleStartLine: CInt = 0
    var cstyleStyleStartColumn: CInt = 0
    var cstyleStyleEndLine: CInt = 0
    var cstyleStyleEndColumn: CInt = 0

    var cssMedias: UnsafeMutablePointer<CSSMediaPtrRef?>?
    var cssMediasCount: CInt = 0

    _CSSRuleRead(
      ptr,
      &cstylesheetId,
      &cselectorListText,
      &cselectorListValuesCount,
      &cselectorListValuesTexts,
      &cselectorListValuesStartLine,
      &cselectorListValuesStartColumn,
      &cselectorListValuesEndLine,
      &cselectorListValuesEndColumn,
      &corigin,
      &cssPropertiesCount,
      &cssPropertiesNames,
      &cssPropertiesValues,
      &cssPropertiesImportants,
      &cssPropertiesImplicits,
      &cssPropertiesTexts,
      &cssPropertiesParsedOk,
      &cssPropertiesDisabled,
      &cssPropertiesStartLine,
      &cssPropertiesStartColumn,
      &cssPropertiesEndLine,
      &cssPropertiesEndColumn,
      &shorthandEntriesCount,
      &shorthandEntriesNames,
      &shorthandEntriesValues,
      &shorthandEntriesImportants,
      &cstyleStyleSheetId,
      &cstyleStyleCssText,
      &cstyleStyleStartLine,
      &cstyleStyleStartColumn,
      &cstyleStyleEndLine,
      &cstyleStyleEndColumn,
      &cssMedias,
      &cssMediasCount)
    
    if cstylesheetId != nil {
      self.styleSheetId = String(cString: cstylesheetId!)
    }

    self.selectorList.text = String(cString: cselectorListText!)
    for i in 0..<Int(cselectorListValuesCount) {
      var cssValue = CSSValue()
      cssValue.text = String(cString: cselectorListValuesTexts![i]!)
      cssValue.range = SourceRange()
      cssValue.range!.startLine = Int(cselectorListValuesStartLine![i])
      cssValue.range!.startColumn = Int(cselectorListValuesStartColumn![i])
      cssValue.range!.endLine = Int(cselectorListValuesEndLine![i])
      cssValue.range!.endColumn = Int(cselectorListValuesEndColumn![i])
      self.selectorList.selectors.append(cssValue)
    }
    self.origin = StyleSheetOrigin(rawValue: Int(corigin))!
    
    if cstyleStyleSheetId != nil {
      style.styleSheetId = String(cString: cstyleStyleSheetId!)
    }
    
    if cstyleStyleCssText != nil {
      style.cssText = String(cString: cstyleStyleCssText!)
    }

    if cstyleStyleStartLine != -1 {
      style.range = SourceRange()
      style.range!.startLine = Int(cstyleStyleStartLine)
      style.range!.startColumn = Int(cstyleStyleStartColumn)
      style.range!.endLine = Int(cstyleStyleEndLine)
      style.range!.endColumn = Int(cstyleStyleEndColumn)
    }

    for i in 0..<Int(cssPropertiesCount) { 
      let cssProperty = CSSProperty()
      cssProperty.name = String(cString: cssPropertiesNames![i]!)
      cssProperty.value = String(cString: cssPropertiesValues![i]!)
      cssProperty.important = cssPropertiesImportants![i] != 0
      cssProperty.implicit = cssPropertiesImplicits![i] != 0
      cssProperty.text = String(cString: cssPropertiesTexts![i]!)
      cssProperty.parsedOk = cssPropertiesParsedOk![i] != 0
      cssProperty.disabled = cssPropertiesDisabled![i] != 0
      if cssPropertiesStartLine![i] != -1 {
        cssProperty.range = SourceRange()
        cssProperty.range!.startLine = Int(cssPropertiesStartLine![i])
        cssProperty.range!.startColumn = Int(cssPropertiesStartColumn![i])
        cssProperty.range!.endLine = Int(cssPropertiesEndLine![i])
        cssProperty.range!.endColumn = Int(cssPropertiesEndColumn![i])
      }
      style.cssProperties.append(cssProperty)
    }

    for i in 0..<Int(shorthandEntriesCount) { 
      let entry = ShorthandEntry()
      entry.name = String(cString: shorthandEntriesNames![i]!)
      entry.value = String(cString: shorthandEntriesValues![i]!)
      entry.important = shorthandEntriesImportants![i] != 0
      style.shorthandEntries.append(entry)
    }

    for i in 0..<Int(cssMediasCount) {
      let cssMedia = CSSMedia()
      cssMedia.decode(cssMedias![i]!)
      media!.append(cssMedia)
    }

    _CSSRuleCleanup(
      ptr,
      cselectorListValuesCount,
      cselectorListValuesTexts,
      cselectorListValuesStartLine,
      cselectorListValuesStartColumn,
      cselectorListValuesEndLine,
      cselectorListValuesEndColumn,
      cssPropertiesCount,
      cssPropertiesNames,
      cssPropertiesValues,
      cssPropertiesImportants,
      cssPropertiesImplicits,
      cssPropertiesTexts,
      cssPropertiesParsedOk,
      cssPropertiesDisabled,
      cssPropertiesStartLine,
      cssPropertiesStartColumn,
      cssPropertiesEndLine,
      cssPropertiesEndColumn,
      shorthandEntriesCount,
      shorthandEntriesNames,
      shorthandEntriesValues,
      shorthandEntriesImportants,
      cssMedias,
      cssMediasCount)
  }
}
  
public struct CSSRuleUsage {
  public var styleSheetId: String = String()
  public var startOffset: Int = 0
  public var endOffset: Int = 0
  public var used: Bool = false

  public mutating func decode(_ ptr: CSSRuleUsagePtrRef) {
    var cstyleSheetId: UnsafePointer<CChar>?
    var cstartOffset: CInt = 0
    var cendOffset: CInt = 0
    var cused: CInt = 0

    _CSSRuleUsageRead(
      ptr,
      &cstyleSheetId,
      &cstartOffset,
      &cendOffset,
      &cused)

    styleSheetId = String(cString: cstyleSheetId!)
    startOffset = Int(cstartOffset)
    endOffset = Int(cendOffset)
    used = cused != 0
  }
}
  
public struct SourceRange {
  public var startLine: Int = -1
  public var startColumn: Int = -1
  public var endLine: Int = -1
  public var endColumn: Int = -1
}
  
public class ShorthandEntry {
  public var name: String = String()
  public var value: String = String()
  public var important: Bool = false

  public init() {}
}
  
public struct CSSComputedStyleProperty {
  public var name: String = String()
  public var value: String = String()

  public mutating func decode(_ ptr: CSSComputedStylePropertyPtrRef) {
    var cname: UnsafePointer<CChar>?
    var cvalue: UnsafePointer<CChar>?
    _CSSComputedStylePropertyRead(
      ptr,
      &cname,
      &cvalue)
    name = String(cString: cname!)
    value = String(cString: cvalue!)
  }
}
  
public class CSSStyle {
  public var styleSheetId: String?
  public var cssProperties: [CSSProperty] = []
  public var shorthandEntries: [ShorthandEntry] = []
  public var cssText: String? 
  public var range: SourceRange?

  public init() {}

  public func decode(_ ptr: CSSStylePtrRef) {
    var cstyleStyleSheetId: UnsafePointer<CChar>?
    var cstyleStyleCssText: UnsafePointer<CChar>?
    var cstyleStyleStartLine: CInt = 0
    var cstyleStyleStartColumn: CInt = 0
    var cstyleStyleEndLine: CInt = 0
    var cstyleStyleEndColumn: CInt = 0

    var cssPropertiesCount: CInt = 0
    var cssPropertiesNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesImportants: UnsafeMutablePointer<CInt>?
    var cssPropertiesImplicits: UnsafeMutablePointer<CInt>?
    var cssPropertiesTexts: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cssPropertiesParsedOk: UnsafeMutablePointer<CInt>?
    var cssPropertiesDisabled: UnsafeMutablePointer<CInt>?
    var cssPropertiesStartLine: UnsafeMutablePointer<CInt>?
    var cssPropertiesStartColumn: UnsafeMutablePointer<CInt>?
    var cssPropertiesEndLine: UnsafeMutablePointer<CInt>?
    var cssPropertiesEndColumn: UnsafeMutablePointer<CInt>?
    
    var shorthandEntriesCount: CInt = 0
    var shorthandEntriesNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var shorthandEntriesValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var shorthandEntriesImportants: UnsafeMutablePointer<CInt>?

    _CSSStyleRead(
      ptr,
      &cstyleStyleSheetId,
      &cstyleStyleCssText,
      &cstyleStyleStartLine,
      &cstyleStyleStartColumn,
      &cstyleStyleEndLine,
      &cstyleStyleEndColumn,
      &cssPropertiesCount,
      &cssPropertiesNames,
      &cssPropertiesValues,
      &cssPropertiesImportants,
      &cssPropertiesImplicits,
      &cssPropertiesTexts,
      &cssPropertiesParsedOk,
      &cssPropertiesDisabled,
      &cssPropertiesStartLine,
      &cssPropertiesStartColumn,
      &cssPropertiesEndLine,
      &cssPropertiesEndColumn,
      &shorthandEntriesCount,
      &shorthandEntriesNames,
      &shorthandEntriesValues,
      &shorthandEntriesImportants)
    
    if cstyleStyleSheetId != nil {
      styleSheetId = String(cString: cstyleStyleSheetId!)
    }
    
    if cstyleStyleCssText != nil {
      cssText = String(cString: cstyleStyleCssText!)
    }

    if cstyleStyleStartLine != -1 {
      range = SourceRange()
      range!.startLine = Int(cstyleStyleStartLine)
      range!.startColumn = Int(cstyleStyleStartColumn)
      range!.endLine = Int(cstyleStyleEndLine)
      range!.endColumn = Int(cstyleStyleEndColumn)
    }

    for i in 0..<Int(cssPropertiesCount) { 
      let cssProperty = CSSProperty()
      cssProperty.name = String(cString: cssPropertiesNames![i]!)
      cssProperty.value = String(cString: cssPropertiesValues![i]!)
      cssProperty.important = cssPropertiesImportants![i] != 0
      cssProperty.implicit = cssPropertiesImplicits![i] != 0
      cssProperty.text = String(cString: cssPropertiesTexts![i]!)
      cssProperty.parsedOk = cssPropertiesParsedOk![i] != 0
      cssProperty.disabled = cssPropertiesDisabled![i] != 0
      if cssPropertiesStartLine![i] != -1 {
        cssProperty.range = SourceRange()
        cssProperty.range!.startLine = Int(cssPropertiesStartLine![i])
        cssProperty.range!.startColumn = Int(cssPropertiesStartColumn![i])
        cssProperty.range!.endLine = Int(cssPropertiesEndLine![i])
        cssProperty.range!.endColumn = Int(cssPropertiesEndColumn![i])
      }
      cssProperties.append(cssProperty)
    }

    for i in 0..<Int(shorthandEntriesCount) { 
      let entry = ShorthandEntry()
      entry.name = String(cString: shorthandEntriesNames![i]!)
      entry.value = String(cString: shorthandEntriesValues![i]!)
      entry.important = shorthandEntriesImportants![i] != 0
      shorthandEntries.append(entry)
    }

  }
}
  
public class CSSProperty {
  public var name: String = String()
  public var value: String = String()
  public var important: Bool = false
  public var implicit: Bool = false
  public var text: String?
  public var parsedOk: Bool = false
  public var disabled: Bool = false
  public var range: SourceRange?

  public init() {}
}
  
public class CSSMedia {
  public var source: CSSMediaSource = .mediaRule
  public var text: String = String()
  public var sourceUrl: String?
  public var range: SourceRange?
  public var styleSheetId: String?
  public var mediaList: [CSSMediaQuery]?

  public init() {}

  public func decode(_ ptr: CSSMediaPtrRef) {
    var csource: CInt = -1
    var ctext: UnsafePointer<CChar>?
    var csourceUrl: UnsafePointer<CChar>?
    var cstyleSheetId: UnsafePointer<CChar>?
    var startLine: CInt = -1
    var startColumn: CInt = -1
    var endLine: CInt = -1
    var endColumn: CInt = -1
    var cmediaList: UnsafeMutablePointer<CSSMediaQueryPtrRef?>?
    var cmediaListCount: CInt = 0

    _CSSMediaRead(
      ptr,
      &csource,
      &ctext,
      &csourceUrl,
      &startLine,
      &startColumn,
      &endLine,
      &endColumn,
      &cstyleSheetId,
      &cmediaList,
      &cmediaListCount)

    source = CSSMediaSource(rawValue: Int(csource))!
    text = String(cString: ctext!)
    if csourceUrl != nil {
      sourceUrl = String(cString: csourceUrl!)
    }
    if cstyleSheetId != nil {
      styleSheetId = String(cString: cstyleSheetId!)
    }
    if startLine != -1 {
      range = SourceRange()
      range!.startLine = Int(startLine)
      range!.startColumn = Int(startColumn)
      range!.endLine = Int(endLine)
      range!.endColumn = Int(endColumn)
    }

    if cmediaListCount > 0 {
      mediaList = []
      for i in 0..<Int(cmediaListCount) {
        let query = CSSMediaQuery()
        query.decode(cmediaList![i]!)
        mediaList!.append(query)
      } 
    }

    _CSSMediaCleanup(
      ptr,
      cmediaList,
      cmediaListCount)
  }
}
  
public class CSSMediaQuery {
  public var expressions: [CSSMediaQueryExpression] = []
  public var active: Bool = false

  public init() {}

  public func decode(_ ptr: CSSMediaQueryPtrRef) {
    var cexpr: UnsafeMutablePointer<CSSMediaQueryExpressionPtrRef?>?
    var cexprCount: CInt = 0
    var cactive: CInt = 0
    _CSSMediaQueryRead(
      ptr,
      &cexpr,
      &cexprCount,
      &cactive)

    active = cactive != 0
    for i in 0..<Int(cexprCount) {
      let expr = CSSMediaQueryExpression()
      expr.decode(cexpr![i]!)
      expressions.append(expr)
    }
    _CSSMediaQueryCleanup(ptr, cexpr, cexprCount)
  }
}
  
public class CSSMediaQueryExpression {
  public var value: Int = -1
  public var unit: String = String()
  public var feature: String = String()
  public var valueRange: SourceRange?
  public var computedLength: Int = -1

  public init() {}

  public func decode(_ ptr: CSSMediaQueryExpressionPtrRef) {
    var cvalue: CInt = 0
    var cunit: UnsafePointer<CChar>?
    var cfeature: UnsafePointer<CChar>?
    var startLine: CInt = -1
    var startColumn: CInt = -1
    var endLine: CInt = -1
    var endColumn: CInt = -1
    var ccomputedLength: CInt = 0
    
    _CSSMediaQueryExpressionRead(
      ptr,
      &cvalue,
      &cunit,
      &cfeature,
      &startLine,
      &startColumn,
      &endLine,
      &endColumn,
      &ccomputedLength)
    
    value = Int(cvalue)
    unit = String(cString: cunit!)
    feature = String(cString: cfeature!)
    if startLine != -1 {
      valueRange = SourceRange()
      valueRange!.startLine = Int(startLine)
      valueRange!.startColumn = Int(startColumn)
      valueRange!.endLine = Int(endLine)
      valueRange!.endColumn = Int(endColumn)
    }
    computedLength = Int(ccomputedLength)
  }
}
  
public struct PlatformFontUsage {
  public var familyName: String = String()
  public var isCustomFont: Bool = false
  public var glyphCount: Int = -1

  public mutating func decode(_ ptr: PlatformFontUsagePtrRef) {
    var cfamilyName: UnsafePointer<CChar>?
    var cisCustomFont: CInt = 0
    var cglyphCount: CInt = 0
    _PlatformFontUsage(
      ptr,
      &cfamilyName,
      &cisCustomFont,
      &cglyphCount)
    familyName = String(cString: cfamilyName!)
    isCustomFont = cisCustomFont != 0
    glyphCount = Int(cglyphCount)
  }
}
  
public class FontFace {
  public var fontFamily: String = String()
  public var fontStyle: String = String()
  public var fontVariant: String = String()
  public var fontWeight: String = String()
  public var fontStretch: String = String()
  public var unicodeRange: String = String()
  public var src: String = String()
  public var platformFontFamily: String = String()

  public init() {}

  public func decode(_ ptr: FontFacePtrRef) {
    var cfontFamily: UnsafePointer<CChar>?
    var cfontStyle: UnsafePointer<CChar>?
    var cfontVariant: UnsafePointer<CChar>?
    var cfontWeight: UnsafePointer<CChar>?
    var cfontStretch: UnsafePointer<CChar>?
    var cunicodeRange: UnsafePointer<CChar>?
    var csrc: UnsafePointer<CChar>?
    var cplatformFontFamily: UnsafePointer<CChar>?
    
    _FontFaceRead(
      ptr,
      &cfontFamily,
      &cfontStyle,
      &cfontVariant,
      &cfontWeight,
      &cfontStretch,
      &cunicodeRange,
      &csrc,
      &cplatformFontFamily)
   
    fontFamily = String(cString: cfontFamily!)
    fontStyle = String(cString: cfontStyle!)
    fontVariant = String(cString: cfontVariant!)
    fontWeight = String(cString: cfontWeight!)
    fontStretch = String(cString: cfontStretch!)
    unicodeRange = String(cString: cunicodeRange!)
    src = String(cString: csrc!)
    platformFontFamily = String(cString: cplatformFontFamily!)
  }
}
  
public class CSSKeyframesRule {
  public var animationName: CSSValue = CSSValue()
  public var keyframes: [CSSKeyframeRule] = []

  public init() {}

  public func decode(_ ptr: CSSKeyframesRulePtrRef) {
    var canimationName: CSSValuePtrRef?
    var ckeyframes: UnsafeMutablePointer<CSSKeyframeRulePtrRef?>?
    var ckeyframesCount: CInt = 0
    _CSSKeyframesRuleRead(ptr, &canimationName, &ckeyframes, &ckeyframesCount)
    if canimationName != nil {
      animationName.decode(canimationName!)
    }
    for i in 0..<Int(ckeyframesCount) {
      let keyframe = CSSKeyframeRule()
      keyframe.decode(ckeyframes![i]!)
      keyframes.append(keyframe)
    }
    _CSSKeyframesRuleCleanup(ptr, ckeyframes, ckeyframesCount)
  }
}
  
public class CSSKeyframeRule {
  public var styleSheetId: String?
  public var origin: StyleSheetOrigin = .originInjected
  public var keyText: CSSValue = CSSValue()
  public var style: CSSStyle = CSSStyle()

  public init() {}

  public func decode(_ ptr: CSSKeyframeRulePtrRef) {
    var cstyleSheetId: UnsafePointer<CChar>?
    var corigin: CInt = 0
    var ckeyText: CSSValuePtrRef?
    var cstyle: CSSValuePtrRef?
    
    _CSSKeyframeRuleRead(ptr, &cstyleSheetId, &corigin, &ckeyText, &cstyle)
    
    if cstyleSheetId != nil {
      styleSheetId = String(cString: cstyleSheetId!)
    }
    origin = StyleSheetOrigin(rawValue: Int(corigin))!
    if ckeyText != nil {
      keyText.decode(ckeyText!)
    }
    if cstyle != nil {
      style.decode(cstyle!)
    }
  }
}
  
public struct StyleDeclarationEdit {
  public var styleSheetId: String
  public var range: SourceRange
  public var text: String
}
  
public class DataEntry {
  public var requestUrl: String = String()
  public var requestMethod: String = String()
  public var requestHeaders: [Header] = []
  public var responseTime: Int64 = -1
  public var responseStatus: Int = -1
  public var responseStatusText: String = String()
  public var responseHeaders: [Header] = []

  public init() {}

  public func decode(_ ptr: DataEntryPtrRef) {
    var crequestUrl: UnsafePointer<CChar>?
    var crequestMethod: UnsafePointer<CChar>?
    var crequestHeadersNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var crequestHeadersValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var crequestHeadersCount: CInt = 0
    var cresponseStatus: CInt = 0
    var cresponseStatusText: UnsafePointer<CChar>?
    var cresponseHeadersNames: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cresponseHeadersValues: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var cresponseHeadersCount: CInt = 0
    
    _DataEntryRead(
      ptr,
      &crequestUrl,
      &crequestMethod,
      &crequestHeadersNames,
      &crequestHeadersValues,
      &crequestHeadersCount,
      &responseTime,
      &cresponseStatus,
      &cresponseStatusText, 
      &cresponseHeadersNames,
      &cresponseHeadersValues,
      &cresponseHeadersCount)

    requestUrl = String(cString: crequestUrl!)
    requestMethod = String(cString: crequestMethod!)
    for i in 0..<Int(crequestHeadersCount) {
      var header = Header()
      header.name = String(cString: crequestHeadersNames![i]!)
      header.value = String(cString: crequestHeadersValues![i]!)
    }
    responseStatus = Int(cresponseStatus)
    responseStatusText = String(cString: cresponseStatusText!)
    for i in 0..<Int(cresponseHeadersCount) {
      var header = Header()
      header.name = String(cString: cresponseHeadersNames![i]!)
      header.value = String(cString: cresponseHeadersValues![i]!)

    }
    
    _DataEntryCleanup(
      ptr,
      crequestHeadersNames,
      crequestHeadersValues,
      crequestHeadersCount,
      cresponseHeadersNames,
      cresponseHeadersValues,
      cresponseHeadersCount)
  }
}
  
public struct Cache {
  public var cacheId: String = String()
  public var securityOrigin: String = String()
  public var cacheName: String = String()

  public func decode(_ ptr: CachePtrRef) {
    var cchacheId: UnsafePointer<CChar>?
    var csecurityOrigin: UnsafePointer<CChar>?
    var ccacheName: UnsafePointer<CChar>?
    
    _CacheRead(
      ptr,
      &cchacheId,
      &csecurityOrigin,
      &ccacheName)
  }
}
  
public struct Header {
  public var name: String = String()
  public var value: String = String()
}

// class: the body might be big  
public class CachedResponse {
  public var body: Data = Data()

  public init() {}

  public init(body: Data) {
    self.body = body
  }
}

public struct ApplicationCacheResource {
  public var url: String = String()
  public var size: Int = 0
  public var type: String = String()
}

public class ApplicationCache {
  public var manifestUrl: String = String()
  public var size: Int64 = -1
  public var creationTime: TimeTicks = TimeTicks()
  public var updateTime: TimeTicks = TimeTicks()
  public var resources: [ApplicationCacheResource] = []

  public init() {}

  public func decode(_ ptr: ApplicationCachePtrRef) {
    var cmanifestUrl: UnsafePointer<CChar>?
    var ccreationTime: Int64 = 0
    var cupdateTime: Int64 = 0
    var resourceCount: CInt = 0
    var resourceUrls: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var resourceTypes: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    var resourceSizes: UnsafeMutablePointer<CInt>?

    _ApplicationCacheRead(
      ptr, 
      &cmanifestUrl,
      &size,
      &ccreationTime,
      &cupdateTime,
      &resourceUrls,
      &resourceSizes,
      &resourceTypes,
      &resourceCount)

    manifestUrl = String(cString: cmanifestUrl!)
    creationTime = TimeTicks(microseconds: ccreationTime)
    updateTime = TimeTicks(microseconds: cupdateTime)

    for i in 0..<Int(resourceCount) {
      var resource = ApplicationCacheResource()
      resource.url = String(cString: resourceUrls![i]!)
      resource.size = Int(resourceSizes![i])
      resource.type = String(cString: resourceTypes![i]!)
      resources.append(resource)
    }

    _ApplicationCacheCleanup(
      ptr, 
      resourceUrls,
      resourceSizes,
      resourceTypes,
      resourceCount)
  }
}

public struct FrameWithManifest {
  public var frameId: String = String()
  public var manifestUrl: String = String()
  public var status: Int = -1

  public mutating func decode(_ ptr: FrameWithManifestPtrRef) {
    var cframeId: UnsafePointer<CChar>?
    var cmanifestUrl: UnsafePointer<CChar>?
    var cstatus: CInt = -1

    _FrameWithManifestRead(
      ptr,
      &cframeId,
      &cmanifestUrl,
      &cstatus)
    
    frameId = String(cString: cframeId!)
    manifestUrl = String(cString: cmanifestUrl!)
    status = Int(cstatus)
  }

}

public class BlobBytesProvider {
  
  internal let reference: BlobBytesProviderRef

  init(reference: BlobBytesProviderRef) {
    self.reference = reference
  }

  public func append(_ str: String) {
    append(Data(str.utf8))
  }

  public func append(_ data: Data) {
    data.withUnsafeBytes {
      BlobBytesProviderAppendData(reference, $0, CInt(data.count))
    }
  }
}

// FIXME: this is the same thing as Web.BlobData
//        but internally we use a pass/switch
//        where PutCacheEntry for instance destroy(pass)
//        the inner pointer of BlobData
//        Once the Web versiona can do the same for us
//        theres no reason to have this  

public class BlobData {

  public var contentType: String {
    get {
      if let str = _contentType {
        return str
      }
      var size: CInt = 0
      let buf = BlobDataGetContentType(reference, &size)
      _contentType = String(bytesNoCopy: buf!, length: Int(size), encoding: String.Encoding.utf8, freeWhenDone: true)!
      return _contentType!
    }
    set {
      newValue.withCString {
        BlobDataSetContentType(reference, $0)
      }
      _contentType = nil
    }
  }

  public var length: UInt64 {
    return BlobDataGetLength(reference)
  }
  
  internal let reference: BlobDataRef
  private var _contentType: String?

  public init() {
    reference = BlobDataCreate()
  }

  public init(file: String) {
    reference = file.withCString {
      return BlobDataCreateForFile($0)
    }
  }

  public init(filesystem: String) {
    reference = filesystem.withCString {
      return BlobDataCreateForFilesystemUrl($0)
    }
  }
  
  init(reference: BlobDataRef) {
    self.reference = reference
  }

  deinit {
    BlobDataDestroy(reference)
  }


  public func appendBytes(_ data: Data) {
    data.withUnsafeBytes {
      BlobDataAppendBytes(reference, $0, data.count)
    }
  }

  public func appendFile(_ path: String, offset: UInt64, length: UInt64, expectedModificationTime: Double) {
    path.withCString { cpath in
      BlobDataAppendFile(reference, 
                         cpath,
                         Int64(offset),
                         Int64(length),
                         expectedModificationTime)
    }
  }

  public func appendFilesystem(_ url: String, offset: UInt64, length: UInt64, expectedModificationTime: Double) {
    url.withCString { curl in
      BlobDataAppendFileSystemURL(reference, 
                                  curl,
                                  Int64(offset),
                                  Int64(length),
                                  expectedModificationTime)
    }
  }

  public func appendText(_ text: String, normalizeLineEndingsToNative: Bool = false) {
    text.withCString {
      BlobDataAppendText(reference, $0, normalizeLineEndingsToNative ? 1 : 0)
    }
  }
}