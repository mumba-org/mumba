// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public class WebURLRequest {

   public enum CachePolicy : Int {
        case UseProtocolCachePolicy = 0
        case ReloadIgnoringCacheData
        case ReturnCacheDataElseLoad
        case ReturnCacheDataDontLoad
        case ReloadBypassingCache
    }

    public enum Priority : Int {
        case Unresolved = -1
        case VeryLow
        case Low
        case Medium
        case High
        case VeryHigh
    }

    public enum RequestContext : Int {
        case Unspecified = 0
        case Audio
        case Beacon
        case CSPReport
        case Download
        case Embed
        case EventSource
        case Favicon
        case Fetch
        case Font
        case Form
        case Frame
        case Hyperlink
        case Iframe
        case Image
        case ImageSet
        case Import
        case Internal
        case Location
        case Manifest
        case Object
        case Ping
        case Plugin
        case Prefetch
        case Script
        case ServiceWorker
        case SharedWorker
        case Subresource
        case Style
        case Track
        case Video
        case Worker
        case XMLHttpRequest
        case XSLT
    }

    public enum FrameType : Int {
        case Auxiliary = 0
        case Nested
        case None
        case TopLevel
    }

    public enum FetchRequestMode : Int {
        case SameOrigin = 0
        case NoCORS
        case CORS
        case CORSWithForcedPreflight
    }

    public enum FetchCredentialsMode : Int {
        case Omit = 0
        case SameOrigin
        case Include
    }

    public enum FetchRedirectMode : Int  {
        case Follow = 0
        case Error
        case Manual
    }

    public enum InputToLoadPerfMetricReportPolicy : Int  {
        case NoReport = 0
        case ReportLink
        case ReportIntent
    }

    public enum LoFiState : Int {
        case Unspecified = 0
        case Off
        case On
    }

    public struct ExtraData {}

    public var url: String {
        get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLRequestGetURL(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLRequest.self)
                if str != nil {
                    this._url = String(cString: str!)
                } else {
                    this._url = String()
                }
            })
            return _url
        }
        set {
            newValue.withCString { urlbuf in
              _WebURLRequestSetURL(reference, urlbuf)
            }
        }

    }

    // public var firstPartyForCookies: URL? {
        
    //     get {
    //         let result = _WebURLRequestGetFirstPartyForCookies(reference)
    //         if result == nil {
    //             return nil
    //         }
    //         return URL(string: String(cString: result!))!
    //     }

    //     set {
    //         guard let url = newValue else {
    //             return
    //         }
    //         url.absoluteString.withCString { urlbuf in
    //             _WebURLRequestSetFirstPartyForCookies(reference, urlbuf)
    //         }
    //     }
    // }

    
    public var requestorOrigin: WebSecurityOrigin {
        
        get {
            let ref = _WebURLRequestGetRequestorOrigin(reference)
            return WebSecurityOrigin(reference: ref!)
        }

        set (origin) {
            _WebURLRequestSetRequestorOrigin(reference, origin.reference)
        }
    }

    public var allowStoredCredentials: Bool {
        
        get {
            return _WebURLRequestGetAllowStoredCredentials(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetAllowStoredCredentials(reference, newValue ? 1 : 0)
        }
    }

    // public var cachePolicy: CachePolicy {
        
    //     get {
    //         let result = _WebURLRequestCachePolicy(reference)
    //         return CachePolicy(rawValue: Int(result))!
    //     }

    //     set {
    //         _WebURLRequestSetCachePolicy(reference, Int32(newValue.rawValue))
    //     }
    // }


    public var httpMethod: String {
        
        get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLRequestGetHttpMethod(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLRequest.self)
                if str != nil {
                    this._httpMethod = String(cString: str!)
                } else {
                    this._httpMethod = String()
                }
            })
            return _httpMethod
        }

        set (method) {
            method.withCString { methodbuf in
                _WebURLRequestSetHTTPMethod(reference, methodbuf)
            }
        }
    }

    public var httpBody: WebHTTPBody {
        
        get {
            let result = _WebURLRequestGetHttpBody(reference)
            return WebHTTPBody(reference: result!)
        }
        
        set {
            _WebURLRequestSetHttpBody(reference, newValue.reference)
        }

    }

    public var reportUploadProgress: Bool {
        
        get {
            return _WebURLRequestGetReportUploadProgress(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetReportUploadProgress(reference, newValue ? 1 : 0)
        }
    }

    public var reportRawHeaders: Bool {
        
        get {
            return _WebURLRequestGetReportRawHeaders(reference) == 0 ? false : true
        }
        
        set {
            _WebURLRequestSetReportRawHeaders(reference, newValue ? 1 : 0)
        }
    }


    public var requestContext: RequestContext {
        
        get {
            let result = _WebURLRequestGetRequestContext(reference)
            return RequestContext(rawValue: Int(result))!
        }

        set {
            _WebURLRequestSetRequestContext(reference, Int32(newValue.rawValue))
        }

    }

    public var frameType: FrameType {
        
        get {
            let result = _WebURLRequestGetFrameType(reference)
            return FrameType(rawValue: Int(result))!
        }
        
        set {
            _WebURLRequestSetFrameType(reference, Int32(newValue.rawValue))
        }
    }

    public var referrerPolicy: WebReferrerPolicy {
        let result = _WebURLRequestGetWebReferrerPolicy(reference)
        return WebReferrerPolicy(rawValue: Int(result))!    
    }


    public var hasUserGesture: Bool {
        
        get {
            return _WebURLRequestGetHasUserGesture(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetHasUserGesture(reference, newValue ? 1 : 0)
        }
    }

    public var requestorId: Int {
        
        get {
            return Int(_WebURLRequestGetRequestorId(reference))
        }
        
        set {
            _WebURLRequestSetRequestorId(reference, Int32(newValue))
        }
    }

    // public var requestorProcessId: Int {
        
    //     get {
    //         return Int(_WebURLRequestGetRequestorProcessId(reference))
    //     }

    //     set {
    //         _WebURLRequestSetRequestorProcessId(reference, Int32(newValue))
    //     }
    // }

    public var appCacheHostId: Int {
        
        get {
            return Int(_WebURLRequestGetAppCacheHostId(reference))
        }
        
        set {
            _WebURLRequestSetAppCacheHostId(reference, Int32(newValue))
        }
    
    }

    public var downloadToFile: Bool {
        
        get {
            return _WebURLRequestGetDownloadToFile(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetDownloadToFile(reference, newValue ? 1 : 0)
        }

    }

    public var useStreamOnResponse: Bool {
 
        get {
            return _WebURLRequestGetUseStreamOnResponse(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetUseStreamOnResponse(reference, newValue ? 1 : 0)
        }

    }

    public var skipServiceWorker: Bool {

        get {
            return _WebURLRequestGetSkipServiceWorker(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetSkipServiceWorker(reference, newValue ? 1 : 0)
        }
    
    }

    public var shouldResetAppCache: Bool {
        
        get {
            return _WebURLRequestGetShouldResetAppCache(reference) == 0 ? false : true
        }

        set {
            _WebURLRequestSetShouldResetAppCache(reference, newValue ? 1 : 0)
        }

    }

    public var fetchRequestMode: FetchRequestMode {
        
        get {
            let result = _WebURLRequestGetFetchRequestMode(reference)
            return FetchRequestMode(rawValue: Int(result))!
        }
        
        set {
            _WebURLRequestSetFetchRequestMode(reference, Int32(newValue.rawValue))
        }

    }

    public var fetchCredentialsMode: FetchCredentialsMode {
        
        get {
            let result = _WebURLRequestGetFetchCredentialsMode(reference)
            return FetchCredentialsMode(rawValue: Int(result))!
        }
        
        set {
            _WebURLRequestSetFetchCredentialsMode(reference, Int32(newValue.rawValue))
        }
    }

    public var fetchRedirectMode: FetchRedirectMode {

        get {
            let result = _WebURLRequestGetFetchRedirectMode(reference)
            return FetchRedirectMode(rawValue: Int(result))!
        }

        set {
            _WebURLRequestSetFetchRedirectMode(reference, Int32(newValue.rawValue))
        }
    } 

    public var wasDiscarded: Bool {
        get {
            return _WebURLRequestGetWasDiscarded(reference) != 0
        }

        set {
            _WebURLRequestSetWasDiscarded(reference, newValue ? 1 : 0)
        }
    }
    // public var loFiState: LoFiState {
    //     get {
    //         let result = _WebURLRequestGetLoFiState(reference)
    //         return LoFiState(rawValue: Int(result))!
    //     }
    //     set {
    //         _WebURLRequestSetLoFiState(reference, Int32(newValue.rawValue))
    //     }
    // }

    public var extraData: ExtraData? {
        
        get {
            return nil
        }

        set {

        }

    }

    public var priority: Priority {
        
        get {
            let result = _WebURLRequestGetPriority(reference)
            return Priority(rawValue: Int(result))!
        }
        
        set {
            _WebURLRequestSetPriority(reference, Int32(newValue.rawValue))
        }
    }

    public var checkForBrowserSideNavigation: Bool {
        
        get {
            return _WebURLRequestGetCheckForBrowserSideNavigation(reference) == 0 ? false : true
        }
        
        set {
            _WebURLRequestSetCheckForBrowserSideNavigation(reference, newValue ? 1 : 0)
        }
    }

    // This is used to report navigation metrics starting from the UI action
    // that triggered the navigation (which can be different from the navigation
    // start time used in the Navigation Timing API).
    public var uiStartTime: Double {
        
        get {
            return _WebURLRequestGetUiStartTime(reference)
        }
        
        set {
            _WebURLRequestSetUiStartTime(reference, newValue)
        }
    }

    public var inputPerfMetricReportPolicy: InputToLoadPerfMetricReportPolicy {
        
        get {
            let result = _WebURLRequestGetInputPerfMetricReportPolicy(reference)
            return InputToLoadPerfMetricReportPolicy(rawValue: Int(result))!
        }

        set {
            _WebURLRequestSetInputPerfMetricReportPolicy(reference, Int32(newValue.rawValue))
        }
    }

    public var keepalive: Bool {
        get {
            return _WebURLRequestGetKeepAlive(reference) != 0
        }

        set {
            _WebURLRequestSetKeepAlive(reference, CInt(newValue ? 1 : 0))
        }   
    }

    // public var originatesFromReservedIPRange: Bool {
        
    //     get {
    //         return _WebURLRequestGetOriginatesFromReservedIPRange(reference) == 0 ? false : true
    //     }

    //     set {
    //         _WebURLRequestSetOriginatesFromReservedIPRange(reference, newValue ? 1 : 0)
    //     }

    // }

    var reference: WebURLRequestRef
    private var _url: String = String()
    private var _httpMethod: String = String()
    private var _httpHeaderField: String = String()
    private var owned: Bool = false

    public init(url: String) {
      self.reference = url.withCString { (str) -> WebURLRequestRef in 
        return _WebURLRequestCreate(str)
      }
      self.owned = true
    }

    public init (reference: WebURLRequestRef, owned: Bool = false) {
      self.reference = reference
      self.owned = owned
    }

    deinit {
      //if owned {
      //  _WebURLRequestDestroy(reference)
      //}
    }

    // public func addHTTPOriginIfNeeded(origin: String) {
    //     origin.withCString { strbuf in
    //         _WebURLRequestAddHTTPOriginIfNeeded(reference, strbuf)
    //     }
    // }

    public func getHttpHeaderField(name: String) -> String {
        name.withCString { (strbuf: UnsafePointer<CChar>) in
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLRequestGetHttpHeaderField(reference, strbuf, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLRequest.self)
                if str != nil {
                    this._httpHeaderField = String(cString: str!)
                } else {
                    this._httpHeaderField = String()
                }
            })
        }
        return _httpHeaderField
    }
    
    public func setHTTPHeaderField(name: String, value: String) {
        name.withCString { namebuf in
            value.withCString { valuebuf in
                _WebURLRequestSetHTTPHeaderField(reference, namebuf, valuebuf)
            }
        }
    }
    
    public func setHTTPReferrer(referrer: String, policy: WebReferrerPolicy) {
        referrer.withCString { refbuf in
            _WebURLRequestSetHTTPReferrer(reference, refbuf, Int32(policy.rawValue))
        }
    }
    
    public func addHTTPHeaderField(name: String, value: String) {
        name.withCString { namebuf in
            value.withCString { valuebuf in
                _WebURLRequestAddHTTPHeaderField(reference, namebuf, valuebuf)
            }
        }
    }
    
    public func clearHTTPHeaderField(name: String) {
        name.withCString { namebuf in
            _WebURLRequestClearHTTPHeaderField(reference, namebuf)
        }  
    }

    public func setIsSameDocumentNavigation(_ sameDocumentNavigation: Bool) {
       _WebURLRequestSetIsSameDocumentNavigation(reference, sameDocumentNavigation ? 1 : 0)
    }
   
    public func setNavigationStartTime(_ start: TimeTicks) { 
        _WebURLRequestSetNavigationStartTime(reference, start.microseconds)
    }

    //public func visitHTTPHeaderFields(visitor: WebHTTPHeaderVisitor) {}
}