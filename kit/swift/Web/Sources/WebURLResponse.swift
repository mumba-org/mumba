// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebURLResponse {
	
	public enum HTTPVersion : Int { 
		case Unknown = 0
        case HTTP0_9
        case HTTP1_0
        case HTTP1_1
        case HTTP2_0
    }
    
    public enum SecurityStyle : Int {
        case Unknown = 0
        case Unauthenticated
        case AuthenticationBroken
        case Warning
        case Authenticated
    }

    public struct ExtraData {}

    public var url: String { 
    	get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetURL(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
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
                _WebURLResponseSetURL(reference, urlbuf)
            }
        }

    }

    public func setConnectionId(_ id: Int) {
        _WebURLResponseSetConnectionId(reference, CInt(id))
    }

    public func setConnectionReused(_ reused: Bool) {
        _WebURLResponseSetConnectionReused(reference, reused ? 1 : 0)
    }


    // Commented for now
    
    //public var loadTiming: WebURLLoadTiming {
    //	
    //	get {
    //        let result = _WebURLResponseGetLoadTiming(reference)
    //        return WebURLLoadTiming(rawValue: result)!
    //    }
    //    
    //    set {
    //        _WebURLResponseSetLoadTiming(reference, newValue.rawValue)
    //    }
    //}


    public func setHttpLoadInfo(_ info: WebHTTPLoadInfo) {
        _WebURLResponseSetHttpLoadInfo(reference, info.reference)
    }

    public var mimeType: String {
    	
    	get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetMimeType(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
                if str != nil {
                    this._mimeType = String(cString: str!)
                } else {
                    this._mimeType = String()
                }
            })
            return _mimeType
        }

        set (mime) {
            mime.withCString { mimebuf in
                _WebURLResponseSetMimeType(reference, mimebuf)
            }
        }

    }

    public var expectedContentLength: Int64 {
    	
    	get {
            return _WebURLResponseGetExpectedContentLength(reference)
        }
        
        set {
            _WebURLResponseSetExpectedContentLength(reference, newValue)
        }

    }

    public func setTextEncodingName(_ encoding: String) {
        encoding.withCString { encodingbuf in
            _WebURLResponseSetTextEncodingName(reference, encodingbuf)
        }
    }
   
    // public var suggestedFileName: String {
    	
    // 	get {
    //         let result = _WebURLResponseGetSuggestedFileName(reference)
    //         if result == nil {
    //             return String()
    //         }
    //         return String(cString: result!)
    //     }

    //     set (filename) {
    //         filename.withCString { filenamebuf in
    //             _WebURLResponseSetSuggestedFileName(reference, filenamebuf)
    //         }
    //     }

    // }
    
    public var httpVersion: HTTPVersion {
    	
    	get {
    		let result = _WebURLResponseGetHttpVersion(reference)
    		return HTTPVersion(rawValue: Int(result))!
    	}
        
    	set {
    		_WebURLResponseSetHttpVersion(reference, Int32(newValue.rawValue))
    	}

    }

    public var httpStatusCode: Int {
    	get {
            return Int(_WebURLResponseGetHttpStatusCode(reference))
        }
        
        set {
            _WebURLResponseSetHttpStatusCode(reference, Int32(newValue))
        }
    }

   	public var httpStatusText: String {
   		
   		get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetHttpStatusText(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
                if str != nil {
                    this._httpStatus = String(cString: str!)
                } else {
                    this._httpStatus = String()
                }
            })
            return _httpStatus
        }

        set (status) {
            status.withCString { statusbuf in
                _WebURLResponseSetHttpStatusText(reference, statusbuf)
            }
        }

   	}

   	// public var lastModifiedDate: Double {
   	// 	get {
    //         return _WebURLResponseGetLastModifiedDate(reference)
    //     }
        
    //     set {
    //         _WebURLResponseSetLastModifiedDate(reference, newValue)
    //     }
   	// }

    public var appCacheId: Int64 {

    	get {
            return _WebURLResponseGetAppCacheId(reference)
        }
        
        set {
            _WebURLResponseSetAppCacheId(reference, newValue)
        }
    
    }

    public var appCacheManifestURL: String {
    	
    	get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetAppCacheManifestURL(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
                if str != nil {
                    this._appCacheManifestURL = String(cString: str!)
                } else {
                    this._appCacheManifestURL = String()
                }
            })
            return _appCacheManifestURL
        }
        
        set {
            newValue.withCString { urlbuf in
                _WebURLResponseSetAppCacheManifestURL(reference, urlbuf)
            }
        }

    }

    // public var securityInfo: String {
    	
    // 	get {
    //         let result = _WebURLResponseGetSecurityInfo(reference)
    //         if result == nil {
    //             return String()
    //         }
    //         return String(cString: result!)
    //     }

    //     set (info) {
    //         info.withCString { infobuf in
    //             _WebURLResponseSetSecurityInfo(reference, infobuf)
    //         }
    //     }

    // }

    public func setSecurityStyle(_ style: SecurityStyle) {
        _WebURLResponseSetSecurityStyle(reference, Int32(style.rawValue))
    } 

    public func setWasCached(_ cached: Bool) {
        _WebURLResponseSetWasCached(reference, cached ? 1 : 0)
    }

    public func setWasFetchedViaSPDY(_ fetched: Bool) {
        _WebURLResponseSetWasFetchedViaSPDY(reference, fetched ? 1 : 0)
    }


	// public var wasNpnNegotiated: Bool {
		
	// 	get {
 //            return _WebURLResponseWasNpnNegotiated(reference) == 0 ? false : true
 //        }

 //        set {
 //            _WebURLResponseSetWasNpnNegotiated(reference, newValue ? 1 : 0)
 //        }

	// }

    // public var wasAlternateProtocolAvailable: Bool { 
    	
    // 	get {
    //         return _WebURLResponseWasAlternateProtocolAvailable(reference) == 0 ? false : true
    //     }

    //     set {
    //         _WebURLResponseSetWasAlternateProtocolAvailable(reference, newValue ? 1 : 0)
    //     }

    // }

    // public var wasFetchedViaProxy: Bool {
    	
    // 	get {
    //         return _WebURLResponseWasFetchedViaProxy(reference) == 0 ? false : true
    //     }

    //     set {
    //         _WebURLResponseSetWasFetchedViaProxy(reference, newValue ? 1 : 0)
    //     }

    // }

	// public var wasFetchedViaServiceWorker: Bool {
    
 //        get {
 //            return _WebURLResponseWasFetchedViaServiceWorker(reference) == 0 ? false : true
 //        }

 //        set {
 //            _WebURLResponseSetWasFetchedViaServiceWorker(reference, newValue ? 1 : 0)
 //        }

 //    }

	// public var wasFallbackRequiredByServiceWorker: Bool {
    	
 //    	get {
 //            return _WebURLResponseWasFallbackRequiredByServiceWorker(reference) == 0 ? false : true
 //        }

 //        set {
 //            _WebURLResponseSetWasFallbackRequiredByServiceWorker(reference, newValue ? 1 : 0)
 //        }

 //    }

	// public var serviceWorkerResponseType: WebServiceWorkerResponseType {

	// 	get {
 //    		let result = _WebURLResponseGetServiceWorkerResponseType(reference)
 //    		return WebServiceWorkerResponseType(rawValue: Int(result))!
 //    	}
        
 //    	set {
 //    		_WebURLResponseSetServiceWorkerResponseType(reference, Int32(newValue.rawValue))
 //    	}

	// }

    // public var originalURLViaServiceWorker: URL? {

    // 	get {
    //         let result = _WebURLResponseGetOriginalURLViaServiceWorker(reference)
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
    //             _WebURLResponseSetOriginalURLViaServiceWorker(reference, urlbuf)
    //         }
    //     }
    // }

    public var downloadFilePath: String {
    	get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetDownloadFilePath(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
                if str != nil {
                    this._downloadFilePath = String(cString: str!)
                } else {
                    this._downloadFilePath = String()
                }
            })
            return _downloadFilePath
        }

        set (path) {
            path.withCString { pathbuf in
                _WebURLResponseSetDownloadFilePath(reference, pathbuf)
            }
        }
    }

    public var remoteIPAddress: String {
    	get {
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetRemoteIPAddress(reference, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
                if str != nil {
                    this._remoteIPAddress = String(cString: str!)
                } else {
                    this._remoteIPAddress = String()
                }
            })
            return _remoteIPAddress
        }

        set (address) {
            address.withCString { addressbuf in
                _WebURLResponseSetRemoteIPAddress(reference, addressbuf)
            }
        }
    }

    public var remotePort: Int16 {
    	
    	get {
            return _WebURLResponseGetRemotePort(reference)
        }
        
        set {
            _WebURLResponseSetRemotePort(reference, newValue)
        }

    }

    public var extraData: ExtraData? {
    	
    	get {
    		return nil
    	}

    	set {

    	}
    }
    
    var reference: WebURLResponseRef
    private var _url: String = String()
    private var _appCacheManifestURL: String = String()
    private var _remoteIPAddress: String = String()
    private var _downloadFilePath: String = String()
    private var _httpStatus: String = String()
    private var _mimeType: String = String()
    private var _httpHeaderField: String = String()

    public init(reference: WebURLResponseRef) {
    	self.reference = reference
    }

    deinit {
		_WebURLResponseDestroy(reference)    	
    }

    public func setResponseTime(time: Int64) {
    	_WebURLResponseSetResponseTime(reference, time)
    }

    public func getHttpHeaderField(name: String) -> String {
        name.withCString { (strbuf: UnsafePointer<CChar>) in
            let selfPtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
            _WebURLResponseGetHttpHeaderField(reference, strbuf, selfPtr, { (state: UnsafeMutableRawPointer?, str: UnsafePointer<Int8>?, len: Int) in
                let this = unsafeBitCast(state, to: WebURLResponse.self)
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
                _WebURLResponseSetHTTPHeaderField(reference, namebuf, valuebuf)
            }
        }
    }
    
    public func addHTTPHeaderField(name: String, value: String) {
    	name.withCString { namebuf in
            value.withCString { valuebuf in
                _WebURLResponseAddHTTPHeaderField(reference, namebuf, valuebuf)
            }
        }
    }
    
    public func clearHTTPHeaderField(name: String) {
    	name.withCString { namebuf in
            _WebURLResponseClearHTTPHeaderField(reference, namebuf)
        }
    }
    
    //public func visitHTTPHeaderFields(visitor: WebHTTPHeaderVisitor) {}

  
    public func setSecurityDetails(
        proto: String, 
        key: String, 
        keyGroup: String, 
        cypher: String, 
        mac: String, 
        subjectName: String,
        issuer: String, 
        validFrom: Bool,
        validTo: Bool) {
    	
        proto.withCString { protobuf in
    		key.withCString { keybuf in
                keyGroup.withCString { keygrbuf in
                    cypher.withCString { cypherbuf in
    			        mac.withCString { macbuf in
    				        subjectName.withCString { subjbuf in
                                issuer.withCString { issuerbuf in
            			          _WebURLResponseSetSecurityDetails(reference, protobuf, keybuf, keygrbuf, cypherbuf, macbuf, subjbuf, issuerbuf, validFrom ? 1 : 0, validTo ? 1 : 0)
                                }
            		        }
            	        }
        	        }
                }
            }
        }
    }

}