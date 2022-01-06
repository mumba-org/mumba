// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebHTTPLoadInfo {
    
    public var httpStatusCode: Int { 
        get {
            return Int(_WebHTTPLoadInfoGetHttpStatusCode(reference))
        }
        
        set {
            _WebHTTPLoadInfoSetHttpStatusCode(reference, Int32(newValue))
        }
    }


    public var httpStatusText: String {
        
        get {
            let result = _WebHTTPLoadInfoGetHttpStatusText(reference)
            if result == nil {
                return String()
            }
            return String(cString: result!)
        }

        set (status) {
            status.withCString { statusbuf in
                _WebHTTPLoadInfoSetHttpStatusText(reference, statusbuf)
            }
        }

    }

    // public var encodedDataLength: Int64 {
        
    //     get {
    //         return _WebHTTPLoadInfoGetEncodedDataLength(reference)
    //     }
        
    //     set {
    //         _WebHTTPLoadInfoSetEncodedDataLength(reference, newValue)
    //     }

    // }

    public var requestHeadersText: String {
        
        get {
            let result = _WebHTTPLoadInfoGetRequestHeadersText(reference)
            if result == nil {
                return String()
            }
            return String(cString: result!)
        }

        set (headers) {
            headers.withCString { headersbuf in
                _WebHTTPLoadInfoSetRequestHeadersText(reference, headersbuf)
            }
        }

    }

    public var responseHeadersText: String {
        
        get {
            let result = _WebHTTPLoadInfoGetResponseHeadersText(reference)
            if result == nil {
                return String()
            }
            return String(cString: result!)
        }

        set (headers) {
            headers.withCString { headersbuf in
                _WebHTTPLoadInfoSetResponseHeadersText(reference, headersbuf)
            }
        }

    }

    public var npnNegotiatedProtocol: String {
        
        get {
            let result = _WebHTTPLoadInfoGetNpnNegotiatedProtocol(reference)
            if result == nil {
                return String()
            }
            return String(cString: result!)
        }

        set (proto) {
            proto.withCString { protobuf in
                _WebHTTPLoadInfoSetNpnNegotiatedProtocol(reference, protobuf)
            }
        }
    }

    var reference: WebHTTPLoadInfoRef

    public init() {
        reference = _WebHTTPLoadInfoCreate()
    }

    init(reference: WebHTTPLoadInfoRef) {
        self.reference = reference
    }

    deinit {
        _WebHTTPLoadInfoDestroy(reference)
    }

    public func addRequestHeader(name: String, value: String) {
        name.withCString { namebuf in
            value.withCString { valuebuf in
                _WebHTTPLoadInfoAddRequestHeader(reference, namebuf, valuebuf)
            }
        }
    }
    
    public func addResponseHeader(name: String, value: String) {
        name.withCString { namebuf in
            value.withCString { valuebuf in
                _WebHTTPLoadInfoAddResponseHeader(reference, namebuf, valuebuf)
            }
        }
    }

}