// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import MumbaShims

public enum XmlHttpRequestMethod : Int {
    case `get` = 0
    case post = 1
    case delete = 2
    case head = 3
    case options = 4
    case put = 5
}

public enum XmlHttpRequestState : Int {
    case unsent = 0
    case opened = 1
    case headersReceived = 2
    case loading = 3
    case done = 4
}

public enum XmlHttpRequestResponseType : Int {
    case `default` = 0
    case text = 1
    case json = 2
    case document = 3
    case blob = 4
    case arrayBuffer = 5
}

public typealias DefaultCallback = (_: ExecutionContext) -> Void
public typealias ProgressCallback = (_: ProgressEvent) -> Void

public class XmlHttpRequest {

    public var readyState: XmlHttpRequestState {
        return XmlHttpRequestState(rawValue: Int(_XMLHttpRequestGetReadyState(reference)))!
    }
    
    public var status: Int {
        return Int(_XMLHttpRequestGetStatus(reference))
    }

    public var statusText: String {
        var len: CInt = 0
        let strbuf = _XMLHttpRequestGetStatusTextString(reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var timeout: Int64 {
        get {
            return _XMLHttpRequestGetTimeout(reference)
        } 
        set {
            _XMLHttpRequestSetTimeout(reference, newValue)
        }
    }

    public var hasPendingActivity: Bool {
        return _XMLHttpRequestHasPendingActivity(reference) != 0
    }

    public var url: String {
        var len: CInt = 0
        let strbuf = _XMLHttpRequestGetUrl(reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var withCredentials: Bool {
        get {
            return _XMLHttpRequestWithCredentials(reference) != 0
        }
        set {
            _XMLHttpRequestSetWithCredentials(reference, newValue ? 1 : 0)
        }
    }

    public var responseUrl: String {
        var len: CInt = 0
        let strbuf = _XMLHttpRequestGetResponseUrl(reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var responseText: String? {
        var len: CInt = 0

        guard let strbuf = _XMLHttpRequestGetResponseText(reference, &len) else {
            return nil
        }

        return String(bytesNoCopy: strbuf, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var responseXML : WebDocument? {

        guard let ref = _XMLHttpRequestGetResponseXML(reference) else {
            return nil
        }

        return WebDocument(reference: ref)
    }

    public var responseBlob : Blob? {
        
        guard let ref = _XMLHttpRequestGetResponseBlob(reference) else {
            return nil
        }

        return Blob(reference: ref)
    }

    public var responseArrayBuffer: ArrayBuffer? {
        
        guard let ref = _XMLHttpRequestGetResponseArrayBuffer(reference) else {
            return nil
        }

        return ArrayBuffer(reference: ref)
    }

    public var responseType: XmlHttpRequestResponseType {
        get {
            return XmlHttpRequestResponseType(rawValue: Int(_XMLHttpRequestGetResponseType(reference)))!
        }
        set {
            _XMLHttpRequestSetResponseType(reference, CInt(newValue.rawValue))
        }
    }

    public var isAsync: Bool {
        return _XMLHttpRequestIsAsync(reference) != 0
    }

    //public var method: XmlHttpRequestMethod = XmlHttpRequestMethod.UNDEFINED

    var reference: XMLHttpRequestRef
    private var readyStateChangeCallback: DefaultCallback?
    private var timeoutCallback: DefaultCallback?
    private var progressCallback: ProgressCallback?
    private var abortCallback: DefaultCallback?
    private var errorCallback: DefaultCallback?
    private var loadCallback: DefaultCallback?
    private var loadStartCallback: DefaultCallback?
    private var loadEndCallback: DefaultCallback?
    
    public init(document: WebDocument) {
        reference = _XMLHttpRequestCreate(document.reference)       
    }

    init(reference: XMLHttpRequestRef) {
        self.reference = reference
    }

    public func open(method: XmlHttpRequestMethod, url: String) {
        url.withCString {
            _XMLHttpRequestOpen(reference, CInt(method.rawValue), $0)
        }
    }

    public func open(method: XmlHttpRequestMethod, url: String, async: Bool) {
        url.withCString {
            _XMLHttpRequestOpenWithAsync(reference, CInt(method.rawValue), $0, async ? 1 : 0)
        }
    }

    public func open(method: XmlHttpRequestMethod, url: String, async: Bool, username: String, password: String) {
        url.withCString { urlBuf in
            username.withCString { ubuf in
                password.withCString { pbuf in
                    _XMLHttpRequestOpenWithUsername(reference, CInt(method.rawValue), urlBuf,  async ? 1 : 0, ubuf, pbuf)
                }
            }
        }
    }

    public func send() {
        _XMLHttpRequestSend(reference)
    }

    public func abort() {
        _XMLHttpRequestAbort(reference)
    }

    public func setRequestHeader(name: String, value: String) {
        name.withCString { nameStr in
            value.withCString { valStr in
                _XMLHttpRequestSetRequestHeader(reference, nameStr, valStr)
            }
        }
    }

    public func overrideMimeType(_ type: String) {
        type.withCString { 
            _XMLHttpRequestOverrideMimeType(reference, $0)
        }
    }

    public func getAllResponseHeaders() -> String {
        var len: CInt = 0
        let strbuf = _XMLHttpRequestGetAllResponseHeaders(reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public func getResponseHeader(name: String) -> String {
        var len: CInt = 0
        let strbuf = name.withCString { 
           return _XMLHttpRequestGetResponseHeader(reference, $0, &len)
        }
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public func onReadyStateChange(_ callback: @escaping DefaultCallback) {
        self.readyStateChangeCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnReadyStateChangeCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.readyStateChangeCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onTimeout(_ callback: @escaping DefaultCallback) {
        self.timeoutCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnTimeoutCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.timeoutCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onProgress(_ callback: @escaping ProgressCallback) {
        self.progressCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnProgressCallback(reference, state, { (handle: UnsafeMutableRawPointer?, lengthComputable: CInt, loaded: UInt64, total: UInt64) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.progressCallback {
                cb(ProgressEvent(isLengthComputable: lengthComputable != 0, loaded: loaded, total: total))
            }
        });
    }

    public func onAbort(_ callback: @escaping DefaultCallback) {
        self.abortCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnAbortCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.abortCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onError(_ callback: @escaping DefaultCallback) {
        self.errorCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnErrorCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.errorCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onLoad(_ callback: @escaping DefaultCallback) {
        self.loadCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnLoadCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.loadCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onLoadStart(_ callback: @escaping DefaultCallback) {
        self.loadStartCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnLoadStartCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.loadStartCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

    public func onLoadEnd(_ callback: @escaping DefaultCallback) {
        self.loadEndCallback = callback
        let state = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _XMLHttpRequestSetOnTimeoutCallback(reference, state, { (handle: UnsafeMutableRawPointer?, context: UnsafeMutableRawPointer?, event: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(handle, to: XmlHttpRequest.self)
            if let cb = this.loadEndCallback {
                cb(ExecutionContext(reference: context!))
            }
        });
    }

}