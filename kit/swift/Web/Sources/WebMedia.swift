// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum MediaStreamSourceType : Int {
    case Audio = 0 
    case Video = 1
}

public enum MediaStreamSourceReadyState : Int {
    case Live = 0
    case Muted = 1
    case Ended = 2
}

public struct MediaStreamSource {
    public var id: String
    public var type: MediaStreamSourceType
    public var name: String
    public var remote: Bool
    public var readyState: MediaStreamSourceReadyState

    public init(id: String, name: String, type: MediaStreamSourceType, remote: Bool = false) {
        self.id = id
        self.type = type
        self.name = name
        self.remote = remote
        readyState = .Live
    }

    public init(id: String, name: String, type: MediaStreamSourceType, remote: Bool, readyState: MediaStreamSourceReadyState) {
        self.id = id
        self.type = type
        self.name = name
        self.remote = remote
        self.readyState = readyState
    }
}

public struct MediaStreamComponent {

    public var source: MediaStreamSource {
        var id: UnsafeMutablePointer<CChar>?
        var idlen: CInt = 0
        var type: CInt = 0
        var name: UnsafeMutablePointer<CChar>?
        var namelen: CInt = 0
        var remote: CInt = 0
        var readystate: CInt = 0
        _WebMediaStreamComponentGetSource(reference,
          &id,
          &idlen,
          &type,
          &name,
          &namelen,
          &remote,
          &readystate)
        return MediaStreamSource(
            id: (id == nil ? String() : String(bytesNoCopy: id!, length: Int(idlen), encoding: String.Encoding.utf8, freeWhenDone: true)!), 
            name: (name == nil ? String() : String(bytesNoCopy: name!, length: Int(namelen), encoding: String.Encoding.utf8, freeWhenDone: true)!), 
            type: MediaStreamSourceType(rawValue: Int(type))!, 
            remote: remote != 0, 
            readyState: MediaStreamSourceReadyState(rawValue: Int(readystate))!)
    }

    public var isEnabled: Bool {
        return _WebMediaStreamComponentIsEnabled(reference) != 0
    }

    public var isMuted: Bool {
        return _WebMediaStreamComponentIsMuted(reference) != 0
    }
    
    var reference: WebMediaStreamComponentRef

    init(reference: WebMediaStreamComponentRef) {
        self.reference = reference
    }
}

public struct AudioTrack {

    public var source: MediaStreamSource {
        return component.source
    }

    public var isEnabled: Bool {
        return component.isEnabled
    }

    public var isMuted: Bool {
        return component.isMuted
    }

    internal var reference: WebMediaStreamComponentRef {
        return component.reference
    }

    internal let component: MediaStreamComponent

    init(reference: WebMediaStreamComponentRef) {
        component = MediaStreamComponent(reference: reference)
    }
}

public struct VideoTrack {

    public var source: MediaStreamSource {
        return component.source
    }

    public var isEnabled: Bool {
        return component.isEnabled
    }

    public var isMuted: Bool {
        return component.isMuted
    }

    internal var reference: WebMediaStreamComponentRef {
        return component.reference
    }

    internal let component: MediaStreamComponent

    init(reference: WebMediaStreamComponentRef) {
        component = MediaStreamComponent(reference: reference)
    }
}

public struct TextTrack {

    internal var reference: WebMediaStreamComponentRef {
        return component.reference
    }

    private let component: MediaStreamComponent

    init(reference: WebMediaStreamComponentRef) {
        component = MediaStreamComponent(reference: reference)
    }
}

public struct MediaStreamDescriptor {

    public var id: String {
        var len: CInt = 0
        let ref = _WebMediaStreamDescriptorGetId(reference, &len)
        return ref != nil ? String(bytesNoCopy: ref!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }

    public var uniqueId: Int {
        return Int(_WebMediaStreamDescriptorGetUniqueId(reference))
    }

    public var audioTracks: [AudioTrack] {
        var tracks: [AudioTrack] = []
        var count: CInt = 0
        var tracksPtr: UnsafeMutablePointer<WebMediaStreamComponentRef?>?
        _WebMediaStreamDescriptorGetAudioTracks(reference, &tracksPtr, &count)
        guard count > 0 else {
            return tracks
        }
        defer {
            free(tracksPtr)
        }
        for i in 0..<Int(count) {
            tracks.append(AudioTrack(reference: tracksPtr![i]!))
        }
        return tracks
    }

    public var videoTracks: [VideoTrack] {
        var tracks: [VideoTrack] = []
        var count: CInt = 0
        var tracksPtr: UnsafeMutablePointer<WebMediaStreamComponentRef?>?
        
        _WebMediaStreamDescriptorGetVideoTracks(reference, &tracksPtr, &count)
        guard count > 0 else {
            return tracks
        }
        defer {
            free(tracksPtr)
        }
        for i in 0..<Int(count) {
            tracks.append(VideoTrack(reference: tracksPtr![i]!))
        }
        return tracks
    }

    public var audioTrackCount: Int {
        return Int(_WebMediaStreamDescriptorGetAudioTrackCount(reference))
    }

    public var videoTrackCount: Int {
        return Int(_WebMediaStreamDescriptorGetVideoTrackCount(reference))
    }
    
    var reference: MediaStreamDescriptorRef

    public init() {
        self.reference = _WebMediaStreamDescriptorCreate()
    }

    init(reference: MediaStreamDescriptorRef) {
        self.reference = reference
    }

    public func getAudioTrack(index: Int) -> AudioTrack? {
        let ref = _WebMediaStreamDescriptorGetAudioTrack(reference, CInt(index))
        return ref != nil ? AudioTrack(reference: ref!) : nil
    }

    public func getAudioTrack(id: String) -> AudioTrack? {
        let ref = id.withCString {
            return _WebMediaStreamDescriptorGetAudioTrackById(reference, $0)
        }
        return ref != nil ? AudioTrack(reference: ref!) : nil
    }

    public func getVideoTrack(index: Int) -> VideoTrack? {
        let ref = _WebMediaStreamDescriptorGetVideoTrack(reference, CInt(index))
        return ref != nil ? VideoTrack(reference: ref!) : nil
    }

    public func getVideoTrack(id: String) -> VideoTrack? {
        let ref = id.withCString {
            return _WebMediaStreamDescriptorGetVideoTrackById(reference, $0)
        }
        return ref != nil ? VideoTrack(reference: ref!) : nil
    }

    public func addTrack(audio: AudioTrack) {
        _WebMediaStreamDescriptorAddTrack(reference, audio.reference)
    }

    public func addTrack(video: VideoTrack) {
        _WebMediaStreamDescriptorAddTrack(reference, video.reference)
    }

    public func removeTrack(audio: AudioTrack) {
        _WebMediaStreamDescriptorRemoveTrack(reference, audio.reference)
    }

    public func removeTrack(video: VideoTrack) {
        _WebMediaStreamDescriptorRemoveTrack(reference, video.reference)
    }
    
}

public struct MediaError {}

public struct MediaControls {
    
    var reference: MediaControlsRef
    
    init(reference: MediaControlsRef) {
        self.reference = reference
    }

    public func maybeShow() {
        _MediaControlsMaybeShow(reference)
    }
    
    public func hide() {
        _MediaControlsHide(reference)
    }

    public func reset() {
        _MediaControlsReset(reference)
    }
}

public struct CueTimeline {

    var reference: CueTimelineRef

    init(reference: CueTimelineRef) {
        self.reference = reference
    }

}

public struct SourceBuffer {
    
    public var mode: String {
        var len: CInt = 0
        let ref = _SourceBufferGetMode(reference, &len)
        return ref != nil ? String(bytesNoCopy: ref!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }
    
    public var isUpdating: Bool {
        return _SourceBufferIsUpdating(reference) != 0
    }

    public var buffered: TimeRanges {
        var len: CInt = 0
        var startPtr: UnsafeMutablePointer<Double>?
        var endPtr: UnsafeMutablePointer<Double>?
        _SourceBufferGetBuffered(reference, &len, &startPtr, &endPtr)
        guard len > 0 else {
            return TimeRanges()
        }
        var result = TimeRanges()
        for i in 0..<Int(len) {
            result.append(TimeRange(start: startPtr![i], end: endPtr![i]))
        }
        free(startPtr)
        free(endPtr)
        return result
    }
    
    public var timestampOffset: Double {
        return _SourceBufferGetTimestampOffset(reference)
    }

    public var appendWindowStart: Double {
        return _SourceBufferAppendWindowStart(reference)
    }

    public var appendWindowEnd: Double {
        return _SourceBufferAppendWindowEnd(reference)
    }

    var reference: SourceBufferRef
    private var listeners: [ListenerHolder] = []

    init(reference: SourceBufferRef) {
        self.reference = reference
    }

    public func appendBuffer(data: ArrayBuffer) {
        _SourceBufferAppendBuffer(reference, data.reference)
    }

    public func abort() {
        _SourceBufferAbort(reference)
    }

    public func remove(start: Double, end: Double) {
        _SourceBufferRemove(reference, start, end)
    }

    public mutating func onUpdateStart(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "updateStart", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _SourceBufferOnUpdateStart(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

    public mutating func onUpdate(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "update", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _SourceBufferOnUpdate(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

    public mutating func onUpdateEnd(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "updateEnd", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _SourceBufferOnUpdateEnd(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

    public mutating func onError(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "error", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _SourceBufferOnError(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

    public mutating func onAbort(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "abort", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _SourceBufferOnAbort(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }
   
}

public struct MediaSource {

    public var duration: Double {
        return _MediaSourceGetDuration(reference)
    }

    public var readyState: String {
        var len: CInt = 0
        let state = _MediaSourceGetReadyState(reference, &len)
        return String(bytesNoCopy: state!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    var reference: MediaSourceRef
    private var listeners: [ListenerHolder] = []

    public init(document: WebDocument) {
        reference = _MediaSourceCreate(document.reference)
    }

    init(reference: MediaSourceRef) {
        self.reference = reference
    }

    public static func isTypeSupported(_ type: String) -> Bool {
        return type.withCString {
            return _MediaSourceIsTypeSupported($0) != 0
        }
    }

    public func addSourceBuffer(type: String) -> SourceBuffer {
        return type.withCString {
            return SourceBuffer(reference: _MediaSourceAddSourceBuffer(reference, $0))
        }
    } 

    public func removeSourceBuffer(_ buffer: SourceBuffer) {
        _MediaSourceRemoveSourceBuffer(reference, buffer.reference)
    }

    public func endOfStream() {
        endOfStream(error: nil)
    }

    public func endOfStream(error: String?) {
        if let err = error, !err.isEmpty {
            err.withCString {
                _MediaSourceEndOfStream(reference, $0)
            }    
            return    
        }  
        _MediaSourceEndOfStream(reference, nil)
    }

    public func setLiveSeekableRange(start: Double, end: Double) {
        _MediaSourceSetLiveSeekableRange(reference, start, end)
    }
    
    public func clearLiveSeekableRange() {
        _MediaSourceClearLiveSeekableRange(reference)
    }

    public mutating func onSourceOpen(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "sourceOpen", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _MediaSourceOnSourceOpen(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

    public mutating func onSourceEnded(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "sourceEnded", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _MediaSourceOnSourceEnded(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }
    
    public mutating func onSourceClose(_ callback: @escaping ListenerCallback) {
        let state = ListenerHolder(event: "sourceClose", callback: callback)
        listeners.append(state)
        let listenerState = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _MediaSourceOnSourceClose(reference, listenerState, { (handle: UnsafeMutableRawPointer?, evhandle: UnsafeMutableRawPointer?) in 
            let holder = unsafeBitCast(handle, to: ListenerHolder.self)
            if let cb = holder.callback {
                cb(Event(reference: evhandle!))
            }
        })
    }

}