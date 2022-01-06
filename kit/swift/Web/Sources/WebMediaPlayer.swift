// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import MumbaShims
import Graphics
import Compositor

public enum MediaContentType : Int {
  // Type indicating that a player is persistent, which needs to take audio
  // focus to play.
  case Persistent = 0
  // Type indicating that a player only plays a transient sound.
  case Transient = 1
  // Type indicating that a player is a Pepper instance. MediaSession may duck
  // the player instead of pausing it.
  case Pepper = 2
  // Type indicating that a player cannot be controlled. MediaSession will take
  // audio focus when the player joins but will not let it respond to audio
  // focus changes.
  case OneShot = 3
}

public enum WebFullscreenVideoStatus : Int {
  // Video is not effectively fullscreen.
  case NotEffectivelyFullscreen = 0
  // Video is fullscreen and allowed to enter Picture-in-Picture.
  case FullscreenAndPictureInPictureEnabled = 1
  // Video is fullscreen and is not allowed to enter Picture-in-Picture.
  case FullscreenAndPictureInPictureDisabled = 2
}

public struct WebMediaPlayerAction {

    public enum Kind : Int {
    	case Unknown = 0
    	case Play
        case Mute
        case Loop
        case Controls
    }

    public var type: Kind
    public var enable: Bool

    public init(type: Kind, enable: Bool) {
      self.type = type
      self.enable = enable
    }
}

public class WebMediaSession {

	var reference: WebMediaSessionRef

	init(reference: WebMediaSessionRef) {
		self.reference = reference
	}

}

public struct WebMediaStream {}

public class WebMediaPlayerEncryptedMediaClient {

    var reference: WebMediaPlayerClientRef

    init(reference: WebMediaPlayerClientRef) {
        self.reference = reference
    }
}

public enum WebMediaPlayerLoadType : Int {
    case URL = 0
    case MediaSource = 1
    case MediaStream = 2
}

public enum WebMediaPlayerPreload : Int {
    case None = 0 
    case MetaData = 1
    case Auto = 2
}

public class WebMediaPlayerClient {

  var reference: WebMediaPlayerClientRef

  init(reference: WebMediaPlayerClientRef) {
      self.reference = reference
  }
}

// blink.WebMediaPlayer.PipWindowOpenedCallback
public typealias PipWindowOpenedCallback = () -> Void
public typealias ClosureCallback = () -> Void

public protocol WebMediaPlayerDelegateObserver {
    func onFrameHidden()
    func onFrameClosed()
    func onFrameShown()
    func onIdleTimeout()
    func onPlay()
    func onPause()
    func onSeekForward(to: TimeDelta)
    func onSeekBackward(to: TimeDelta)
    func onVolumeMultiplierUpdate(multiplier: Double)
    func onBecamePersistentVideo(value: Bool)
    func onPictureInPictureModeEnded()
}

public protocol WebMediaPlayerDelegate : class {
    var isFrameHidden: Bool { get }
    var isFrameClosed: Bool { get }
    var unretainedReference: UnsafeMutableRawPointer? { get }

    func createWebMediaPlayerDelegateCallbacks() -> WebMediaPlayerDelegateCallbacks
    func addObserver(_ observer: WebMediaPlayerDelegateObserver) -> Int
    func removeObserver(playerId: Int)
    func didPlay(playerId: Int,
                 hasVideo: Bool,
                 hasAudio: Bool,
                 contentType: MediaContentType)
    func didPause(playerId: Int)
    func playerGone(playerId: Int)
    func setIdle(playerId: Int, isIdle: Bool)
    func isIdle(playerId: Int) -> Bool
    func clearStaleFlag(playerId: Int)
    func isStale(playerId: Int) -> Bool
    func setIsEffectivelyFullscreen(
      playerId: Int,
      status: WebFullscreenVideoStatus)
    func didPlayerSizeChange(delegateId: Int, size: IntSize)
    func didPlayerMutedStatusChange(delegateId: Int, muted: Bool)
    func didPictureInPictureModeStart(
      delegateId: Int,
      surfaceId: SurfaceId,
      size: IntSize,
      callback: PipWindowOpenedCallback)
    func didPictureInPictureSourceChange(delegateId: Int)
    func didPictureInPictureModeEnd(delegateId: Int, _ cb: ClosureCallback?)
    func didPictureInPictureSurfaceChange(delegateId: Int,
                                          surfaceId: SurfaceId,
                                          size: IntSize)
    func onPictureInPictureSurfaceIdUpdated(delegateId: Int, surfaceId: SurfaceId, size: IntSize)
    func onExitPictureInPicture(delegateId: Int)
    func onMediaDelegatePause(playerId: Int)
    func onMediaDelegatePlay(playerId: Int)
    func onMediaDelegateSeekForward(playerId: Int, to: TimeDelta)
    func onMediaDelegateSeekBackward(playerId: Int, to: TimeDelta)
    func onMediaDelegateSuspendAllMediaPlayers()
    func onMediaDelegateVolumeMultiplierUpdate(playerId: Int, multiplier: Double)
    func onMediaDelegateBecamePersistentVideo(playerId: Int, value: Bool)
    func onPictureInPictureModeEnded(playerId: Int)
}

public class WebMediaPlayer : WebMediaPlayerDelegateObserver {

    public enum CORSMode : Int {
        case unspecified = 0
        case anonymous = 1
        case useCredentials = 2
    }

    public var hasVideo: Bool {
        return _WebMediaPlayerHasVideo(reference) != 0
    }
    
    public var hasAudio: Bool {
        return _WebMediaPlayerHasAudio(reference) != 0
    }

    public var naturalSize: IntSize {
        var w: CInt = 0
        var h: CInt = 0
        _WebMediaPlayerGetNaturalSize(reference, &w, &h)
        return IntSize(width: Int(w), height: Int(h))
    }

    public var visibleRect: IntSize {
        var w: CInt = 0
        var h: CInt = 0
        _WebMediaPlayerGetVisibleRect(reference, &w, &h)
        return IntSize(width: Int(w), height: Int(h))
    }

    public var paused: Bool {
        return _WebMediaPlayerIsPaused(reference) != 0
    }

    public var seeking: Bool {
        return _WebMediaPlayerIsSeeking(reference) != 0
    }

    public var duration: Double {
        return _WebMediaPlayerGetDuration(reference)
    }

    public var timelineOffset: Double {
        return _WebMediaPlayerGetTimelineOffset(reference)
    }

    public var currentTime: Double {
        return _WebMediaPlayerGetCurrentTime(reference)
    }

    public var networkState: MediaNetworkState {
        return MediaNetworkState(rawValue: Int(_WebMediaPlayerGetNetworkState(reference)))!
    }
    
    public var readyState: MediaReadyState {
        return MediaReadyState(rawValue: Int(_WebMediaPlayerGetRadyState(reference)))!
    }

    public var errorMessage: String {
        var len: CInt = 0
      guard let ref = _WebMediaPlayerGetErrorMessage(reference, &len) else {
          return String()
      }
      return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var decodedFrameCount: UInt {
        return UInt(_WebMediaPlayerGetDecodedFrameCount(reference))
    }

    public var droppedFrameCount: UInt {
        return UInt(_WebMediaPlayerGetDroppedFrameCount(reference))
    }

    public var audioDecodedByteCount: UInt {
        return UInt(_WebMediaPlayerGetAudioDecodedByteCount(reference))
    }

    public var videoDecodedByteCount: UInt {
        return UInt(_WebMediaPlayerGetVideoDecodedByteCount(reference))
    }

    public var buffered: TimeRanges {
        var len: CInt = 0
        var startPtr: UnsafeMutablePointer<Double>?
        var endPtr: UnsafeMutablePointer<Double>?
        _WebMediaPlayerGetBuffered(reference, &len, &startPtr, &endPtr)
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

    public var seekable: TimeRanges {
        var len: CInt = 0
        var startPtr: UnsafeMutablePointer<Double>?
        var endPtr: UnsafeMutablePointer<Double>?
        _WebMediaPlayerGetSeekable(reference, &len, &startPtr, &endPtr)
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

    public private(set) var reference: WebMediaPlayerRef

    public init(delegate: WebMediaPlayerDelegate,
                frame: WebLocalFrame,
                url: String,
                client: WebMediaPlayerClient,
                encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
                module: WebContentDecryptionModule?, 
                sinkId: String,
                view: WebView) {
        var urlCStr: UnsafePointer<CChar>? 
        var sinkIdCStr: UnsafePointer<CChar>?

        url.withCString { urlCStr = $0 }

        if !sinkId.isEmpty {
            sinkId.withCString { sinkIdCStr = $0 }
        }
        
        reference = _WebMediaPlayerCreateURL(
            delegate.unretainedReference,
            delegate.createWebMediaPlayerDelegateCallbacks(),
            frame.reference,
            urlCStr,
            client.reference,
            encryptedClient != nil ? encryptedClient!.reference : nil,
            module != nil ? module!.reference : nil,
            sinkIdCStr,
            view.nativeWebViewClient)
    }

    public init(delegate: WebMediaPlayerDelegate,
                frame: WebLocalFrame,
                descriptor: MediaStreamDescriptor,
                client: WebMediaPlayerClient,
                encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
                module: WebContentDecryptionModule?, 
                sinkId: String,
                view: WebView) {
        var sinkIdCStr: UnsafePointer<CChar>? 
        if !sinkId.isEmpty {
            sinkId.withCString { sinkIdCStr = $0 }
        }

        reference = _WebMediaPlayerCreateMediaStreamDescriptor(
            delegate.unretainedReference,
            delegate.createWebMediaPlayerDelegateCallbacks(),
            frame.reference,
            descriptor.reference,
            client.reference,
            encryptedClient != nil ? encryptedClient!.reference : nil,
            module != nil ? module!.reference : nil,
            sinkIdCStr,
            view.nativeWebViewClient)
    }

    public init(delegate: WebMediaPlayerDelegate,
                frame: WebLocalFrame,
                id: String,
                name: String,
                type: MediaStreamSourceType,
                remote: Bool,
                client: WebMediaPlayerClient,
                encryptedClient: WebMediaPlayerEncryptedMediaClient?, 
                module: WebContentDecryptionModule?, 
                sinkId: String,
                view: WebView) {
        var idCStr: UnsafePointer<CChar>?
        var nameCStr: UnsafePointer<CChar>? 
        var sinkIdCStr: UnsafePointer<CChar>? 

        id.withCString { idCStr = $0 }
        name.withCString { nameCStr = $0 }
        if !sinkId.isEmpty {
            sinkId.withCString { sinkIdCStr = $0 }
        }

        if type == .Video {
            reference = _WebMediaPlayerCreateMediaStreamVideo(
                delegate.unretainedReference,
                delegate.createWebMediaPlayerDelegateCallbacks(),
                frame.reference,
                idCStr,
                nameCStr,
                remote ? 1 : 0,
                client.reference,
                encryptedClient != nil ? encryptedClient!.reference : nil,
                module != nil ? module!.reference : nil,
                sinkIdCStr,
                view.nativeWebViewClient)
            return
        }   
        reference = _WebMediaPlayerCreateMediaStreamAudio(
                delegate.unretainedReference,
                delegate.createWebMediaPlayerDelegateCallbacks(),
                frame.reference,
                idCStr,
                nameCStr,
                remote ? 1 : 0,
                client.reference,
                encryptedClient != nil ? encryptedClient!.reference : nil,
                module != nil ? module!.reference : nil,
                sinkIdCStr,
                view.nativeWebViewClient)
    }

    init(reference: WebMediaPlayerRef) {
        self.reference = reference
    }

    deinit {
        _WebMediaPlayerDestroy(reference)
    }

    public func load(loadType: WebMediaPlayerLoadType,
                     url: String,
                     corsMode: CORSMode) {
        url.withCString {                 
            _WebMediaPlayerLoadWithURL(reference, CInt(loadType.rawValue), $0, CInt(corsMode.rawValue))
        }
    }

    public func load(loadType: WebMediaPlayerLoadType,
                     stream: WebMediaStream,
                     corsMode: CORSMode) {
       assert(false)
    }

    public func play() {
        _WebMediaPlayerPlay(reference)
    }

    public func pause() {
        _WebMediaPlayerPause(reference)
    }

    public func seek(to: TimeDelta) {
        _WebMediaPlayerSeek(reference, Double(to.seconds))
    }

    public func setRate(_ rate: Double) {
        _WebMediaPlayerSetRate(reference, rate)
    }

    public func setVolume(_ volume: Double) {
        _WebMediaPlayerSetVolume(reference, volume)
    }
    
    public func mediaTimeForTimeValue(timeValue: Double) -> Double {
        return _WebMediaPlayerGetMediaTimeForTimeValue(reference, timeValue)
    }

    public func onFrameHidden() {
        print("WebMediaPlayer.onFrameHidden")
        _WebMediaPlayerOnFrameHidden(reference)
    }

    public func onFrameClosed() {
        print("WebMediaPlayer.onFrameClosed")
        _WebMediaPlayerOnFrameClosed(reference)
    }

    public func onFrameShown() {
        print("WebMediaPlayer.onFrameShown")
        _WebMediaPlayerOnFrameShown(reference)
    }
    
    public func onIdleTimeout() {
        _WebMediaPlayerOnIdleTimeout(reference)
    }

    public func onPlay() {
        _WebMediaPlayerOnPlay(reference)
    }
    
    public func onPause() {
        _WebMediaPlayerOnPause(reference)
    }
    public func onSeekForward(to: TimeDelta) {
        _WebMediaPlayerOnSeekForward(reference, Double(to.seconds))
    }

    public func onSeekBackward(to: TimeDelta) {
        _WebMediaPlayerOnSeekBackward(reference, Double(to.seconds))
    }

    public func onVolumeMultiplierUpdate(multiplier: Double) {
        _WebMediaPlayerOnVolumeMultiplierUpdate(reference, multiplier)
    }
    
    public func onBecamePersistentVideo(value: Bool) {
        _WebMediaPlayerOnBecamePersistentVideo(reference, value ? 1 : 0)   
    }
    
    public func onPictureInPictureModeEnded() {
        _WebMediaPlayerOnPictureInPictureModeEnded(reference)
    }
    
}