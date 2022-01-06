// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Compositor

public enum MediaReadyState : Int {
  case HaveNothing
  case HaveMetadata
  case HaveCurrentData
  case HaveFutureData
  case HaveEnoughData
}

struct MediaDelayedActionType : OptionSet {

  public static let loadMediaResource = MediaDelayedActionType(rawValue: 1)
  public static let loadTextTrackResource = MediaDelayedActionType(rawValue: 2)
  public static let loadMediaAndTextTrackResource = MediaDelayedActionType(rawValue: 3)

  public var rawValue: Int

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
}

public enum MediaNetworkState : Int {
  case Empty = 0
  case Idle = 1
  case Loading = 2
  case NoSource = 3
}

public class HtmlMediaElement : HtmlElement {

    public var effectiveMediaVolume: Double {
      return _HTMLMediaElementGetEffectiveMediaVolume(reference)
    }

    public var isHTMLAudioElement: Bool {
      _HTMLMediaElementIsHtmlAudioElement(reference) != 0
    }

    public var isHTMLVideoElement: Bool {
      _HTMLMediaElementIsHtmlVideoElement(reference) != 0
    }

    public var loadType: WebMediaPlayerLoadType {
      return WebMediaPlayerLoadType(rawValue: Int(_HTMLMediaElementGetLoadType(reference)))!
    }

    public var hasMediaSource: Bool {
      return _HTMLMediaElementHasMediaSource(reference) != 0
    }

    public var hasVideo: Bool {
      return _HTMLMediaElementHasVideo(reference) != 0
    }

    public var hasAudio: Bool {
      return _HTMLMediaElementHasAudio(reference) != 0
    }

    public var compositorLayer: Compositor.Layer? {
      guard let ref = _HTMLMediaElementGetWebLayer(reference) else {
        return nil
      }
      return Compositor.Layer(reference: ref)
    }

    public var hasRemoteRoutes: Bool {
      return _HTMLMediaElementHasRemoteRoutes(reference) != 0
    }

    public var isPlayingRemotely: Bool {
      return _HTMLMediaElementIsPlayingRemotely(reference) != 0
    }

    public var readyState: MediaReadyState {
      return MediaReadyState(rawValue: Int(_HTMLMediaElementGetReadyState(reference)))!
    } 

    public var seeking: Bool {
      return _HTMLMediaElementIsSeeking(reference) != 0
    }

    public var played: TimeRanges? {
      var len: CInt = 0
      var startPtr: UnsafeMutablePointer<Double>?
      var endPtr: UnsafeMutablePointer<Double>?
      _HTMLMediaElementGetPlayed(reference, &len, &startPtr, &endPtr)
      guard len > 0 else {
        return nil
      }
      var result = TimeRanges()
      for i in 0..<Int(len) {
        result.append(TimeRange(start: startPtr![i], end: endPtr![i]))
      }
      free(startPtr)
      free(endPtr)
      return result
    }

    public var seekable: TimeRanges? {
      var len: CInt = 0
      var startPtr: UnsafeMutablePointer<Double>?
      var endPtr: UnsafeMutablePointer<Double>?
      _HTMLMediaElementGetSeekable(reference, &len, &startPtr, &endPtr)
      guard len > 0 else {
        return nil
      }
      var result = TimeRanges()
      for i in 0..<Int(len) {
        result.append(TimeRange(start: startPtr![i], end: endPtr![i]))
      }
      free(startPtr)
      free(endPtr)
      return result
    }

    public var ended: Bool {
      return _HTMLMediaElementEnded(reference) != 0
    }

    public var currentTime: Double {
      get {
        return _HTMLMediaElementGetCurrentTime(reference)
      }
      set {
        _HTMLMediaElementSetCurrentTime(reference, newValue)
      }
    }

    public var duration: Double {
      return _HTMLMediaElementGetDuration(reference)
    }

    public var paused: Bool {
      return _HTMLMediaElementIsPaused(reference) != 0
    }

    public var defaultPlaybackRate: Double {
      get {
        return _HTMLMediaElementGetDefaultPlaybackRate(reference)
      }
      set {
        _HTMLMediaElementSetDefaultPlaybackRate(reference, newValue)
      }
    }

    public var playbackRate: Double {
      get {
        return _HTMLMediaElementGetPlaybackRate(reference)
      }
      set {
        _HTMLMediaElementSetPlaybackRate(reference, newValue)
      }
    }

    public var error: MediaError? {
      //_HTMLMediaElementGetError(reference)
      return nil
    }

    public var src: String {
      get {
        var len: CInt = 0
        guard let ref = _HTMLMediaElementGetSrc(reference, &len) else {
            return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
      set {
        newValue.withCString {
          _HTMLMediaElementSetSrc(reference, $0)
        }
      }
    }

    public var srcObject: MediaStreamDescriptor {
      get {
        return MediaStreamDescriptor(reference: _HTMLMediaElementGetSrcObject(reference))
      }
      set {
        _HTMLMediaElementSetSrcObject(reference, newValue.reference)
      }
    }

    public var networkState: MediaNetworkState {
      return MediaNetworkState(rawValue: Int(_HTMLMediaElementGetNetworkState(reference)))!
    }

    public var preload: String {
      get {
        var len: CInt = 0
        guard let ref = _HTMLMediaElementGetPreload(reference, &len) else {
            return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
      set {
        newValue.withCString {
          _HTMLMediaElementSetPreload(reference, $0)
        }
      }
    }

    public var preloadType: WebMediaPlayerPreload {
      return WebMediaPlayerPreload(rawValue: Int(_HTMLMediaElementGetPreloadType(reference)))!
    }

    public var effectivePreload: String {
      var len: CInt = 0
      guard let ref = _HTMLMediaElementGetEffectivePreload(reference, &len) else {
          return String()
      }
      return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public var effectivePreloadType: WebMediaPlayerPreload {
      return WebMediaPlayerPreload(rawValue: Int(_HTMLMediaElementGetEffectivePreloadType(reference)))!
    }

    public var buffered: TimeRanges? {
      var len: CInt = 0
      var startPtr: UnsafeMutablePointer<Double>?
      var endPtr: UnsafeMutablePointer<Double>?
      _HTMLMediaElementGetBuffered(reference, &len, &startPtr, &endPtr)
      guard len > 0 else {
        return nil
      }
      var result = TimeRanges()
      for i in 0..<Int(len) {
        result.append(TimeRange(start: startPtr![i], end: endPtr![i]))
      }
      free(startPtr)
      free(endPtr)
      return result
    }

    public var autoplay: Bool {
      _HTMLMediaElementAutoplay(reference) != 0
    }

    public var loop: Bool {
      get {
        return _HTMLMediaElementGetLoop(reference) != 0
      } 
      set {
        _HTMLMediaElementSetLoop(reference, newValue ? 1 : 0)
      } 
    }

    public var audioDecodedByteCount: Int {
      return Int(_HTMLMediaElementGetAudioDecodedByteCount(reference))
    }

    public var videoDecodedByteCount: Int {
      return Int(_HTMLMediaElementGetVideoDecodedByteCount(reference))
    }

    // Returns this media element is in a cross-origin frame.
    public var isInCrossOriginFrame: Bool {
      return _HTMLMediaElementIsInCrossOriginFrame(reference) != 0
    }

    public var volume: Double {
      get {
        return _HTMLMediaElementGetVolume(reference)
      }
      set {
        _HTMLMediaElementSetVolume(reference, newValue)
      }
    }

    public var muted: Bool {
      get {
        return _HTMLMediaElementGetMuted(reference) != 0
      }
      set {
        _HTMLMediaElementSetMuted(reference, newValue ? 1 : 0)
      }
    }

    public var isFullscreen: Bool {
      return _HTMLMediaElementIsFullscreen(reference) != 0
    }
    
    public var usesOverlayFullscreenVideo: Bool {
      return _HTMLMediaElementUsesOverlayFullscreenVideo(reference) != 0
    }

    public var hasClosedCaptions: Bool {
      return _HTMLMediaElementHasClosedCaptions(reference) != 0
    }
    
    public var textTracksVisible: Bool {
      return _HTMLMediaElementTextTracksVisible(reference) != 0
    }

    // public var mediaControls: MediaControls? {
    //   guard let ref = _HTMLMediaElementGetMediaControls(reference) else {
    //     return nil
    //   }
    //   return MediaControls(reference: ref)
    // }

    // public var AudioSourceNode: AudioSourceProviderClient? {
    //   get {
    //     _HTMLMediaElementGetAudioSourceNode(reference)
    //   }
    //   set {
    //     _HTMLMediaElementSetAudioSourceNode(reference, nil)
    //   }
    // }

    // public var controlsList: DOMTokenList? {
    //   _HTMLMediaElementGetControlsList(reference)
    // }
    
    public var supportsPictureInPicture: Bool {
      return _HTMLMediaElementSupportsPictureInPicture(reference) != 0 
    }

    public var lastSeekTime: Double {
      return _HTMLMediaElementLastSeekTime(reference)
    }

    public var audioTracks: [AudioTrack] {
      var len: CInt = 0
      let ref = _HTMLMediaElementGetAudioTracks(reference, &len)
      guard len > 0 else {
        return []
      }
      var result = Array<AudioTrack>()
      for i in 0..<Int(len) {
        result.append(AudioTrack(reference: ref![i]!)) 
      }
      free(ref)
      return result
    }

    public var videoTracks: [VideoTrack] {
      var len: CInt = 0
      let ref = _HTMLMediaElementGetVideoTracks(reference, &len)
      guard len > 0 else {
        return []
      }
      var result = Array<VideoTrack>()
      for i in 0..<Int(len) {
        result.append(VideoTrack(reference: ref![i]!))
      }
      free(ref)
      return result
    }

    public var textTracks: [TextTrack]? {
      var len: CInt = 0
      let ref = _HTMLMediaElementGetTextTracks(reference, &len)
      guard len > 0 else {
        return []
      }
      var result = Array<TextTrack>()
      for i in 0..<Int(len) {
        result.append(TextTrack(reference: ref![i]!))
      }
      free(ref)
      return result
    }

    public var cueTimeline: CueTimeline {
      let ref = _HTMLMediaElementGetCueTimeline(reference)
      return CueTimeline(reference: ref!)
    }

    public var textTracksAreReady: Bool {
      return _HTMLMediaElementTextTracksAreReady(reference) != 0
    }

    public var shouldShowControls: Bool {
      return _HTMLMediaElementShouldShowControls(reference) != 0
    }

    public init(name: String, document: WebDocument) {
      var nameStr: UnsafePointer<Int8>?
      name.withCString {
        nameStr = $0
      }
      super.init(reference: _HTMLMediaElementCreate(nameStr, document.reference))
    }

    required init(reference: WebNodeRef) {
        super.init(reference: reference)
    }
 
    public func scheduleTextTrackResourceLoad() {
      _HTMLMediaElementScheduleTextTrackResourceLoad(reference)
    }

    public func load() {
      _HTMLMediaElementLoad(reference)
    }

    public func canPlayType(mimeType: String) -> String {
      return mimeType.withCString { mimeCStr in
        var len: CInt = 0
        guard let ref = _HTMLMediaElementCanPlayType(reference, mimeCStr, &len) else {
          return String()
        }
        return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
      }
    }

    public func updatePlaybackRate() {
      _HTMLMediaElementUpdatePlaybackRate(reference)
    }
    
    public func play() {
      _HTMLMediaElementPlay(reference)
    }

    public func pause() {
      _HTMLMediaElementPause(reference)
    }

    public func requestRemotePlayback() {
      _HTMLMediaElementRequestRemotePlayback(reference)
    }

    public func requestRemotePlaybackControl() {
      _HTMLMediaElementRequestRemotePlaybackControl(reference)
    }

    public func requestRemotePlaybackStop() {
      _HTMLMediaElementRequestRemotePlaybackStop(reference)
    }

    public func closeMediaSource() {
      _HTMLMediaElementCloseMediaSource(reference)
    }

    public func durationChanged(duration: Double, requestSeek: Double) {
      _HTMLMediaElementDurationChanged(reference, duration, requestSeek)
    }
    
    public func enterPictureInPicture() {
      _HTMLMediaElementEnterPictureInPicture(reference)
    }
    
    public func exitPictureInPicture() {
      _HTMLMediaElementExitPictureInPicture(reference)
    }

    public func togglePlayState() {
      _HTMLMediaElementTogglePlayState(reference)
    }

    public func audioTrackChanged(track: AudioTrack) {
      _HTMLMediaElementAudioTrackChanged(reference, track.reference)
    }

    public func selectedVideoTrackChanged(track: VideoTrack) {
      _HTMLMediaElementSelectedVideoTrackChanged(reference, track.reference)
    }

    public func addTextTrack(kind: String,
                             label: String,
                             language: String) -> TextTrack {
      var kindStr: UnsafePointer<Int8>?
      var labelStr: UnsafePointer<Int8>?
      var langStr: UnsafePointer<Int8>?

      kind.withCString { kindStr = $0 }
      label.withCString { labelStr = $0 }
      language.withCString { langStr = $0 }
      let ref = _HTMLMediaElementAddTextTrackWithStrings(reference, kindStr, labelStr, langStr)
      return TextTrack(reference: ref!)
    }
    
    public func configureTextTrackDisplay() {
      _HTMLMediaElementConfigureTextTrackDisplay(reference)
    }
    
    public func updateTextTrackDisplay() {
      _HTMLMediaElementUpdateTextTrackDisplay(reference)
    }
    
    public func textTrackReadyStateChanged(track: TextTrack) {
      _HTMLMediaElementTextTrackReadyStateChanged(reference, track.reference)
    }

    public func textTrackModeChanged(track: TextTrack) {
      _HTMLMediaElementTextTrackModeChanged(reference, track.reference)
    }
    
    public func disableAutomaticTextTrackSelection() {
      _HTMLMediaElementDisableAutomaticTextTrackSelection(reference)
    }
    
    public func automaticTrackSelectionForUpdatedUserPreference() {
      _HTMLMediaElementAutomaticTrackSelectionForUpdatedUserPreference(reference)
    }

    public func scheduleEvent(_ event: Event) {
      _HTMLMediaElementScheduleEvent(reference, event.reference)
    }

}

extension WebElement {

  public func asHtmlMedia() -> HtmlMediaElement? {
    return asHtmlElement(to: HtmlMediaElement.self)
  }

}