// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import MumbaShims
import Graphics
import Compositor
import Web

public class UIWebMediaPlayerDelegate : WebMediaPlayerDelegate,
                                        UIWebFrameObserver {

    
    // WebMediaPlayerDelegate
    public var isFrameHidden: Bool {
        return frame.isHidden || isFrameClosed
    }

    public private(set) var isFrameClosed: Bool

    public var unretainedReference: UnsafeMutableRawPointer? {
        return unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    }

    private var observers: [Int : WebMediaPlayerDelegateObserver]
    private var observerLastId: Int
    private var playingVideos: [Int] = []
    private var stalePlayers: [Int] = []
    private var idlePlayers: [Int: TimeTicks] = [:]
    private var hasPlayedMedia: Bool = false
    private var hasPlayedVideo: Bool = false
    private var tickClock: DefaultTickClock = DefaultTickClock()
    private var idleTimeout: TimeTicks = TimeTicks()
    private weak var frame: UIWebFrame!

    public init(parentFrame: UIWebFrame) {
        observers = [:]
        observerLastId = 0
        self.frame = parentFrame
        isFrameClosed = false
    }

    public func addObserver(_ observer: WebMediaPlayerDelegateObserver) -> Int {
        observerLastId += 1   
        return addObserverInternal(observer)
    }

    public func removeObserver(playerId: Int) {
        observers.removeValue(forKey: playerId)
        frame.window.sendOnMediaDestroyed(delegate: playerId)
        // scheduleUpdateTask()
    }

    public func didPlay(playerId: Int,
                        hasVideo: Bool,
                        hasAudio: Bool,
                        contentType: MediaContentType) {
        hasPlayedMedia = true
        if hasVideo {
            if !hasItem(playerId, from: playingVideos) {
                playingVideos.append(playerId)
                hasPlayedVideo = true
            }
        } else {
            removeItem(playerId, from: &playingVideos)
        }

        frame.window.sendOnMediaPlaying(
          delegate: playerId, 
          hasVideo: hasVideo, 
          hasAudio: hasAudio, 
          isRemote: false,
          contentType: contentType)

        //scheduleUpdateTask()
    }
    
    public func didPause(playerId: Int) {
        removeItem(playerId, from: &playingVideos)
        frame.window.sendOnMediaPaused(delegate: playerId, reachedEndOfStream: false)
        //scheduleUpdateTask()
    }
    
    public func playerGone(playerId: Int) {
        removeItem(playerId, from: &playingVideos)
        frame.window.sendOnMediaDestroyed(delegate: playerId)
        //scheduleUpdateTask()
    }

    public func setIdle(playerId: Int, isIdle idle: Bool) {
        if idle == isIdle(playerId: playerId) {
            return
        }

        if idle {
            idlePlayers[playerId] = tickClock.nowTicks
        } else {
            idlePlayers.removeValue(forKey: playerId)
            removeItem(playerId, from: &stalePlayers)
        }

        //scheduleUpdateTask()
    }

    public func isIdle(playerId: Int) -> Bool {
        return idlePlayers[playerId] != nil || hasItem(playerId, from: stalePlayers)
    }

    public func clearStaleFlag(playerId: Int) {
        if !removeItem(playerId, from: &stalePlayers) {
            return
        }

        idlePlayers[playerId] = tickClock.nowTicks - idleTimeout
        
        //if !idleCleanupTimer.isRunning && !pendingUpdateTask {
        //    idleCleanupTimer.start(
        //        self.idleCleanupInterval,
        //        UIWebMediaPlayerDelegate.updateTask)
        //}
    }
    
    public func isStale(playerId: Int) -> Bool {
        return hasItem(playerId, from: stalePlayers)
    }
 
    public func setIsEffectivelyFullscreen(
        playerId: Int,
        status: WebFullscreenVideoStatus) {
        frame.window.sendOnMediaEffectivelyFullscreenChanged(
            delegate: playerId,
            status: status)
    }

    public func didPlayerSizeChange(delegateId: Int, size: IntSize) {
        frame.window.sendOnMediaSizeChanged(delegate: delegateId, size: size)
    }

    public func didPlayerMutedStatusChange(delegateId: Int, muted: Bool) {
        frame.window.sendOnMediaMutedStatusChanged(delegate: delegateId, muted: muted)
    }

    public func didPictureInPictureModeStart(
        delegateId: Int,
        surfaceId: SurfaceId,
        size: IntSize,
        callback: PipWindowOpenedCallback) {
      
      print("UIWebMediaPlayerDelegate.didPictureInPictureModeStart: not implemented")
    }

    public func didPictureInPictureModeEnd(delegateId: Int, _ cb: ClosureCallback?) {
      print("UIWebMediaPlayerDelegate.didPictureInPictureModeEnd: not implemented")
    }

    public func didPictureInPictureSourceChange(delegateId: Int) {
        print("UIWebMediaPlayerDelegate.didPictureInPictureSourceChange: not implemented")
    }

    public func didPictureInPictureSurfaceChange(delegateId: Int,
                                                 surfaceId: SurfaceId,
                                                 size: IntSize) {
        print("UIWebMediaPlayerDelegate.didPictureInPictureSurfaceChange: not implemented")
    }

    public func onPictureInPictureSurfaceIdUpdated(delegateId: Int, surfaceId: SurfaceId, size: IntSize) {
        print("UIWebMediaPlayerDelegate.onPictureInPictureSurfaceIdUpdated: not implemented")
    }

    public func onExitPictureInPicture(delegateId: Int) {
        print("UIWebMediaPlayerDelegate.onExitPictureInPicture: not implemented")
    }

    public func onMediaDelegatePause(playerId: Int) {
        if let observer = observers[playerId] {
            observer.onPause()
        }
    }
    
    public func onMediaDelegatePlay(playerId: Int) {
        if let observer = observers[playerId] {
            observer.onPlay()
        }
    }
    
    public func onMediaDelegateSeekForward(playerId: Int, to: TimeDelta) {
        if let observer = observers[playerId] {
            observer.onSeekForward(to: to)
        }
    }
    
    public func onMediaDelegateSeekBackward(playerId: Int, to: TimeDelta) {
        if let observer = observers[playerId] {
            observer.onSeekBackward(to: to)
        }
    }
    
    public func onMediaDelegateSuspendAllMediaPlayers() {
        self.isFrameClosed = true
        for (_, observer) in observers {
            observer.onFrameClosed()
        }
    }
    
    public func onMediaDelegateVolumeMultiplierUpdate(playerId: Int, multiplier: Double) {
        if let observer = observers[playerId] {
            observer.onVolumeMultiplierUpdate(multiplier: multiplier)
        }
    }
    
    public func onMediaDelegateBecamePersistentVideo(playerId: Int, value: Bool) {
        if let observer = observers[playerId] {
            observer.onBecamePersistentVideo(value: value)
        }
    }
    
    public func onPictureInPictureModeEnded(playerId: Int) {
        if let observer = observers[playerId] {
            observer.onPictureInPictureModeEnded()
        }
    }
  
    // UIWebFrameObserver
    public func onWasShown(frame: UIWebFrame) {
        print("UIWebMediaPlayerDelegate.onWasShown")
        self.isFrameClosed = false
        for (_, observer) in observers {
            observer.onFrameShown()
        }
        // scheduleUpdateTask()
    }
    
    public func onWasHidden(frame: UIWebFrame) {
        print("UIWebMediaPlayerDelegate.onWasHidden")
        for (_, observer) in observers {
            observer.onFrameHidden()
        }
        // scheduleUpdateTask()
    }

    private func addNativeObserver(_ observer: UnsafeMutableRawPointer?) -> Int {
        print("WebMediaPlayeDelegate.addNativeObserver")
        var playerToAdd: WebMediaPlayer?
        observerLastId += 1
        // we need to compare the handle with media players from the parent frame
        // if theres a match we add them as observers
        for player in frame.mediaPlayers {
            if player.reference == observer {
                playerToAdd = player
                break
            }
        }
        if let p = playerToAdd {
            print("addNativeObserver: we have a match with a MediaPlayer. adding it..")
            return addObserverInternal(p)
        } else {
            print("addNativeObserver: no match with a local MediaPlayer. not adding it") 
        }
        return observerLastId
    }

    private func removeNativeObserver(_ id: Int) {
        removeObserver(playerId: id)
    }

    public func createWebMediaPlayerDelegateCallbacks() -> WebMediaPlayerDelegateCallbacks {
        var callbacks = WebMediaPlayerDelegateCallbacks()
        memset(&callbacks, 0, MemoryLayout<WebMediaPlayerDelegateCallbacks>.stride)
        
        //int (*IsFrameHidden)();
        callbacks.IsFrameHidden = { (state: UnsafeMutableRawPointer?) -> CInt in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            return this.isFrameHidden ? 1 : 0
        }

        //int (*IsFrameClosed)();
        callbacks.IsFrameClosed = { (state: UnsafeMutableRawPointer?) -> CInt in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            return this.isFrameClosed ? 1 : 0
        }

        //int (*AddObserver)(void* state, void* observer)
        callbacks.AddObserver = { (state: UnsafeMutableRawPointer?, observer: UnsafeMutableRawPointer?) -> CInt in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            return CInt(this.addNativeObserver(observer))
        }

        //void (*RemoveObserver)(void* state, int player_id)
        callbacks.RemoveObserver = { (state: UnsafeMutableRawPointer?, id: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.removeNativeObserver(Int(id))
        }
        //void (*DidPlay)(int player_id,
        //                int has_video,
        //                int has_audio,
        //                int media_content_type);
        callbacks.DidPlay = { (
            state: UnsafeMutableRawPointer?,
            playerId: CInt,
            hasVideo: CInt,
            hasAudio: CInt,
            mediaContentType: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPlay(
                playerId: Int(playerId),
                hasVideo: hasVideo != 0,
                hasAudio: hasAudio != 0,
                contentType: MediaContentType(rawValue: Int(mediaContentType))!)
        }
        //void (*DidPause)(int player_id);
        callbacks.DidPause = { (state: UnsafeMutableRawPointer?, playerId: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPause(playerId: Int(playerId))
        }
        //void (*DidPlayerSizeChange)(int delegate_id, int sw, int wh);
        callbacks.DidPlayerSizeChange = { (
            state: UnsafeMutableRawPointer?, 
            delegateId: CInt,
            sw: CInt,
            sh: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPlayerSizeChange(
                delegateId: Int(delegateId), 
                size: IntSize(width: Int(sw), height: Int(sh)))
        }
        //void (*DidPlayerMutedStatusChange)(int delegate_id, int muted);
        callbacks.DidPlayerMutedStatusChange = { (
            state: UnsafeMutableRawPointer?, 
            delegateId: CInt,
            muted: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPlayerMutedStatusChange(
                delegateId: Int(delegateId), 
                muted: muted != 0)
        }
        //void (*DidPictureInPictureSourceChange)(int delegate_id);
        callbacks.DidPictureInPictureSourceChange = { (
            state: UnsafeMutableRawPointer?, 
            delegateId: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPictureInPictureSourceChange(
                delegateId: Int(delegateId))
        }
        //void (*DidPictureInPictureModeEnd)(int delegate_id);
        callbacks.DidPictureInPictureModeEnd = { (
            state: UnsafeMutableRawPointer?, 
            delegateId: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.didPictureInPictureModeEnd(
                delegateId: Int(delegateId), nil)
        }
        //void (*PlayerGone)(int player_id);
        callbacks.PlayerGone = { (
            state: UnsafeMutableRawPointer?, 
            playerId: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.playerGone(
                playerId: Int(playerId))
        }
        //void (*SetIdle)(int player_id, int is_idle);
        callbacks.SetIdle = { (
            state: UnsafeMutableRawPointer?, 
            playerId: CInt,
            isIdle: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.setIdle(
                playerId: Int(playerId),
                isIdle: isIdle != 0)
        }
        //int (*IsIdle)(int player_id);
        callbacks.IsIdle = { (
            state: UnsafeMutableRawPointer?, 
            playerId: CInt) -> CInt in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            return this.isIdle(
                playerId: Int(playerId)) ? 1 : 0
        }
        //void (*ClearStaleFlag)(int player_id);
        callbacks.ClearStaleFlag = { (state: UnsafeMutableRawPointer?, playerId: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.clearStaleFlag(playerId: Int(playerId))
        }
        //int (*IsStale)(int player_id);
        callbacks.IsStale = { (state: UnsafeMutableRawPointer?, playerId: CInt) -> CInt in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            return this.isStale(playerId: Int(playerId)) ? 1 : 0
        }
        //void (*SetIsEffectivelyFullscreen)(
        //    int player_id,
        //    int fullscreen_video_status);
        callbacks.SetIsEffectivelyFullscreen = { (
            state: UnsafeMutableRawPointer?, 
            playerId: CInt, 
            fullscreenVideoStatus: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.setIsEffectivelyFullscreen(playerId: Int(playerId), status: WebFullscreenVideoStatus(rawValue: Int(fullscreenVideoStatus))!)
        }

        //void (*OnPictureInPictureSurfaceIdUpdated)(
        // void* state,
        // int delegate_id,
        // uint32_t surface_id_client_id,
        // uint32_t surface_id_sink_id, 
        // uint32_t surface_id_parent_sequence_number,
        // uint32_t surface_id_child_sequence_number,
        // uint64_t surface_id_token_high, 
        // uint64_t surface_id_token_low,
        // int width,
        // int height);

        callbacks.OnPictureInPictureSurfaceIdUpdated = { (
            state: UnsafeMutableRawPointer?,
            delegateId: CInt,
            surfaceIdClientId: UInt32,
            surfaceIdSinkId: UInt32, 
            surfaceIdParentSequenceNumber: UInt32,
            surfaceIdChildSequenceNumber: UInt32,
            surfaceIdTokenHigh: UInt64, 
            surfaceIdTokenLow: UInt64,
            width: CInt, 
            height: CInt) in 
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            var frameSinkId = FrameSinkId(clientId: surfaceIdClientId, sinkId: surfaceIdSinkId)
            var localSurfaceId = LocalSurfaceId()
            localSurfaceId.parentSequenceNumber = surfaceIdParentSequenceNumber
            localSurfaceId.childSequenceNumber = surfaceIdChildSequenceNumber
            localSurfaceId.token = UnguessableToken(high: surfaceIdTokenHigh, low: surfaceIdTokenLow)
            let surface = SurfaceId(frameSinkId: frameSinkId, localSurfaceId: localSurfaceId)
            this.onPictureInPictureSurfaceIdUpdated(delegateId: Int(delegateId), surfaceId: surface, size: IntSize(width: Int(width), height: Int(height)))
        }
        
        // void (*OnExitPictureInPicture)(void* state, int delegate_id);
        callbacks.OnExitPictureInPicture = { (
            state: UnsafeMutableRawPointer?,
            delegateId: CInt) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onExitPictureInPicture(delegateId: Int(delegateId))
        }

        //void (*OnMediaDelegatePause)(void* state, int player_id);
        callbacks.OnMediaDelegatePause = { (state: UnsafeMutableRawPointer?, playerId: CInt) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegatePause(playerId: Int(playerId))
        }

        //void (*OnMediaDelegatePlay)(void* state, int player_id);
        callbacks.OnMediaDelegatePlay = { (state: UnsafeMutableRawPointer?, playerId: CInt) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegatePlay(playerId: Int(playerId))
        }
        
        //void (*OnMediaDelegateSeekForward)(
        //    void* state, 
        //    int player_id,
        //    int64_t seek_milliseconds);
        callbacks.OnMediaDelegateSeekForward = { (state: UnsafeMutableRawPointer?, playerId: CInt, seek: Int64) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegateSeekForward(playerId: Int(playerId), to: TimeDelta(milliseconds: seek))
        }
        
        //void (*OnMediaDelegateSeekBackward)(
        //    void* state, 
        //    int player_id,
        //    int64_t seek_milliseconds);
        callbacks.OnMediaDelegateSeekBackward = { (state: UnsafeMutableRawPointer?, playerId: CInt, seek: Int64) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegateSeekBackward(playerId: Int(playerId), to: TimeDelta(milliseconds: seek))
        }

        //void (*OnMediaDelegateSuspendAllMediaPlayers)(void* state);
        callbacks.OnMediaDelegateSuspendAllMediaPlayers = { (state: UnsafeMutableRawPointer?) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegateSuspendAllMediaPlayers()
        }

        //void (*OnMediaDelegateVolumeMultiplierUpdate)(
        //    void* state, 
        //    int player_id,
        //    double multiplier);
        callbacks.OnMediaDelegateVolumeMultiplierUpdate = { (state: UnsafeMutableRawPointer?, playerId: CInt, multiplier: Double) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegateVolumeMultiplierUpdate(playerId: Int(playerId), multiplier: multiplier)
        }

        //void (*OnMediaDelegateBecamePersistentVideo)(
        //    void* state,
        //    int player_id,
        //    bool value);
        callbacks.OnMediaDelegateBecamePersistentVideo = { (state: UnsafeMutableRawPointer?, playerId: CInt, value: CInt) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onMediaDelegateBecamePersistentVideo(playerId: Int(playerId), value: value != 0)
        }
        
        //void (*OnPictureInPictureModeEnded)(
        //    void* state,
        //    int player_id);
        callbacks.OnPictureInPictureModeEnded = { (state: UnsafeMutableRawPointer?, playerId: CInt) in
            let this = unsafeBitCast(state, to: UIWebMediaPlayerDelegate.self)
            this.onPictureInPictureModeEnded(playerId: Int(playerId))
        }

        return callbacks
    }
    
    @discardableResult
    private func removeItem(_ playerId: Int, from: inout [Int]) -> Bool {
        var found: Bool = false
        for (index, item) in from.enumerated() {
            if playerId == item {
                from.remove(at: index)
                found = true
                break
            }
        }
        return found
    }

    private func hasItem(_ playerId: Int, from: [Int]) -> Bool {
        var found: Bool = false
        for item in from {
            if item == playerId {
                found = true
                break
            }
        }
        return found
    }

    internal func addObserverInternal(_ observer: WebMediaPlayerDelegateObserver) -> Int {
        observers[observerLastId] = observer
        return observerLastId
    }
   

}