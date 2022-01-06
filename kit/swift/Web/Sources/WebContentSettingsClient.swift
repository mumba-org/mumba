// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebContentSettingCallbacks {
  
  var reference: WebContentSettingCallbacksRef

  init(reference: WebContentSettingCallbacksRef) {
    self.reference = reference
  }

  deinit {}
  
}

public protocol WebContentSettingsClient {
    
    func allowDatabase(name: String, displayName: String, estimatedSize: Int64) -> Bool

    func requestFileSystemAccessSync() -> Bool

    func requestFileSystemAccessAsync(callbacks: WebContentSettingCallbacks)

    func allowImage(enabledPerSettings: Bool, imageURL: String) -> Bool

    func allowIndexedDB(name: String, origin: WebSecurityOrigin) -> Bool

    func allowMedia(videoURL: String) -> Bool

    func allowPlugins(enabledPerSettings: Bool) -> Bool

    func allowScript(enabledPerSettings: Bool) -> Bool

    func allowScriptFromSource(enabledPerSettings: Bool, scriptURL: String) -> Bool

    func allowDisplayingInsecureContent(enabledPerSettings: Bool, origin: WebSecurityOrigin, url: String) -> Bool

    func allowRunningInsecureContent(enabledPerSettings: Bool, origin: WebSecurityOrigin, url: String) -> Bool

    func allowScriptExtension(extensionName: String, extensionGroup: Int) -> Bool

    func allowScriptExtension(extensionName: String, extensionGroup: Int, worldId: Int) -> Bool

    func allowStorage(local: Bool) -> Bool

    func allowReadFromClipboard(default: Bool) -> Bool

    func allowWriteToClipboard(default: Bool) -> Bool

    func allowWebComponents(default: Bool)
    
    func allowMutationEvents(default: Bool) -> Bool

    func didNotAllowPlugins()

    func didNotAllowScript()
}