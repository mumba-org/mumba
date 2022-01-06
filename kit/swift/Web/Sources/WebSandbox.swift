// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct WebSandboxFlags : OptionSet {
    
    public static let None = WebSandboxFlags(rawValue: 0)
    public static let Navigation = WebSandboxFlags(rawValue: 1)
    public static let Plugins = WebSandboxFlags(rawValue: 1 << 1)
    public static let Origin = WebSandboxFlags(rawValue: 1 << 2)
    public static let Forms = WebSandboxFlags(rawValue: 1 << 3)
    public static let Scripts = WebSandboxFlags(rawValue: 1 << 4)
    public static let TopNavigation = WebSandboxFlags(rawValue: 1 << 5)
    public static let Popups = WebSandboxFlags(rawValue: 1 << 6)
    public static let AutomaticFeatures = WebSandboxFlags(rawValue: 1 << 7)
    public static let PointerLock = WebSandboxFlags(rawValue: 1 << 8)
    public static let DocumentDomain = WebSandboxFlags(rawValue: 1 << 9)
    public static let OrientationLock = WebSandboxFlags(rawValue: 1 << 10)
    public static let PropagatesToAuxiliaryBrowsingContexts = WebSandboxFlags(rawValue: 1 << 11)
    public static let Modals = WebSandboxFlags(rawValue: 1 << 12)
    public static let All = WebSandboxFlags(rawValue: -1)

    public var rawValue: Int

    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

}