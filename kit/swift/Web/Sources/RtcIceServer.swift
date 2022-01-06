// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct RTCIceServer {
    public var urls: [String] = []
    public var url: String = String()
    public var username: String = String()
    public var credential: String = String()

    public init() {}
};