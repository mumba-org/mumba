// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public struct RtcCertificate {
  public var expires: TimeTicks = TimeTicks()
  public var fingerprints: [RtcDtlsFingerprint] = []

  public init() {}
}