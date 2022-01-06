// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class CSSPaintWorklet : PaintWorklet {
  
  public init(window: WebWindow) {
    super.init(reference: PaintWorkletCreate(window.reference), window: window)
  }

}