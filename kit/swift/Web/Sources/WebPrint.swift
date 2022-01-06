// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum WebPrintScalingOption : Int {
  case None = 0
  case FitToPrintableArea
  case SourceSize
}

public struct WebPrintParams {
  
  public var printContentArea: IntRect
  
  public var printableArea: IntRect
  
  public var paperSize: IntSize
  
  public var printerDPI: Int

  public var rasterizePdf: Bool
  
  public var printScalingOption: WebPrintScalingOption

  public var usePrintLayout: Bool
}

public enum WebDuplexMode : Int {
    case UnknownDuplexMode = -1
    case Simplex
    case LongEdge
    case ShortEdge
}

public struct WebPageRange {
  public var from: Int
  public var to: Int
}

public struct WebPrintPresetOptions {
  
    public var isScalingDisabled: Bool

    public var copies: Int

    public var duplexMode: WebDuplexMode

    public var pageRanges: [WebPageRange]

    public var isPageSizeUniform: Bool

    public var uniformPageSize: IntSize

}