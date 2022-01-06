// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public typealias WebPopupMenu = Int
public typealias WebCredentialManagerClient = Int
public typealias WebPrerendererClient = Int
public typealias WebSpellCheckClient = Int

public class WebSettings {
	
	var reference: WebSettingsRef

	init(reference: WebSettingsRef) {
		self.reference = reference
	}

}

public class WorkerContentSettingsClientProxy {

	var reference: UnsafeMutableRawPointer//WorkerContentSettingsClientProxyRef

	init(reference: UnsafeMutableRawPointer) {
		self.reference = reference
	}

}

public enum WebTreeScopeType : Int {
	case Document = 0
	case Shadow
}

public class WebHitTestResult {

	var reference: WebHitTestResultRef

	init(reference: WebHitTestResultRef) {
		self.reference = reference
	}	
}

public enum CommitResult : Int {
	case Ok = 0
  	case Aborted = 1
  	case RestartCrossDocument = 2
}

public enum WebLifecycleUpdate : Int {
	case PrePaint = 0
	case All = 1
}

public enum CSSPrimitiveValueUnitType : Int {
    case Unknown
    case Number
    case Percentage
    // Length units
    case Ems
    case Exs
    case Pixels
    case Centimeters
    case Millimeters
    case Inches
    case Points
    case Picas
    case QuarterMillimeters
    case ViewportWidth
    case ViewportHeight
    case ViewportMin
    case ViewportMax
    case Rems
    case Chs
    case UserUnits  // The SVG term for unitless lengths
    // Angle units
    case Degrees
    case Radians
    case Gradians
    case Turns
    // Time units
    case Milliseconds
    case Seconds
    case Hertz
    case Kilohertz
    // Resolution
    case DotsPerPixel
    case DotsPerInch
    case DotsPerCentimeter
    // Other units
    case Fraction
    case `Integer`
    case Calc
    case CalcPercentageWithNumber
    case CalcPercentageWithLength
    case CalcLengthWithNumber
    case CalcPercentageWithLengthAndNumber
}