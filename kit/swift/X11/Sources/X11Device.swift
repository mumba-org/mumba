// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

// Copied from xserver-properties.h
let AxisLabelPropRelHWheel = "Rel Horiz Wheel"
let AxisLabelPropRelWheel = "Rel Vert Wheel"

let AxisLabelPropAbsDblStartTime = "Abs Dbl Start Timestamp"
let AxisLabelPropAbsDblEndTime   = "Abs Dbl End Timestamp"

// Ordinal values
let AxisLabelPropAbsDblOrdinalX  = "Abs Dbl Ordinal X"
let AxisLabelPropAbsDblOrdinalY  = "Abs Dbl Ordinal Y"

// Fling properties
let AxisLabelPropAbsDblFlingVX  = "Abs Dbl Fling X Velocity"
let AxisLabelPropAbsDblFlingVY  = "Abs Dbl Fling Y Velocity"
let AxisLabelPropAbsFlingState   = "Abs Fling State"

let AxisLabelPropAbsFingerCount   = "Abs Finger Count"

// Cros metrics gesture from touchpad
let AxisLabelPropAbsMetricsType      = "Abs Metrics Type"
let AxisLabelPropAbsDblMetricsData1 = "Abs Dbl Metrics Data 1"
let AxisLabelPropAbsDblMetricsData2 = "Abs Dbl Metrics Data 2"

// Touchscreen multi-touch
let AxisLabelAbsMTTouchMAJOR =  "Abs MT Touch Major"
let AxisLabelAbsMTTouchMINOR = "Abs MT Touch Minor"
let AxisLabelAbsMTOrientation = "Abs MT Orientation"
let AxisLabelAbsMTPressure    = "Abs MT Pressure"
let AxisLabelAbsMTPositionX  = "Abs MT Position X"
let AxisLabelAbsMTPositionY  = "Abs MT Position Y"
let AxisLabelAbsMTTrackingID = "Abs MT Tracking ID"
let AxisLabelTouchTimestamp    = "Touch Timestamp"

// When you add new data types, please make sure the order here is aligned
// with the order in the DataType enum in the header file because we assume
// they are in sync when updating the device list (see UpdateDeviceList).
let cachedAtoms: [String] = [
  AxisLabelPropRelHWheel,
  AxisLabelPropRelWheel,
  AxisLabelPropAbsDblStartTime,
  AxisLabelPropAbsDblEndTime,
  AxisLabelPropAbsDblOrdinalX,
  AxisLabelPropAbsDblOrdinalY,
  AxisLabelPropAbsDblFlingVX,
  AxisLabelPropAbsDblFlingVY,
  AxisLabelPropAbsFlingState,
  AxisLabelPropAbsFingerCount,
  AxisLabelPropAbsMetricsType,
  AxisLabelPropAbsDblMetricsData1,
  AxisLabelPropAbsDblMetricsData2,
  AxisLabelAbsMTTouchMAJOR,
  AxisLabelAbsMTTouchMINOR,
  AxisLabelAbsMTOrientation,
  AxisLabelAbsMTPressure,
  AxisLabelAbsMTPositionX,
  AxisLabelAbsMTPositionY,
  AxisLabelAbsMTTrackingID,
  AxisLabelTouchTimestamp
]

public final class X11DeviceDataManager : DeviceDataManager {

  public enum DataType {
    case CMTScrollX
    case CMTScrollY
    case CMTOrdinalX
    case CMTOrdinalY
    case CMTStartTime
    case CMTEndTime
    case CMTFlingX
    case CMTFlingY
    case CMTFlingState
    case CMTMetricsType
    case CMTMetricsData1
    case CMTMetricsData2
    case CMTFingerCount
    case TouchMajor
    case TouchMinor
    case TouchOrientation
    case TouchPressure
    case TouchPositionX
    case TouchPositionY
    case TouchTrackingID
    case TouchRawTimestamp
  }

  public var isXInput2Available: Bool {
    //return _xiOpcode != -1
    // TODO: for now
    return false
  }

  public var masterPointers: [Int]

  public static func createInstance() {
    if X11DeviceDataManager._instance == nil {
      X11DeviceDataManager._instance = X11DeviceDataManager()
    }
  }

  public init() {
    let display = X11Environment.XDisplay
    _xiOpcode = -1
    _buttonMapCount = 0
    _atomCache = AtomCache(display, cachedAtoms)
    _xiDeviceEventTypes = [Int32: Bool]()
    masterPointers = [Int]()

    let _ = initializeXInputInternal()

    X11Environment.updateDeviceList(display: display)
    updateButtonMap()
  }

  public func touchEventNeedsCalibrate(id: Int32) -> Bool {
    return false
  }

  public func getMappedButton(button: Int) -> Int {
    return 0
  }

  public func updateButtonMap() {

  }

  public func isScrollEvent(event: XEvent) -> Bool {
    return false
  }

  public func isTouchpadXInputEvent(event: XEvent) -> Bool {
    return false
  }

  public func isCMTMetricsEvent(event: XEvent) -> Bool {
    return false
  }

  public func isCMTGestureEvent(event: XEvent) -> Bool {
    return false
  }

  public func isEventBlocked(event: XEvent) -> Bool {
    return false
  }

  public func hasEventData(xiev: XIDeviceEvent, type: DataType) -> Bool {
    return false
  }

  public func getEventData(xev: XEvent, type: DataType, value: inout Int64) -> Bool {
    return false
  }

  private func initializeXInputInternal() -> Bool {
    // Check if XInput is available on the system.
    let display = X11Environment.XDisplay
    var opcode: Int32 = 0, event: Int32 = 0, error: Int32 = 0
    if XQueryExtension(display, "XInputExtension", &opcode, &event, &error) == 0 {
      //VLOG(1) << "X Input extension not available: error=" << error;
      return false
    }

    // Check the XInput version.
    var major: Int32 = 2, minor: Int32 = 2
    if XIQueryVersion(display, &major, &minor) == BadRequest {
      //VLOG(1) << "XInput2 not supported in the server.";
      return false
    }
    if major < 2 || (major == 2 && minor < 2) {
      //DVLOG(1) << "XI version on server is " << major << "." << minor << ". "
      //        << "But 2.2 is required.";
      return false
    }

    _xiOpcode = opcode
    assert(_xiOpcode != -1)

    // Possible XI event types for XIDeviceEvent. See the XI2 protocol
    // specification.
    _xiDeviceEventTypes[XI_KeyPress] = true
    _xiDeviceEventTypes[XI_KeyRelease] = true
    _xiDeviceEventTypes[XI_ButtonPress] = true
    _xiDeviceEventTypes[XI_ButtonRelease] = true
    _xiDeviceEventTypes[XI_Motion] = true
    // Multi-touch support was introduced in XI 2.2.
    if minor >= 2 {
      _xiDeviceEventTypes[XI_TouchBegin] = true
      _xiDeviceEventTypes[XI_TouchUpdate] = true
      _xiDeviceEventTypes[XI_TouchEnd] = true
    }
    return true
  }

  internal static var _instance: X11DeviceDataManager?
  private var _atomCache: AtomCache
  private var _xiOpcode: Int32
  private var _buttonMapCount: Int
  private var _xiDeviceEventTypes: [Int32: Bool]
}

extension DeviceDataManager {
  public static func instance() -> X11DeviceDataManager? {
    if X11DeviceDataManager._instance == nil {
      X11DeviceDataManager._instance = X11DeviceDataManager()
    }
    return X11DeviceDataManager._instance!
  }
}
