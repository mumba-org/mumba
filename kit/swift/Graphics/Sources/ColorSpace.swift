// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct ColorSpace {
  
  public enum PrimaryId : UInt8 {
    case INVALID
    case BT709
    case BT470M
    case BT470BG
    case SMPTE170M
    case SMPTE240M
    case FILM
    case BT2020
    case SMPTEST428_1
    case SMPTEST431_2
    case SMPTEST432_1
    case XYZ_D50
    case ADOBE_RGB
    case APPLE_GENERIC_RGB
    case WIDE_GAMUT_OLOR_SPIN
    case CUSTOM
  }

  public enum TransferId : UInt8 {
    case INVALID
    case BT709
    case BT709_APPLE
    case GAMMA18
    case GAMMA22
    case GAMMA24
    case GAMMA28
    case SMPTE170M
    case SMPTE240M
    case LINEAR
    case LOG
    case LOG_SQRT
    case IEC61966_2_4
    case BT1361_ECG
    case IEC61966_2_1
    case BT2020_10
    case BT2020_12
    case SMPTEST2084
    case SMPTEST428_1
    case ARIB_STD_B67
    case SMPTEST2084_NON_HDR
    case IEC61966_2_1_HDR
    case LINEAR_HDR
    case CUSTOM
  }

  public enum MatrixId : UInt8 {
    case INVALID
    case RGB
    case BT709
    case FCC
    case BT470BG
    case SMPTE170M
    case SMPTE240M
    case YCOCG
    case BT2020_NCL
    case BT2020_L
    case YDZDX
  }

  public enum RangeId : UInt8 {
    case INVALID
    case LIMITED
    case FULL
    case DERIVED
  }

  public var hasExtendedSkTransferFn: Bool {
    return transfer == TransferId.LINEAR_HDR ||
           transfer == TransferId.IEC61966_2_1_HDR
  }

  public var rasterColorSpace: ColorSpace {
    if iccProfileId != 0 {
      return ColorSpace(
        primaries: self.primaries,
        transfer: self.transfer,
        matrix: self.matrix,
        range: self.range,
        iccProfile: 0)
    }
    if hasExtendedSkTransferFn {
      return ColorSpace.createDisplayP3D65()
    }
    return ColorSpace(
        primaries: self.primaries,
        transfer: self.transfer,
        matrix: self.matrix,
        range: self.range,
        iccProfile: self.iccProfileId)
  }

  public var isValid: Bool {
    return primaries != PrimaryId.INVALID &&
           transfer != TransferId.INVALID &&
           matrix != MatrixId.INVALID &&
           range != RangeId.INVALID
  }

  public private(set) var primaries: PrimaryId = PrimaryId.INVALID
  public private(set) var transfer: TransferId = TransferId.INVALID
  public private(set) var matrix: MatrixId = MatrixId.INVALID
  public private(set) var range: RangeId = RangeId.INVALID
  public private(set) var customPrimaryMatrix: Array<Float> = Array<Float>(repeating: 0, count: 9)
  public private(set) var customTransferParams: Array<Float> = Array<Float>(repeating: 0, count: 7)
  public private(set) var iccProfileId: Int64 = 0

  public var blendingColorSpace: ColorSpace {
    if self.transfer == .LINEAR_HDR {
      return ColorSpace.createExtendedSRGB()
    }
    return self
  }

  public static func createExtendedSRGB() -> ColorSpace {
    return ColorSpace(
      primaries: PrimaryId.BT709, 
      transfer: TransferId.IEC61966_2_1_HDR,
      matrix: MatrixId.RGB, 
      range: RangeId.FULL)
  }

  public static func createSRGB() -> ColorSpace {
    return ColorSpace(
      primaries: PrimaryId.BT709, 
      transfer: TransferId.IEC61966_2_1, 
      matrix: MatrixId.RGB,
      range: RangeId.FULL)
  }

  public static func createDisplayP3D65() -> ColorSpace {
    return ColorSpace(primaries: PrimaryId.SMPTEST432_1, 
                      transfer: TransferId.IEC61966_2_1,
                      matrix: MatrixId.RGB, 
                      range: RangeId.FULL)
  }

  public init(primaries: PrimaryId,
              transfer: TransferId,
              matrix: MatrixId,
              range: RangeId) {
    self.primaries = primaries
    self.transfer = transfer
    self.matrix = matrix
    self.range = range
  }

  public init(primaries: PrimaryId,
              transfer: TransferId,
              matrix: MatrixId,
              range: RangeId,
              iccProfile: Int64) {
    self.primaries = primaries
    self.transfer = transfer
    self.matrix = matrix
    self.range = range
    self.iccProfileId = iccProfile
  }

  public init() {}

}

extension ColorSpace : Equatable {
  
  public static func ==(left: ColorSpace, right: ColorSpace) -> Bool {
    return left.primaries == right.primaries &&
           left.transfer == right.transfer &&
           left.matrix == right.matrix &&
           left.range == right.range &&
           left.customPrimaryMatrix == right.customPrimaryMatrix &&
           left.customTransferParams == right.customTransferParams && 
           left.iccProfileId == right.iccProfileId
  }

  public static func !=(left: ColorSpace, right: ColorSpace) -> Bool {
    return left.primaries != right.primaries ||
           left.transfer != right.transfer ||
           left.matrix != right.matrix ||
           left.range != right.range ||
           left.customPrimaryMatrix != right.customPrimaryMatrix ||
           left.customTransferParams != right.customTransferParams || 
           left.iccProfileId != right.iccProfileId
  }
}