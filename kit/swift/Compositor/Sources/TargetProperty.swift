// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum TargetProperty : Int {
  case Transform = 0
  case Opacity = 1
  case Filter = 2
  case ScrollOffset = 3
  case BackgroundColor = 4
  case Bounds = 5
}

// TODO: tem que ser como uma mascara com a capacidade
//       de representar vários properties
public struct TargetProperties : OptionSet {
  
  public var rawValue: Int

  static let Transform       = TargetProperties(rawValue: 1 << TargetProperty.Transform.rawValue)
  static let Opacity         = TargetProperties(rawValue: 1 << TargetProperty.Opacity.rawValue)
  static let Filter          = TargetProperties(rawValue: 1 << TargetProperty.Filter.rawValue)
  static let ScrollOffset    = TargetProperties(rawValue: 1 << TargetProperty.ScrollOffset.rawValue)
  static let BackgroundColor = TargetProperties(rawValue: 1 << TargetProperty.BackgroundColor.rawValue)
  static let Bounds          = TargetProperties(rawValue: 1 << TargetProperty.Bounds.rawValue)

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }

  public init(property: TargetProperty) {
    self.rawValue = 1 << property.rawValue
  }

  public func has(_ property: TargetProperty) -> Bool {
    return self.rawValue & (1 << property.rawValue) != 0
  }

  public mutating func add(_ property: TargetProperty) {
    self.rawValue = self.rawValue | ( 1 << property.rawValue)
  }

}