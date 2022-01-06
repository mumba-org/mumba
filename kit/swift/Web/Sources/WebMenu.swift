// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//import Base
import Base

public struct WebMenuItemInfo {
    
    public enum ItemType {
        case Option
        case CheckableOption
        case Group
        case Separator
        case SubMenu
    }

    public var label: String
    public var icon: String
    public var toolTip: String
    public var type: ItemType
    public var action: Int
    public var textDirection: TextDirection
    public var subMenuItems: [WebMenuItemInfo]
    public var hasTextDirectionOverride: Bool
    public var enabled: Bool
    public var checked: Bool
}