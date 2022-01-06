// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum InsetsMetric {
  case CheckboxRadioButton
  case Dialog
  case DialogButtonRow
  case DialogSubsection
  case DialogTitle
  case TooltipBubble
  case VectorImageButton
  case LabelButton
}

public enum DistanceMetric {
  case ButtonHorizontalPadding
  case ButtonMaxLinkableWidth
  case CloseButtonMargin
  case ControlVerticalTextPadding
  case DialogButtonMinimumWidth
  case DialogContentMarginBottomControl
  case DialogContentMarginBottomText
  case DialogContentMarginTopControl
  case DialogContentMarginTopText
  case RelatedButtonHorizontal
  case RelatedControlHorizontal
  case RelatedControlVertical
  case RelatedLabelHorizontal
  case DialogScrollableAreaMaxHeight
  case TableCellHorizontalMargin
  case TextfieldHorizontalTextPadding
  case UnrelatedControlVertical
}

public enum DialogContentType { 
  case Control
  case Text
}

public class LayoutProvider {

  public class func instance() -> LayoutProvider {
    if _instance == nil {
      _instance = LayoutProvider()
    }
    return _instance!
  }

  public static func getControlHeightForFont(context: TextContext,
                                             style: TextStyle,
                                             font: FontList) -> Int {
    return max(TextStyles.getLineHeight(context: context, style: style), font.height) +
         LayoutProvider.instance().getDistanceMetric(.ControlVerticalTextPadding) * 2
  }
  
  static var _instance: LayoutProvider?
  
  public init() {

  }

  public func getInsetsMetric(_ metric: InsetsMetric) -> IntInsets {
    switch metric {
      case .CheckboxRadioButton:
        return IntInsets(vertical: 5, horizontal: 6)
      case .DialogButtonRow:
        let dialogInsets: IntInsets = getInsetsMetric(.Dialog)
        return IntInsets(top: 0, left: dialogInsets.left, bottom: dialogInsets.bottom, right: dialogInsets.right)
      case .Dialog:
        fallthrough
      case .DialogSubsection:
        return IntInsets(vertical: 13, horizontal: 13)
      case .DialogTitle:
        let dialogInsets: IntInsets = getInsetsMetric(.Dialog)
        return IntInsets(top: dialogInsets.top, left: dialogInsets.left, bottom: 0, right: dialogInsets.right)
      case .TooltipBubble:
         return IntInsets(all: 8)
      case .VectorImageButton:
        return IntInsets(all: 4)
      case .LabelButton:
        return IntInsets(vertical: 5, horizontal: 6)
    }
  }

  public func getDistanceMetric(_ metric: DistanceMetric) -> Int {

    switch metric {
      case .ButtonHorizontalPadding:
        return 16
      case .ButtonMaxLinkableWidth:
        return 0
      case .CloseButtonMargin:
        return 7
      case .ControlVerticalTextPadding:
        return 4
      case .DialogButtonMinimumWidth:
        return 75
      case .DialogContentMarginBottomControl:
        fallthrough
      case .DialogContentMarginBottomText:
        fallthrough
      case .DialogContentMarginTopControl:
        fallthrough
      case .DialogContentMarginTopText:
        return 13
      case .RelatedButtonHorizontal:
        return 6
      case .RelatedControlHorizontal:
        return 8
      case .RelatedControlVertical:
        return 8
      case .RelatedLabelHorizontal:
        return 10
      case .DialogScrollableAreaMaxHeight:
        return 160
      case .TableCellHorizontalMargin:
        return 10
      case .TextfieldHorizontalTextPadding:
        return 4
      case .UnrelatedControlVertical:
        return 20
    }
  }

  public func getSnappedDialogWidth(minWidth: Int) -> Int {
    return max(minWidth, 320)
  }

  public func getDialogInsetsForContentType(leading: DialogContentType,
                                            trailing: DialogContentType) -> IntInsets {
    let topMargin =
      leading == .Control
          ? getDistanceMetric(.DialogContentMarginTopControl)
          : getDistanceMetric(.DialogContentMarginTopText)

    let bottomMargin =
        trailing == .Control
            ? getDistanceMetric(.DialogContentMarginBottomControl)
            : getDistanceMetric(.DialogContentMarginBottomText)

    let dialogInsets: IntInsets = getInsetsMetric(.Dialog)
    return IntInsets(top: topMargin, left: dialogInsets.left, bottom: bottomMargin, right: dialogInsets.right)
  }

}