// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum BoxOrientation {
  case Horizontal
  case Vertical
}

public enum BoxMainAxisAlignment {
  case Start
  case Center 
  case End
// TODO(calamity): Add MAIN_AXIS_ALIGNMENT_JUSTIFY which spreads blank space
// in-between the child views.
}

// This specifies where along the cross axis the children should be laid out.
// e.g. a horizontal layout of CROSS_AXIS_ALIGNMENT_END will result in the
// child views being bottom-aligned.
public enum BoxCrossAxisAlignment {
  // This causes the child view to stretch to fit the host in the cross axis.
  case Stretch
  case Start
  case Center
  case End
}

fileprivate struct Flex {
  var flexWeight: Int
  var useMinSize: Bool
}

fileprivate struct ViewWrapper {
  
  public private(set) var margins: IntInsets

  public var preferredSize: IntSize {
    var preferredSize = view!.preferredSize
    if !layout!.collapseMarginsSpacing {
      preferredSize.enlarge(width: margins.width, height: margins.height)
    }
    return preferredSize
  }

  public var isVisible: Bool {
    if let v = view {
      return v.isVisible
    }
    return false
  }

  public private(set) var view: View?

  public var boundsRect: IntRect {
    get {
      if let v = view {
        return v.bounds
      }
      return IntRect()
    }
    set (bounds) {
      var newBounds = bounds
      if !layout!.collapseMarginsSpacing {
        if layout!.orientation == .Horizontal {
          newBounds.x = bounds.x + margins.left
          newBounds.width = max(0, bounds.width - margins.width)
        } else {
          newBounds.y = bounds.y + margins.top
          newBounds.height = max(0, bounds.height - margins.height)
        }
      }
      if let v = view {
        v.bounds = newBounds
      }
    }
  }
  
  private var layout: BoxLayout? 

  public init(layout: BoxLayout?, view: View?) {
    self.view = view
    self.layout = layout
    margins = IntInsets()
    // TODO: we need to implement this.. getting the margins properties
    // comming out of the view!

    //if let v = view, let m = v.getProperty(kMarginsKey) { 
    //  self.margins = m
    //}
  }

  public init() {
    self.init(layout: nil, view: nil) 
  }

  public func getHeightForWidth(width: Int) -> Int {
    if layout!.collapseMarginsSpacing {
      return view!.getHeightFor(width: width)
    }
    // When collapse_margins_spacing_ is false, the view margins are included in
    // the "virtual" size of the view. The view itself is unaware of this, so this
    // information has to be excluded before the call to View::GetHeightForWidth()
    // and added back in to the result.
    // If the orientation_ is kVertical, the cross-axis is the actual view width.
    // This is because the cross-axis margins are always handled by the layout.
    if layout!.orientation == .Horizontal {
      return view!.getHeightFor(width: max(0, width - margins.width)) + margins.height
    }
    return view!.getHeightFor(width: width) + margins.height
  }
}

fileprivate typealias FlexMap = Dictionary<View, Flex>

fileprivate enum Axis {
   case HorizontalAxis
   case VerticalAxis 
}

fileprivate func maxAxisInsets(axis: Axis,
                     leading1: IntInsets,
                     leading2: IntInsets,
                     trailing1: IntInsets,
                     trailing2: IntInsets) -> IntInsets {
  if axis == .HorizontalAxis {
    return IntInsets(top: 0, 
                     left: max(leading1.left, leading2.left), 
                     bottom: 0,
                     right: max(trailing1.right, trailing2.right))
  }
  return IntInsets(top: max(leading1.top, leading2.top), 
                   left: 0,
                   bottom: max(trailing1.bottom, trailing2.bottom), 
                   right: 0)
}


public class BoxLayout {

  public let orientation: BoxOrientation

  // Spacing between child views and host view border.
  public var insideBorderInsets: IntInsets

  // The minimum cross axis size for the layout.
  public var minimumCrossAxisSize: Int

  // The alignment of children in the main axis. This is
  // MAIN_AXIS_ALIGNMENT_START by default.
  public var mainAxisAlignment: BoxMainAxisAlignment

  // The alignment of children in the cross axis. This is
  // CROSS_AXIS_ALIGNMENT_STRETCH by default.
  public var crossAxisAlignment: BoxCrossAxisAlignment

  // The flex weight for views if none is set. Defaults to 0.
  public var defaultFlex: Int

  fileprivate var mainAxisOuterMargin: IntInsets {
    if collapseMarginsSpacing {
      let first = ViewWrapper(layout: self, view: firstVisibleView)
      let last = ViewWrapper(layout: self, view: lastVisibleView)
      //if let first = firstVisibleView, let last = lastVisibleView {
        return maxAxisInsets(
          axis: orientation == .Horizontal ? Axis.HorizontalAxis : Axis.VerticalAxis,
          leading1: insideBorderInsets, 
          leading2: first.margins, 
          trailing1: insideBorderInsets,
          trailing2: last.margins)
      //}
    }
    return maxAxisInsets(
        axis: orientation == .Horizontal ? Axis.HorizontalAxis : Axis.VerticalAxis,
        leading1: insideBorderInsets, 
        leading2: IntInsets(), 
        trailing1: insideBorderInsets,
        trailing2: IntInsets())
  }

  fileprivate var crossAxisMaxViewMargin: IntInsets {
    var leading = 0
    var trailing = 0
    for i in 0..<host!.childCount {
      let child = ViewWrapper(layout: self, view: host!.childAt(index: i))
      
      if !child.isVisible {
        continue
      }

      leading = max(leading, crossAxisLeadingInset(insets: child.margins))
      trailing = max(trailing, crossAxisTrailingInset(insets: child.margins))
    }

    if orientation == .Vertical {
      return IntInsets(top: 0, left: leading, bottom: 0, right: trailing)
    }

    return IntInsets(top: leading, left: 0, bottom: trailing, right: 0);
  }

  fileprivate var firstVisibleView: View? {
    return nextVisibleView(index: -1)
  }

  fileprivate var lastVisibleView: View? {
    for i in stride(from: host!.childCount - 1, to: 0, by: -1) {
    //for var i = host.childCount - 1; i >= 0; --i {
      if let result = host!.childAt(index: i), result.isVisible {
        return result
      }
    }
    return nil
  }

  // Spacing to put in between child views.
  fileprivate let betweenChildSpacing: Int

  // A map of views to their flex weights.
  fileprivate var flexMap: FlexMap
  
  // Adjacent view margins and spacing should be collapsed.
  fileprivate let collapseMarginsSpacing: Bool

  // The view that this BoxLayout is managing the layout for.
  fileprivate var host: View?
  
  public init(orientation: BoxOrientation,
              insideBorderInsets: IntInsets = IntInsets(),
              betweenChildSpacing: Int = 0,
              collapseMarginsSpacing: Bool = false) {
    
    self.orientation = orientation
    self.insideBorderInsets = insideBorderInsets
    self.betweenChildSpacing = betweenChildSpacing
    flexMap = FlexMap()
    mainAxisAlignment = .Start
    crossAxisAlignment = .Stretch
    defaultFlex = 0
    minimumCrossAxisSize = 0
    self.collapseMarginsSpacing = collapseMarginsSpacing 
  }

  // A flex of 0 means this view is not resized. Flex values must not be
  // negative.
  public func setFlexForView(view: View, flexWeight: Int, useMinSize: Bool = false) {
    flexMap[view]?.flexWeight = flexWeight
    flexMap[view]?.useMinSize = useMinSize
  }

  // Clears the flex for the given |view|, causing it to use the default
  // flex.
  public func clearFlexForView(view: View) {
    flexMap.removeValue(forKey: view)
  }

  fileprivate func getFlexForView(view: View) -> Int {
    if let flex = flexMap[view] {
      return flex.flexWeight
    }
    return defaultFlex
  }

  fileprivate func getMinimumSizeForView(view: View) -> Int {
    guard let flex = flexMap[view] else {
      return 0
    }

    if !flex.useMinSize {
      return 0
    }

    return orientation == .Horizontal ? view.minimumSize.width
                                      : view.minimumSize.height
  }

  fileprivate func mainAxisSize(rect: IntRect) -> Int {
    return orientation == .Horizontal ? rect.width : rect.height
  }

  fileprivate func mainAxisPosition(rect: IntRect) -> Int {
    return orientation == .Horizontal ? rect.x : rect.y
  }

  fileprivate func setMainAxisSize(size: Int, rect: inout IntRect) {
    if orientation == .Horizontal {
      rect.width = size
    } else {
      rect.height = size
    }
  }

  fileprivate func setMainAxisPosition(position: Int, rect: inout IntRect) {
    if orientation == .Horizontal {
      rect.x = position
    } else {
      rect.y = position
    }
  }

  fileprivate func crossAxisSize(rect: IntRect) -> Int {
    return orientation == .Vertical ? rect.width : rect.height
  }

  fileprivate func crossAxisPosition(rect: IntRect) -> Int {
    return orientation == .Vertical ? rect.x : rect.y
  }

  fileprivate func setCrossAxisSize(size: Int, rect: inout IntRect) {
    if orientation == .Vertical {
      rect.width = size
    } else {
      rect.height = size
    }
  }

  fileprivate func setCrossAxisPosition(position: Int, rect: inout IntRect) {
    if orientation == .Vertical {
      rect.x = position
    } else { 
      rect.y = position
    }
  }

  fileprivate func mainAxisSizeForView(view: ViewWrapper, childAreaWidth: Int) -> Int {
    return orientation == .Horizontal
              ? view.preferredSize.width
              : view.getHeightForWidth(width: crossAxisAlignment == .Stretch
                                          ? childAreaWidth
                                          : view.preferredSize.width)
  }

  fileprivate func mainAxisLeadingInset(insets: IntInsets) -> Int {
    return orientation == .Horizontal ? insets.left : insets.top
  }

  fileprivate func mainAxisTrailingInset(insets: IntInsets) -> Int {
    return orientation == .Horizontal ? insets.right : insets.bottom
  }

  fileprivate func crossAxisLeadingEdge(rect: IntRect) -> Int {
    return orientation == .Vertical ? rect.x : rect.y
  }

  fileprivate func crossAxisLeadingInset(insets: IntInsets) -> Int {
    return orientation == .Vertical ? insets.left : insets.top
  }

  fileprivate func crossAxisTrailingInset(insets: IntInsets) -> Int {
    return orientation == .Vertical ? insets.right : insets.bottom
  }

  fileprivate func mainAxisMarginBetweenViews(leading: ViewWrapper,
                                              trailing: ViewWrapper) -> Int {
    if !collapseMarginsSpacing { //|| leading == nil || trailing == nil {
      return betweenChildSpacing
    }

    return max(betweenChildSpacing,
                    max(mainAxisTrailingInset(insets: leading.margins),
                            mainAxisLeadingInset(insets: trailing.margins)))
  }

  fileprivate func adjustMainAxisForMargin(rect: inout IntRect) {
    rect.inset(insets: mainAxisOuterMargin)
  }

  fileprivate func adjustCrossAxisForInsets(rect: inout IntRect) {
    rect.inset(insets: 
                orientation == .Vertical
                    ? IntInsets(top: 0, 
                                left: insideBorderInsets.left, 
                                bottom: 0,
                                right: insideBorderInsets.right)
                    : IntInsets(
                        top: insideBorderInsets.top, 
                        left: 0,
                        bottom: insideBorderInsets.bottom, 
                        right: 0))
  }

  fileprivate func crossAxisSizeForView(view: ViewWrapper) -> Int {
    // TODO(bruthig): For horizontal case use the available width and not the
    // preferred width. See https://crbug.com/682266.
    return orientation == .Vertical
              ? view.preferredSize.width
              : view.getHeightForWidth(width: view.preferredSize.width)
  }

  fileprivate func crossAxisMarginSizeForView(view: ViewWrapper) -> Int {
    return collapseMarginsSpacing
              ? 0
              : (orientation == .Vertical ? view.margins.width : view.margins.height)
  }

  fileprivate func crossAxisLeadingMarginForView(view: ViewWrapper) -> Int {
    return collapseMarginsSpacing ? 0 : crossAxisLeadingInset(insets: view.margins)
  }

  fileprivate func insetCrossAxis(rect: inout IntRect,
                                  leading: Int,
                                  trailing: Int) {
    if (orientation == .Vertical) {
      rect.inset(left: leading, top: 0, right: trailing, bottom: 0)
    } else {
      rect.inset(left: 0, top: leading, right: 0, bottom: trailing)
    }
  }

  fileprivate func getPreferredSizeForChildWidth(host: View,
                                                 childAreaWidth: Int) -> IntSize {
   // DCHECK_EQ(host, host_);
    var childAreaBounds = IntRect()

    if orientation == .Horizontal {
      // Horizontal layouts ignore |child_area_width|, meaning they mimic the
      // default behavior of GridLayout::GetPreferredHeightForWidth().
      // TODO(estade|bruthig): Fix this See // https://crbug.com/682266.
      var position = 0
      let maxMargins = crossAxisMaxViewMargin
      for i in 0..<host.childCount {
       // guard let child = host.childAt(index: i) else { //ViewWrapper(self, host.childAt(i))
       //   continue
       // }
       let child = ViewWrapper(layout: self, view: host.childAt(index: i))

        if !child.isVisible {
          continue
        }

        let size = IntSize(child.preferredSize)
        if size.isEmpty {
          continue
        }

        var childBounds = IntRect(
            x: position, 
            y: 0,
            width: size.width +
                (!collapseMarginsSpacing ? child.margins.width : 0),
            height: size.height)
        var childMargins = IntInsets()
        if collapseMarginsSpacing {
          childMargins =
              maxAxisInsets(axis: .VerticalAxis, leading1: child.margins, leading2: insideBorderInsets,
                            trailing1: child.margins, trailing2: insideBorderInsets)
        } else {
          childMargins = child.margins
        }

        if crossAxisAlignment == .Start {
          childBounds.inset(left: 0, top: -crossAxisLeadingInset(insets: maxMargins), right: 0,
                            bottom: -childMargins.bottom)
          childBounds.origin = IntPoint(x: position, y: 0)
        } else if crossAxisAlignment == .End {
          childBounds.inset(left: 0, top: -childMargins.top, right: 0,
                            bottom: -crossAxisTrailingInset(insets: maxMargins))
          childBounds.origin = IntPoint(x: position, y: 0)
        } else {
          childBounds.origin = IntPoint(x: position, y: -(childBounds.height / 2))
          childBounds.inset(left: 0, top: -childMargins.top, right: 0, bottom: -childMargins.bottom)
        }

        childAreaBounds.union(other: childBounds)
        position += childBounds.width +
                    mainAxisMarginBetweenViews(
                        leading: child, trailing: ViewWrapper(layout: self, view: nextVisibleView(index: i)))//ViewWrapper(this, nextVisibleView(i)))
      }
      childAreaBounds.height = 
          max(childAreaBounds.height, minimumCrossAxisSize)
    } else {
      var height = 0
      for i in 0..<host.childCount {
        let child = ViewWrapper(layout: self, view: host.childAt(index: i))
        
        if !child.isVisible {
          continue
        }

        let next = ViewWrapper(layout: self, view: nextVisibleView(index: i))//ViewWrapper(self, nextVisibleView(i))
        // Use the child area width for getting the height if the child is
        // supposed to stretch. Use its preferred size otherwise.
        let extraHeight = mainAxisSizeForView(view: child, childAreaWidth: childAreaWidth)
        // Only add |between_child_spacing_| if this is not the only child.
        if extraHeight > 0 {
          height += mainAxisMarginBetweenViews(leading: child, trailing: next)
        }
        height += extraHeight
      }

      childAreaBounds.width = childAreaWidth
      childAreaBounds.height = height
    }

    let nonchildSize = nonChildSize(host: host)
    return IntSize(width: childAreaBounds.width + nonchildSize.width,
                   height: childAreaBounds.height + nonchildSize.height)
  }

 fileprivate func nonChildSize(host: View) -> IntSize {
    let insets = host.insets
    if !collapseMarginsSpacing {
      return IntSize(width: insets.width + insideBorderInsets.width,
                     height: insets.height + insideBorderInsets.height)
    }
    let mainAxis = mainAxisOuterMargin
    let crossAxis = insideBorderInsets
    return IntSize(width: insets.width + mainAxis.width + crossAxis.width,
                   height: insets.height + mainAxis.height + crossAxis.height)
  }

  fileprivate func nextVisibleView(index: Int) -> View? {
    let start = index + 1
    for i in start..<host!.childCount {
      let result = host!.childAt(index: i)
      if result!.isVisible {
        return result
      }
    }
    return nil
  }

}

extension BoxLayout : LayoutManager {
  
  public func installed(host: View) {
    self.host = host
  }
  
  public func uninstalled(host: View) {}
  
  public func layout(host: View) {
    var childArea = IntRect(host.contentsBounds)
    adjustMainAxisForMargin(rect: &childArea)
   
    var maxCrossAxisMargin = IntInsets()
    
    if !collapseMarginsSpacing {
      adjustCrossAxisForInsets(rect: &childArea)
      maxCrossAxisMargin = crossAxisMaxViewMargin
    }
    
    if childArea.isEmpty {
      return
    }

    var totalMainAxisSize = 0
    var numVisible = 0
    var flexSum = 0

    // Calculate the total size of children in the main axis.
    for i in 0..<host.childCount {
      
      //guard let child = host.childAt(index: i) else {
        //ViewWrapper(self, host.childAt(i))
      //  continue
      //}
      let child = ViewWrapper(layout: self, view: host.childAt(index: i))

      if !child.isVisible {
        continue
      }

      let flex = getFlexForView(view: child.view!)
      
      let childMainAxisSize = mainAxisSizeForView(view: child, childAreaWidth: childArea.width)
      
      if childMainAxisSize == 0 && flex == 0 {
        continue
      }

      totalMainAxisSize += childMainAxisSize +
                              mainAxisMarginBetweenViews(
                                  leading: child, 
                                  trailing: ViewWrapper(layout: self, view: nextVisibleView(index: i)))//ViewWrapper(self, nextVisibleView(i)))
      numVisible += 1
      
      flexSum += flex
    }

    if numVisible == 0 {
      return
    }

    totalMainAxisSize -= betweenChildSpacing

    // Free space can be negative indicating that the views want to overflow.
    let mainFreeSpace = mainAxisSize(rect: childArea) - totalMainAxisSize //{
    var position = mainAxisPosition(rect: childArea)
    var size = mainAxisSize(rect: childArea)
    if flexSum == 0 {
      switch mainAxisAlignment {
        case .Start:
          fallthrough
        case .Center:
          position += mainFreeSpace / 2
          size = totalMainAxisSize
        case .End:
          position += mainFreeSpace
          size = totalMainAxisSize
        }
    }
    var newChildArea = IntRect(childArea)
    setMainAxisPosition(position: position, rect: &newChildArea)
    setMainAxisSize(size: size, rect: &newChildArea)
    childArea.intersect(rect: newChildArea)
   // }

    var mainPosition = mainAxisPosition(rect: childArea)
    var totalPadding = 0
    var currentFlex = 0
    for i in 0..<host.childCount {
     // guard let child = host.childAt(index: i) else {
        // ViewWrapper(self, host.childAt(i))
     //  continue
     // }
      var child = ViewWrapper(layout: self, view: host.childAt(index: i))
      if !child.isVisible {
        continue
      }

      // TODO(bruthig): Fix this. The main axis should be calculated before
      // the cross axis size because child Views may calculate their cross axis
      // size based on their main axis size. See https://crbug.com/682266.

      // Calculate cross axis size.
      var bounds  = IntRect(childArea)
      var minChildArea = IntRect(childArea)
      var childMargins = IntInsets()
      if collapseMarginsSpacing {
        childMargins = maxAxisInsets(
            axis: orientation == .Vertical ? Axis.HorizontalAxis : Axis.VerticalAxis,
            leading1: child.margins, 
            leading2: insideBorderInsets, 
            trailing1: child.margins,
            trailing2: insideBorderInsets)
      } else {
        childMargins = child.margins
      }

      if crossAxisAlignment == .Stretch || crossAxisAlignment == .Center {
        insetCrossAxis(rect: &minChildArea, 
                       leading: crossAxisLeadingInset(insets: childMargins),
                       trailing: crossAxisTrailingInset(insets: childMargins))
      }

      setMainAxisPosition(position: mainPosition, rect: &bounds)
      if crossAxisAlignment != .Stretch {
        let crossAxisMarginSize = crossAxisMarginSizeForView(view: child)
        var viewCrossAxisSize = crossAxisSizeForView(view: child) - crossAxisMarginSize
        let freeSpace = crossAxisSize(rect: bounds) - viewCrossAxisSize
        var position = crossAxisPosition(rect: bounds)
        if crossAxisAlignment == .Center {
          if viewCrossAxisSize > crossAxisSize(rect: minChildArea) {
            viewCrossAxisSize = crossAxisSize(rect: minChildArea)
          }
          position += freeSpace / 2
          position = max(position, crossAxisLeadingEdge(rect: minChildArea))
        } else if crossAxisAlignment == .End {
          position += freeSpace - crossAxisTrailingInset(insets: maxCrossAxisMargin)
          if !collapseMarginsSpacing {
            insetCrossAxis(rect: &minChildArea,
                           leading: crossAxisLeadingInset(insets: child.margins),
                           trailing: crossAxisTrailingInset(insets: maxCrossAxisMargin))
          }
        } else {
          position += crossAxisLeadingInset(insets: maxCrossAxisMargin)
          if !collapseMarginsSpacing {
            insetCrossAxis(rect: &minChildArea,
                           leading: crossAxisLeadingInset(insets: maxCrossAxisMargin),
                           trailing: crossAxisTrailingInset(insets: child.margins))
          }
        }
        setCrossAxisPosition(position: position, rect: &bounds)
        setCrossAxisSize(size: viewCrossAxisSize, rect: &bounds)
      }

      // Calculate flex padding.
      var currentPadding = 0
      let childFlex = getFlexForView(view: child.view!)
     
      if childFlex > 0 {
        currentFlex += childFlex
        let quot = (mainFreeSpace * currentFlex) / flexSum
        let rem = (mainFreeSpace * currentFlex) % flexSum
        currentPadding = quot - totalPadding
        // Use the current remainder to round to the nearest pixel.
        if abs(rem) * 2 >= flexSum {
          currentPadding += mainFreeSpace > 0 ? 1 : -1
        }
        totalPadding += currentPadding
      }

      // Set main axis size.
      // TODO(bruthig): Use the allocated width to determine the cross axis size.
      // See https://crbug.com/682266.
      let childMainAxisSize = mainAxisSizeForView(view: child, childAreaWidth: childArea.width)
      var childMinSize = getMinimumSizeForView(view: child.view!)
      
      if childMinSize > 0 && !collapseMarginsSpacing {
        childMinSize += child.margins.width
      }
      
      setMainAxisSize(size: max(childMinSize, childMainAxisSize + currentPadding), rect: &bounds)

      if mainAxisSize(rect: bounds) > 0 || getFlexForView(view: child.view!) > 0 {
        mainPosition += mainAxisSize(rect: bounds) +
                        mainAxisMarginBetweenViews(
                            leading: child, trailing: ViewWrapper(layout: self, view: nextVisibleView(index: i)))//ViewWrapper(self, nextVisibleView(i)))
      }

      // Clamp child view bounds to |child_area|.
      bounds.intersect(rect: minChildArea)
      child.boundsRect = bounds
    }

    // Flex views should have grown/shrunk to consume all free space.
    if flexSum > 0 {
      assert(totalPadding == mainFreeSpace)
    }
  }
  
  public func getPreferredSize(host: View) -> IntSize {
    var width = 0
    if orientation == .Vertical {
      // Calculating the child views' overall preferred width is a little involved
      // because of the way the margins interact with |cross_axis_alignment_|.
      var leading = 0
      var trailing = 0
      var childViewArea = IntRect()
      //for var i = 0; i < host.childCount; ++i {
      for i in 0..<host.children.count {  
      //for child in host.children {  
        //guard let child = host.childAt(i) else {//ViewWrapper(self, host.childAt(i))
        //  continue
        //}
        let child = ViewWrapper(layout: self, view: host.childAt(index: i))
        if !child.isVisible {
          continue 
        }

        // We need to bypass the ViewWrapper GetPreferredSize() to get the actual
        // raw view size because the margins along the cross axis are handled
        // below.
        let childSize = child.preferredSize
        var childMargins = IntInsets()
        if collapseMarginsSpacing {
          childMargins = maxAxisInsets(axis: .HorizontalAxis, 
                                       leading1: child.margins,
                                       leading2: insideBorderInsets, 
                                       trailing1: child.margins,
                                       trailing2: insideBorderInsets)
        } else {
          childMargins = child.margins
        }

        // The value of |cross_axis_alignment_| will determine how the view's
        // margins interact with each other or the |inside_border_insets_|.
        if crossAxisAlignment == .Start {
          leading = max(leading, crossAxisLeadingInset(insets: childMargins))
          width = max(width, childSize.width + crossAxisTrailingInset(insets: childMargins));
        } else if crossAxisAlignment == .End {
          trailing = max(trailing, crossAxisTrailingInset(insets:  childMargins))
          width = max(width, childSize.width + crossAxisLeadingInset(insets: childMargins))
        } else {
          // We don't have a rectangle which can be used to calculate a common
          // center-point, so a single known point (0) along the horizontal axis
          // is used. This is OK because we're only interested in the overall
          // width and not the position.
          var childBounds = IntRect(x: -(childSize.width / 2), y: 0, width: childSize.width, height: childSize.height)
          childBounds.inset(insets: IntInsets(top: -child.margins.left, left: 0, bottom: -child.margins.right, right: 0))
          childViewArea.union(other: childBounds)
          width = max(width, childViewArea.width)
        }
      }
      width = max(width + leading + trailing, minimumCrossAxisSize)
    }

    return getPreferredSizeForChildWidth(host: host, childAreaWidth: width)
  }
  
  public func getPreferredHeightForWidth(host: View, width: Int) -> Int {
    let childWidth = width - nonChildSize(host: host).width
    return getPreferredSizeForChildWidth(host: host, childAreaWidth: childWidth).height
  }
  
  public func viewAdded(host: View, view: View) {

  }
  
  public func viewRemoved(host: View, view: View) {
    clearFlexForView(view: view)
  }

}

extension View : Hashable {

  public func hash(into hasher: inout Hasher) {
    hasher.combine(x)
    hasher.combine(y)
    hasher.combine(width)
    hasher.combine(height)
    hasher.combine(id)
  }

  public final class func == (lhs: View, rhs: View) -> Bool {
    return lhs.x == rhs.x && lhs.y == rhs.y && lhs.width == rhs.width && lhs.height == rhs.height && lhs.id == rhs.id
  }

}