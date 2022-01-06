// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum GridLayoutAlignment {
 // Leading equates to left along the horizontal axis, and top along the
 // vertical axis.
 case Leading
 // Centers the view along the axis.
 case Center
 // Trailing equals to right along the horizontal axis, and bottom along
 // the vertical axis.
 case Trailing
 // The view is resized to fill the space.
 case Fill
 // The view is aligned along the baseline. This is only valid for the
 // vertical axis.
 case Baseline

}

public enum GridLayoutSizeType {
  // The column size is fixed.
  case Fixed
  // The preferred size of the view is used to determine the column size.
  case UsePref
}

fileprivate struct ViewState {
  let columnSet: ColumnSet?
  let view: View?
  let startCol: Int
  let startRow: Int
  let colSpan: Int
  let rowSpan: Int 
  let halign: GridLayoutAlignment
  let valign: GridLayoutAlignment

  // If true, the height/width were explicitly set and the view's preferred and
  // minimum size is ignored.
  let prefWidthFixed: Bool
  let prefHeightFixed: Bool

  // The preferred size, only set during the preferred size pass
  // (SizeCalculationType::PREFERRED).
  var prefSize: IntSize

  // The width/height. This is one of possible three values:
  // . an explicitly set value (if pref_X_fixed is true). If an explicitly set
  //   value was provided, then this value never changes.
  // . the preferred width.
  // . the minimum width.
  // If the value wasn't explicitly set, then whether the value is the preferred
  // or minimum depends upon the pass.
  var width: Int
  var height: Int

  // Used during layout. Gives how much width/height has not yet been
  // distributed to the columns/rows the view is in.
  var remainingWidth: Int = 0
  var remainingHeight: Int = 0
  // The baseline. Only used if the view is vertically aligned along the
  // baseline.
  var baseline: Int = -1

  public init(columnSet: ColumnSet?, 
    view: View?,
    startCol: Int,
    startRow: Int,
    colSpan: Int,
    rowSpan: Int,
    halign: GridLayoutAlignment,
    valign: GridLayoutAlignment,
    prefWidth: Int,
    prefHeight: Int) {
      self.columnSet = columnSet
      self.view = view
      self.startCol = startCol
      self.startRow = startRow
      self.colSpan = colSpan
      self.rowSpan = rowSpan
      self.halign = halign
      self.valign = valign
      self.width = prefWidth
      self.height = prefHeight
      prefSize = IntSize()
      prefWidthFixed = width > 0
      prefHeightFixed = height > 0
  }
}

fileprivate func compareByColumnSpan(_ v1: ViewState, _ v2: ViewState) -> Bool {
   return v1.colSpan < v2.colSpan
}

fileprivate func compareByRowSpan(_ v1: ViewState, _ v2: ViewState) -> Bool {
  return v1.rowSpan < v2.rowSpan
}

public class GridLayout {
  // The view we were created with. We don't own this.
  fileprivate let host: View?

  // Whether or not we've calculated the master/linked columns.
  fileprivate var calculatedMasterColumns: Bool = false

  // Used to verify a view isn't added with a row span that expands into
  // another column structure.
  fileprivate var remainingRowSpan: Int = 0

  // Current row.
  fileprivate var currentRow: Int = -1

  // Current column.
  fileprivate var nextColumn: Int = 0

  // Column set for the current row. This is null for padding rows.
  fileprivate var currentRowColSet: ColumnSet?

  // Set to true when adding a View.
  fileprivate var addingView: Bool = false

  // ViewStates. This is ordered by row_span in ascending order.
  fileprivate var viewStates: [ViewState]

  // ColumnSets.
  fileprivate var columnSets: [ColumnSet]

  // Rows.
  fileprivate var rows: [Row]

  // Returns the column set of the last non-padding row.
  fileprivate var lastValidColumnSet: ColumnSet? {
    //for var i = currentRow - 1; i >= 0; --i {
    for i in (0...currentRow).reversed() {   
      if let cs = rows[i].columnSet {
        return cs
      }
    }
    return nil
  }

  // Minimum preferred size.
  public var minimumSize: IntSize// {
    // didSet {

    // }
  //}

  fileprivate var honorsMinWidth: Bool = false
  
  public init(host: View) {
    self.host = host
    viewStates = []
    columnSets = []
    rows = []
    minimumSize = IntSize()
  }
  // Creates a new column set with the specified id and returns it.
  // The id is later used when starting a new row.
  // GridLayout takes ownership of the ColumnSet and will delete it when
  // the GridLayout is deleted.
  public func addColumnSet(id: Int) -> ColumnSet {
    let cs = ColumnSet(id: id)
    columnSets.append(cs)
    return cs
  }

  // Returns the column set for the specified id, or NULL if one doesn't exist.
  public func getColumnSet(id: Int) -> ColumnSet? {
    for cs in columnSets {
      if cs.id == id {
        return cs
      }
    }
    return nil
  }

  // Adds a padding row. Padding rows typically don't have any views, and
  // but are used to provide vertical white space between views.
  // IntSize specifies the height of the row.
  public func addPaddingRow(verticalResize: Float, pixelCount: Int) {
    addRow(row: Row(height: pixelCount, resizePercent: verticalResize, columnSet: nil))
  }

  // A convenience for AddPaddingRow followed by StartRow.
  public func startRowWithPadding(verticalResize: Float, columnSetId: Int, paddingResize: Float, padding: Int) {
    addPaddingRow(verticalResize: paddingResize, pixelCount: padding)
    startRow(verticalResize: verticalResize, columnSetId: columnSetId)
  }

  // Starts a new row with the specified column set and height (0 for
  // unspecified height).
  public func startRow(verticalResize: Float, columnSetId: Int, height: Int = 0) {
    if let columnSet = getColumnSet(id: columnSetId) {
      addRow(row: Row(height: height, resizePercent: verticalResize, columnSet: columnSet))
    }
  }

  // Advances past columns. Use this when the current column should not
  // contain any views.
  public func skipColumns(colCount: Int) {
    nextColumn += colCount
    skipPaddingColumns()
  }

  // Adds a view using the default alignment from the column. The added
  // view has a column and row span of 1.
  // As a convenience this adds the view to the host. The view becomes owned
  // by the host, and NOT this GridLayout.
  public func addView(view: View) {
    addView(view, colSpan: 1, rowSpan: 1);
  }

  // Adds a view using the default alignment from the column.
  // As a convenience this adds the view to the host. The view becomes owned
  // by the host, and NOT this GridLayout.
  public func addView(_ view: View, colSpan: Int, rowSpan: Int) {
    if let column = currentRowColSet?.columns[nextColumn] {
      addView(view, colSpan: colSpan, rowSpan: rowSpan, halign: column.halign, valign: column.valign)
    }
  }

  // Adds a view with the specified alignment and spans.
  // As a convenience this adds the view to the host. The view becomes owned
  // by the host, and NOT this GridLayout.
  public func addView(_ view: View, colSpan: Int, rowSpan: Int, halign: GridLayoutAlignment, valign: GridLayoutAlignment) {
    addView(view: view, colSpan: colSpan, rowSpan: rowSpan, halign: halign, valign: valign, prefWidth: 0, prefHeight: 0)
  }

  // Adds a view with the specified alignment and spans. If
  // pref_width/pref_height is > 0 then the preferred width/height of the view
  // is fixed to the specified value.
  // As a convenience this adds the view to the host. The view becomes owned
  // by the host, and NOT this GridLayout.
  public func addView(view: View, colSpan: Int, rowSpan: Int,
                      halign: GridLayoutAlignment, valign: GridLayoutAlignment,
                      prefWidth: Int, prefHeight: Int) {
    
    addViewState(viewState: 
      ViewState(
        columnSet: currentRowColSet, 
        view: view, 
        startCol: nextColumn, 
        startRow: currentRow, 
        colSpan: colSpan,
        rowSpan: rowSpan, 
        halign: halign, 
        valign: valign, 
        prefWidth: prefWidth, 
        prefHeight: prefHeight))
  }

  // As both Layout and GetPreferredSize need to do nearly the same thing,
  // they both call into this method. This sizes the Columns/Rows as
  // appropriate. If layout is true, width/height give the width/height the
  // of the host, otherwise they are ignored.
  fileprivate func sizeRowsAndColumns(layout: Bool, width: Int, height: Int, pref: inout IntSize) {
      // Make sure the master columns have been calculated.
    calculateMasterColumnsIfNecessary()
    
    pref.width = 0
    pref.height = 0
    
    if rows.isEmpty {
      return
    }

    // Calculate the preferred width of each of the columns. Some views'
    // preferred heights are derived from their width, as such we need to
    // calculate the size of the columns first.
    for columnSet in columnSets {
      columnSet.calculateSize(type: ColumnSet.SizeCalculationType.Preferred)
      pref.width = max(pref.width, columnSet.layoutWidth)
    }

    let insets = host!.insets
    pref.width = pref.width + insets.width

    // Go over the columns again and set them all to the size we settled for.
    let w = width > 0 ? width : pref.width
    for columnSet in columnSets {
      // We're doing a layout, divvy up any extra space.
      columnSet.resize(delta: w - columnSet.layoutWidth - insets.width,  honorsMinWidth: honorsMinWidth)
      // And reset the x coordinates.
      columnSet.resetColumnXCoordinates()
    }

    // Reset the height of each row.
    LayoutElement.resetSizes(elements: &rows)

    // Do the following:
    // . If the view is aligned along it's baseline, obtain the baseline from the
    //   view and update the rows ascent/descent.
    // . Reset the remaining_height of each view state.
    // . If the width the view will be given is different than it's pref, ask
    //   for the height given the actual width.
    for var viewState in viewStates {
      viewState.remainingHeight = viewState.height

      if viewState.valign == .Baseline {
        viewState.baseline = viewState.view!.baseline
      }

      if !viewState.prefHeightFixed {
        // If the view is given a different width than it's preferred width
        // requery for the preferred height. This is necessary as the preferred
        // height may depend upon the width.
        var actualWidth = viewState.columnSet!.getColumnWidth(
            startCol: viewState.startCol, colSpan: viewState.colSpan)
        var x = 0  // Not used in this stage.
        calculateSize(prefSize: viewState.width, alignment: viewState.halign, location: &x, size: &actualWidth)
        if actualWidth != viewState.width {
          // The width this view will get differs from its preferred. Some Views
          // pref height varies with its width; ask for the preferred again.
          viewState.height = viewState.view!.getHeightFor(width: actualWidth)
          viewState.remainingHeight = viewState.height
        }
      }
    }

    // Update the height/ascent/descent of each row from the views.
    for var viewState in  viewStates {
      if viewState.rowSpan == 1 {
        let row = rows[viewState.startRow]
        row.adjustSize(size: viewState.remainingHeight)
        if viewState.baseline != -1 &&
            viewState.baseline <= viewState.height {
          row.adjustSizeForBaseline(ascent: viewState.baseline,
                                    descent: viewState.height - viewState.baseline)
        }
        viewState.remainingHeight = 0
      }
    }

    // Distribute the height of each view with a row span > 1.
    for var viewState in viewStates {
      // Update the remaining_width from columns this view_state touches.
      updateRemainingHeightFromRows(state: &viewState)

      // Distribute the remaining height.
      distributeRemainingHeight(state: &viewState)
    }

    // Update the location of each of the rows.
    LayoutElement.calculateLocationsFromSize(elements: &rows)

    // We now know the preferred height, set it here.
    pref.height = rows.last!.location + rows.last!.size + insets.height

    if layout && height != pref.height {
      // We're doing a layout, and the height differs from the preferred height,
      // divvy up the extra space.
      LayoutElement.distributeDelta(delta: height - pref.height, elements: &rows)

      // Reset y locations.
      LayoutElement.calculateLocationsFromSize(elements: &rows)
    }

  }

  // Calculates the master columns of all the column sets. See Column for
  // a description of what a master column is.
  fileprivate func calculateMasterColumnsIfNecessary() {
    if !calculatedMasterColumns {
      calculatedMasterColumns = true
      for columnSet in columnSets {
        columnSet.calculateMasterColumns()
      }
    }
  }

  // This is called internally from AddView. It adds the ViewState to the
  // appropriate structures, and updates internal fields such as next_column_.
  fileprivate func addViewState(viewState: ViewState) {
    guard let currentRowCols = currentRowColSet else {
      // fix: exception?
      assert(false)
    }

    if viewState.view?.parent == nil {
      addingView = true
      host!.addChild(view: viewState.view!)
      addingView = false
    }
    remainingRowSpan = max(remainingRowSpan, viewState.rowSpan)
    nextColumn += viewState.colSpan
    currentRowCols.addViewState(viewState: viewState)
    // view_states are ordered by row_span (in ascending order).
    let i = findViewStateInsertionPos(viewState: viewState, comparator: compareByRowSpan, viewStates: viewStates)
    //std::lower_bound(view_states_.begin(), view_states_.end(),
            //                  view_state.get(), CompareByRowSpan)
    viewStates.insert(viewState, at: i)
    skipPaddingColumns()
  }

  // Adds the Row to rows_, as well as updating next_column_,
  // current_row_col_set ...
  fileprivate func addRow(row: Row) {
    currentRow += 1
    remainingRowSpan -= 1
    // GridLayout requires that if you add a View with a row span you use the same
    // column set for each of the rows the view lands it. This DCHECK verifies
    // that.
    //assert(remainingRowSpan <= 0 || row.columnSet == nil ||
    //      row.columnSet == lastValidColumnSet)
    nextColumn = 0
    currentRowColSet = row.columnSet
    rows.append(row)
    skipPaddingColumns()
  }

  // As the name says, updates the remaining_height of the ViewState for
  // all Rows the supplied ViewState touches.
  fileprivate func updateRemainingHeightFromRows(state viewState: inout ViewState) {
    for i in 0..<viewState.rowSpan {
      let startRow = viewState.startRow
      viewState.remainingHeight -= rows[i + startRow].size
    }
  }

  // If the view state's remaining height is > 0, it is distributed among
  // the rows the view state touches. This is used during layout to make
  // sure the Rows can accommodate a view.
  fileprivate func distributeRemainingHeight(state viewState: inout ViewState) {
    var height = viewState.remainingHeight
    if height <= 0 {
      return
    }

    // Determine the number of resizable rows the view touches.
    var resizableRows = 0
    let startRow = viewState.startRow
    let maxRow = viewState.startRow + viewState.rowSpan
    for i in startRow..<maxRow {
      if rows[i].isResizable {
        resizableRows += 1
      }
    }

    if resizableRows > 0 {
      // There are resizable rows, give the remaining height to them.
      var toDistribute = height / resizableRows
      for i in startRow..<maxRow {
        if rows[i].isResizable {
          height -= toDistribute
          if height < toDistribute {
            // Give all slop to the last column.
            toDistribute += height
          }
          rows[i].size = rows[i].size + toDistribute
        }
      }
    } else {
      // None of the rows are resizable, divvy the remaining height up equally
      // among all rows the view touches.
      var eachRowHeight = height / viewState.rowSpan
      for i in startRow..<maxRow {
        height -= eachRowHeight
        if height < eachRowHeight {
          eachRowHeight += height
        }
        rows[i].size = rows[i].size + eachRowHeight
      }
      viewState.remainingHeight = 0
    }
  }

  // Advances next_column_ past any padding columns.
  fileprivate func skipPaddingColumns() {
    guard let currentRowCols = currentRowColSet else {
      return
    }
    while nextColumn < currentRowCols.numColumns &&
          currentRowCols.columns[nextColumn].isPadding {
      nextColumn += 1
    }
  }

}

extension GridLayout : LayoutManager {
  
  public func installed(host: View) {}
  public func uninstalled(host: View) {}
  public func viewAdded(host: View, view: View) {}
  public func viewRemoved(host: View, view: View) {}

  public func layout(host: View) {
    var pref = IntSize()
    sizeRowsAndColumns(layout: true, width: host.width, height: host.height, pref: &pref)

    // IntSize each view.
    for viewState in viewStates {
      guard let columnSet = viewState.columnSet else {
        // temporary
        assert(false)
      }
      guard let view = viewState.view else {
        // temporary
        assert(false)
      }
      let insets = host.insets
      var x = columnSet.columns[viewState.startCol].location + insets.left
      var width = columnSet.getColumnWidth(startCol: viewState.startCol, colSpan: viewState.colSpan)
      calculateSize(prefSize: viewState.width, alignment: viewState.halign, location: &x, size: &width)
      var y = rows[viewState.startRow].location + insets.top
      var height = LayoutElement.totalSize(start: viewState.startRow, length: viewState.rowSpan, elements: rows)
      if viewState.valign == .Baseline && viewState.baseline != -1 {
        y += rows[viewState.startRow].maxAscent - viewState.baseline
        height = viewState.height
      } else {
        calculateSize(prefSize: viewState.height, alignment: viewState.valign, location: &y, size: &height)
      }
      view.bounds = IntRect(x: x, y: y, width: width, height: height)
    }
  }

  public func getPreferredSize(host: View) -> IntSize {
    var out = IntSize()
    sizeRowsAndColumns(layout: false, width: 0, height: 0, pref: &out)
    (out.width, out.height) = (max(out.width, minimumSize.width), max(out.height, minimumSize.height))
    return out
  }
  
  public func getPreferredHeightForWidth(host: View, width: Int) -> Int {
    var pref = IntSize()
    sizeRowsAndColumns(layout: false, width: width, height: 0, pref: &pref)
    return pref.height
  }
}

fileprivate struct ColumnMinResizeData {
  // The column being resized.
  public var column: Column?

  // The remaining amount of space available (the difference between the
  // preferred and minimum).
  public var available: Int = 0

  // How much to shrink the preferred by.
  public var delta: Int = 0
}

// LayoutElement ------------------------------------------------------

// A LayoutElement has a size and location along one axis. It contains
// methods that are used along both axis.
public class LayoutElement {
  // Invokes ResetSize on all the layout elements.
  public class func resetSizes<T: LayoutElement>(elements: inout [T]) {
    // Reset the layout width of each column.
    for element in elements {
      element.resetSize()
    }
  }

  // Sets the location of each element to be the sum of the sizes of the
  // preceding elements.
  
  public class func calculateLocationsFromSize<T: LayoutElement>(elements: inout [T]) {
    // Reset the layout width of each column.
    var location = 0
    for element in elements {
      element.location = location
      location += element.size
    }
  }

  // Distributes delta among the resizable elements.
  // Each resizable element is given ResizePercent / total_percent * delta
  // pixels extra of space.
  public class func distributeDelta<T: LayoutElement>(delta: Int, elements: inout [T]) {
   
    if delta == 0 {
      return
    }

    var totalPercent: Float = 0.0
    var resizeCount = 0
    for element in elements {
      totalPercent += element.resizePercent
      if element.resizePercent > 0 {
        resizeCount += 1
      }
    }
   
    if totalPercent == 0 {
      // None of the elements are resizable, return.
      return
    }

    var remaining = delta
    var resized = resizeCount
    
    for element in elements {
      if element.resizePercent > 0 {
        let toGive: Int
        resized -= 1
        if resized == 0 {
          toGive = remaining
        } else {
          toGive = Int(delta * (Int(element.resizePercent) / Int(totalPercent)))
          remaining -= toGive
        }
        element.size = element.size + toGive
      }
    }
  }

  // Returns the sum of the size of the elements from start to start + length.
  public class func totalSize<T: LayoutElement>(start: Int,
                                 length: Int,
                                 elements: [T]) -> Int {
    //assert(start >= 0 && length > 0 &&
    //       start + length <= Int(elements.length))
    
    var size = 0
    let max = start + length

    for i in start..<max {
      size += elements[i].size
    }

    return size
  }

  public var location: Int
  public var size: Int
  public var resizePercent: Float
  public var isResizable: Bool {
    return resizePercent > 0
  }

  public init(resizePercent: Float) {
    self.resizePercent = resizePercent
    location = 0
    size = 0
  }

  // Adjusts the size of this LayoutElement to be the max of the current size
  // and the specified size.
  public func adjustSize(size: Int) {
    self.size = max(self.size, size)
  }

  // Resets the size to the initial size. This sets the size to 0, but
  // subclasses that have a different initial size should override.
  public func resetSize() {
    size = 0
  } 
}

public class Column : LayoutElement {
  
  public var valign: GridLayoutAlignment
  public var halign: GridLayoutAlignment
  public var lastMasterColumn: Column? {
    guard let last = masterColumn else {
      return nil
    }

    if last === self {
      return self
    }

    return last.lastMasterColumn
  } 

  internal var sizeType: GridLayoutSizeType
  internal var fixedWidth: Int
  internal var minWidth: Int
  internal var isPadding: Bool
  internal var sameSizeColumn: Int
  internal var sameSizeColumns: [Column] 
  internal var masterColumn: Column?

  public init(halign: GridLayoutAlignment,
         valign: GridLayoutAlignment,
         resizePercent: Float,
         sizeType: GridLayoutSizeType,
         fixedWidth: Int,
         minWidth: Int,
         isPadding: Bool) {
  
    self.halign = halign
    self.valign = valign
    self.sizeType = sizeType
    self.sameSizeColumn = -1
    self.sameSizeColumns = []
    self.fixedWidth = fixedWidth
    self.minWidth = minWidth
    self.isPadding = isPadding
  
    super.init(resizePercent: resizePercent)
  }

  public override func resetSize() {
    if sizeType == .Fixed {
      size = fixedWidth
    } else {
      size = minWidth
    }
  }

  public override func adjustSize(size: Int) {
    if sizeType == .UsePref {
      super.adjustSize(size: size)
    }
  }

  internal func unifyLinkedColumnSizes(sizeLimit: Int) {
    // Accumulate the size first.
    var size = 0
    
    for column in sameSizeColumns {
      if column.size <= sizeLimit {
        size = max(size, column.size)
      }
    }

    // Then apply it.
    for column in sameSizeColumns {
      column.size = max(size, column.size)
    }
  }
}

// Row -------------------------------------------------------------
public class Row : LayoutElement {
  public var columnSet: ColumnSet?
  public private(set) var maxAscent: Int
  public private(set) var maxDescent: Int
  private var height: Int  
 
  public init(height: Int, resizePercent: Float, columnSet: ColumnSet?) {
    self.height = height
    self.columnSet = columnSet
    maxAscent = 0
    maxDescent = 0
    super.init(resizePercent: resizePercent)
  }

  public override func resetSize() {
    maxDescent = 0
    maxAscent = 0
    size = height
  }
  // Adjusts the size to accommodate the specified ascent/descent.
  public func adjustSizeForBaseline(ascent: Int, descent: Int) {
    maxAscent = max(ascent, maxAscent)
    maxDescent = max(descent, maxDescent)
    adjustSize(size: maxAscent + maxDescent)
  }
}

// ColumnSet is used to define a set of columns. GridLayout may have any
// number of ColumnSets. You don't create a ColumnSet directly, instead
// use the AddColumnSet method of GridLayout.
public class ColumnSet {
  
  public enum SizeCalculationType {
    case Preferred
    case Minimum
  }
  // Columns wider than this limit will be ignored when computing linked
  // columns' sizes.
  public var linkedColumnSizeLimit: Int

  // ID for this columnset.
  public let id: Int

  public var numColumns: Int { 
    return columns.count
  }

   // Returns the total size needed for this ColumnSet.
  internal var layoutWidth: Int {
    var width = 0
    for column in columns {
      width += column.size
    }

    return width
  }

  // The columns.
  fileprivate var columns: [Column]

  // The ViewStates. This is sorted based on column_span in ascending
  // order.
  fileprivate var viewStates: [ViewState]

  // The master column of those columns that are linked. See Column
  // for a description of what the master column is.
  fileprivate var masterColumns: [Column]

  public init(id: Int) {
    self.id = id
    linkedColumnSizeLimit = Int.max
    columns = []
    viewStates = []
    masterColumns = []
  }

  // Adds a column for padding. When adding views, padding columns are
  // automatically skipped. For example, if you create a column set with
  // two columns separated by a padding column, the second AddView automatically
  // skips past the padding column. That is, to add two views, do:
  // layout->AddView(v1); layout->AddView(v2);, not:
  // layout->AddView(v1); layout->SkipColumns(1); layout->AddView(v2);
  // See class description for details on |resize_percent|.
  public func addPaddingColumn(resizePercent: Float, width: Int) {
    addColumn(
      halign: .Fill, 
      valign: .Fill, 
      resizePercent: resizePercent, 
      sizeType: .Fixed, 
      fixedWidth: width, 
      minWidth: width, 
      isPadding: true)
  }

  // Adds a column. The alignment gives the default alignment for views added
  // with no explicit alignment. fixed_width gives a specific width for the
  // column, and is only used if size_type == FIXED. min_width gives the
  // minimum width for the column.
  //
  // If none of the columns in a columnset are resizable, the views are only
  // made as wide as the widest views in each column, even if extra space is
  // provided. In other words, GridLayout does not automatically resize views
  // unless the column is marked as resizable.
  // See class description for details on |resize_percent|.
  public func addColumn(halign: GridLayoutAlignment,
                        valign: GridLayoutAlignment,
                        resizePercent: Float,
                        sizeType: GridLayoutSizeType,
                        fixedWidth: Int,
                        minWidth: Int) {
    addColumn(
      halign: halign, 
      valign: valign, 
      resizePercent: resizePercent, 
      sizeType: sizeType, 
      fixedWidth: fixedWidth, 
      minWidth: minWidth, 
      isPadding: false)
  }

  // Forces the specified columns to have the same size. The size of
  // linked columns is that of the max of the specified columns. This
  // must end with -1. For example, the following forces the first and
  // second column to have the same size:
  // LinkColumnSizes(0, 1, -1);
  public func linkColumnSizes(first: Int...) {

  }
 
  fileprivate func addColumn(
    halign: GridLayoutAlignment, 
    valign: GridLayoutAlignment, 
    resizePercent: Float,
    sizeType: GridLayoutSizeType,
    fixedWidth: Int,
    minWidth: Int,
    isPadding: Bool) {
      
    columns.append(Column(
        halign: halign,
        valign: valign,
        resizePercent: resizePercent,
        sizeType: sizeType,
        fixedWidth: fixedWidth,
        minWidth: minWidth,
        isPadding: isPadding))
  }

  fileprivate func addViewState(viewState: ViewState) {
    let pos = findViewStateInsertionPos(viewState: viewState, comparator: compareByColumnSpan, viewStates: viewStates)
    viewStates.insert(viewState, at: pos)
  }

  fileprivate func calculateMasterColumns() {
    for column in columns {
      let sameSizeColumnIndex = column.sameSizeColumn
      if sameSizeColumnIndex != -1 {
        //Column* same_size_column = columns_[same_size_column_index].get();
        //Column* same_size_column_master = same_size_column->master_column_;
        let sameSizeColumn = columns[sameSizeColumnIndex]

       // if let masterColumn = column.masterColumn {
        if column.masterColumn != nil {  
          // Current column is not linked to any other column.
          //if let sameSizeColumnMaster = sameSizeColumn.masterColumn {
          if sameSizeColumn.masterColumn != nil {  
            // Both columns are not linked.
            column.masterColumn = column
            sameSizeColumn.masterColumn = column
            column.sameSizeColumns.append(sameSizeColumn)
            column.sameSizeColumns.append(column)
          } else {
            // Column to link to is linked with other columns.
            // Add current column to list of linked columns in other columns
            // master column.
            if let last = sameSizeColumn.lastMasterColumn {
              last.sameSizeColumns.append(column)
            }
            // And update the master column for the current column to that
            // of the same sized column.
            column.masterColumn = sameSizeColumn
          }
        } else {
          //if let sameSizeColumnMaster = sameSizeColumn.masterColumn {
            if sameSizeColumn.masterColumn != nil{
            if let clmc = column.lastMasterColumn, let slmc = sameSizeColumn.lastMasterColumn {
              if clmc !== slmc {
                // The two columns are already linked with other columns.
    
                // Add all the columns from the others master to current columns
                // master.
                clmc.sameSizeColumns.append(contentsOf: slmc.sameSizeColumns)
                
                // The other master is no longer a master, clear its vector of
                // linked columns, and reset its master_column.
                slmc.sameSizeColumns.removeAll(keepingCapacity: false)

                if let last = sameSizeColumn.lastMasterColumn {
                  last.masterColumn = column
                }
              }
            }
          } else {
            
            // Column to link with is not linked to any other columns.
            // Update it's master_column.
            sameSizeColumn.masterColumn = column
            // Add linked column to list of linked column.
            if let last = column.lastMasterColumn {
              last.sameSizeColumns.append(sameSizeColumn)
            }
          }
        }
      }
    }
    accumulateMasterColumns()
  }
  
  fileprivate func accumulateMasterColumns() {
    for column in columns {
      if let master: Column = column.lastMasterColumn {
        if !masterColumns.contains(where: { $0 === master }) {
          masterColumns.append(master)
        }
        // At this point, GetLastMasterColumn may not == master_column
        // (may have to go through a few Columns)_. Reset master_column to
        // avoid hops.
        column.masterColumn = master
      }
    }
  }

  // Sets the size of each linked column to be the same.
  fileprivate func unifyLinkedColumnSizes() {
    for column in masterColumns {
      column.unifyLinkedColumnSizes(sizeLimit: linkedColumnSizeLimit)
    }
  }

  // Updates the remaining width field of the ViewState from that of the
  // columns the view spans.
  fileprivate func updateRemainingWidth(viewState: inout ViewState) {
    let maxCol = viewState.startCol + viewState.colSpan
    for i in viewState.startCol..<maxCol {
      viewState.remainingWidth -= columns[i].size
    }
  }

  // Makes sure the columns touched by view state are big enough for the
  // view.
  fileprivate func distributeRemainingWidth(viewState: ViewState) {
    var width = viewState.remainingWidth
    if width <= 0 {
      // The columns this view is in are big enough to accommodate it.
      return
    }

    var resizableColumns = 0
    var prefSizeColumns = 0
    let startCol = viewState.startCol
    let maxCol = viewState.startCol + viewState.colSpan
    var totalResize: Float = 0.0
    for i in startCol..<maxCol {
      if columns[i].isResizable {
        totalResize += columns[i].resizePercent
        resizableColumns += 1
      } else if columns[i].sizeType == .UsePref {
        prefSizeColumns += 1
      }
    }

    if resizableColumns > 0 {
      // There are resizable columns, give them the remaining width. The extra
      // width is distributed using the resize values of each column.
      var remainingWidth = width
      var resize = 0
      for i in startCol..<maxCol {
        if columns[i].isResizable {
          resize += 1
          let delta = (resize == resizableColumns) ? remainingWidth :
            Int(width * Int(columns[i].resizePercent) /
                             Int(totalResize))
          remainingWidth -= delta
          columns[i].size = columns[i].size + delta
        }
      }
    } else if (prefSizeColumns > 0) {
      // None of the columns are resizable, distribute the width among those
      // that use the preferred size.
      var toDistribute = width / prefSizeColumns
      for i in startCol..<maxCol {
        if columns[i].sizeType == .UsePref {
          width -= toDistribute
          if width < toDistribute {
            toDistribute += width
          }
          columns[i].size = columns[i].size + toDistribute
        }
      }
    }
  }

  // Returns the width of the specified columns.
  fileprivate func getColumnWidth(startCol: Int, colSpan: Int) -> Int {
      return LayoutElement.totalSize(start: startCol, length: colSpan, elements: columns)
  }

  // Updates the x coordinate of each column from the previous ones.
  // NOTE: this doesn't include the insets.
  fileprivate func resetColumnXCoordinates() {
    LayoutElement.calculateLocationsFromSize(elements: &columns)
  }

  // Calculate the preferred width of each view in this column set, as well
  // as updating the remaining_width.
  fileprivate func calculateSize(type: SizeCalculationType) {
    // Reset the size and remaining sizes.
    for var viewState in viewStates {
      if !viewState.prefWidthFixed || !viewState.prefHeightFixed {
        var size: IntSize
        if type == SizeCalculationType.Minimum && canUseMinimum(viewState: viewState) {
          // If the min size is bigger than the preferred, use the preferred.
          // This relies on MINIMUM being calculated immediately after PREFERRED,
          // which the rest of this code relies on as well.
          size = viewState.view!.minimumSize
          if size.width > viewState.width {
            size.width = viewState.width
          }
          if size.height > viewState.height {
            size.height = viewState.height
          }
        } else {
          size = viewState.view!.preferredSize
          viewState.prefSize = size
        }

        if !viewState.prefWidthFixed {
          viewState.width = size.width
        }

        if !viewState.prefHeightFixed {
          viewState.height = size.height
        }

      }
      viewState.remainingWidth = viewState.width
      viewState.remainingHeight = viewState.height
    }

    LayoutElement.resetSizes(elements: &columns)

    // Distribute the size of each view with a col span == 1.
    for var viewState in viewStates {
      if viewState.colSpan == 1 {
        let column = columns[viewState.startCol]
        column.adjustSize(size: viewState.width)
        viewState.remainingWidth -= column.size
      }
    }

    // Make sure all linked columns have the same size.
    unifyLinkedColumnSizes()

    // Distribute the size of each view with a column span > 1.
    for var viewState in viewStates {
      // Update the remaining_width from columns this view_state touches.
      updateRemainingWidth(viewState: &viewState)
      // Distribute the remaining width.
      distributeRemainingWidth(viewState: viewState)
      // Update the size of linked columns.
      // This may need to be combined with previous step.
      unifyLinkedColumnSizes()
    }
  }

  // Distributes delta among the resizable columns. |honors_min_width| matches
  // that of |GridLayout::honors_min_width_|.
  fileprivate func resize(delta: Int, honorsMinWidth: Bool) {
    if delta < 0 && honorsMinWidth {
      resizeUsingMin(delta: delta)
      return
    }
    LayoutElement.distributeDelta(delta: delta,  elements: &columns)
  }

  // Used when GridLayout is given a size smaller than the preferred width.
  // |total_delta| is negative and the difference between the preferred width
  // and the target width.
  fileprivate func resizeUsingMin(delta: Int) {
    var totalDelta = abs(delta)

    var preferredColumnSizes = Array<Int>(repeating: 0, count: columns.count)
    
    for i in 0..<columns.count {
      preferredColumnSizes[i] = columns[i].size
    }

    // Recalculate the sizes using the min.
    calculateSize(type: ColumnSet.SizeCalculationType.Minimum)

    // Build up the set of columns that can be shrunk in |resize_data|, this
    // iteration also resets the size of the column back to the preferred size.
    var resizeData = Array<ColumnMinResizeData>()
    var totalPercent: Float = 0
    for i in 0..<columns.count {
      let column = columns[i]
      let available =
          max(0, preferredColumnSizes[i] -
                          max(column.minWidth, column.size))
      //DCHECK_GE(available, 0);
      // Set the size back to preferred. We'll reset the size if necessary later.
      column.size = preferredColumnSizes[i]
      
      if column.resizePercent <= 0 || available == 0 {
        continue
      }
      
      resizeData.append(ColumnMinResizeData(column: column, available: available, delta: 0))
      totalPercent += column.resizePercent
    }
    
    if resizeData.isEmpty {
      return
    }

    // Loop through the columns updating the amount available and the amount to
    // resize. This may take multiple iterations if the column min is hit.
    // Generally there are not that many columns in a GridLayout, so this code is
    // not optimized. Any time the column hits the min it is removed from
    // |resize_data|.
    while !resizeData.isEmpty && totalDelta > 0 {
      var nextIterationTotalPercent = totalPercent
      var nextIterationDelta = totalDelta
      //for var i = resizeData.length; i > 0; --i {
      for i in (0...resizeData.count).reversed() {
        var data = resizeData[i - 1]
        var delta =
            min(data.available,
                    Int(totalDelta * Int(data.column!.resizePercent) /
                                      Int(totalPercent)))
        // Make sure at least one column in resized (rounding errors may prevent
        // that).
        if i == 1 && delta == 0 && nextIterationDelta == totalDelta {
          delta = 1
        }

        nextIterationDelta -= delta
        data.delta += delta
        data.available -= delta
        
        if data.available == 0 {
          data.column!.size = data.column!.size - data.delta
          nextIterationTotalPercent -= data.column!.resizePercent
          // resize_data.erase(resize_data.begin() + (i - 1));
          resizeData.remove(at: (i - 1))
        }
      }
      totalDelta = nextIterationDelta
      totalPercent = nextIterationTotalPercent
    }

    for data in resizeData {
      if let col = data.column {
        col.size = col.size - data.delta
      }
    }
  }

  // Only use the minimum size if all the columns the view is in are resizable.
  fileprivate func canUseMinimum(viewState: ViewState) -> Bool {
    for i in 0..<viewState.colSpan {
      if columns[i + viewState.startCol].resizePercent <= 0 ||
        columns[i + viewState.startCol].sizeType == .Fixed {
        return false
      }
    }
    return true
  }

}

fileprivate func calculateSize(prefSize: Int, alignment: GridLayoutAlignment, location: inout Int, size: inout Int) {
  if alignment != .Fill {
    let availableSize = size
    size = min(size, prefSize)
    switch alignment {
      case .Leading:
        // Nothing to do, location already points to start.
        fallthrough
      case .Baseline:  // If we were asked to align on baseline, but
                                  // the view doesn't have a baseline, fall back
                                  // to center.
        fallthrough
      case .Center:
        location += (availableSize - size) / 2
      case .Trailing:
        location = location + availableSize - size
      default:
       assert(false)
    }
  }
}

fileprivate func findViewStateInsertionPos(viewState: ViewState, comparator: (ViewState, ViewState) -> Bool, viewStates: [ViewState]) -> Int {
  var lo = 0
  var hi = viewStates.count - 1
  var mid = (lo + hi)/2
  while lo <= hi {
    if comparator(viewStates[mid], viewState) {
      lo = mid + 1
    } else if comparator(viewState, viewStates[mid]) {
      hi = mid - 1
    } else {
      return mid
    }
    mid = (lo + hi)/2
  }
  return lo
}
