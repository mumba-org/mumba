// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor
import Graphics
import Gpu

// public enum LayerType : Int {
//   case NotDrawn    = 0
//   case NinePatch   = 1
//   case Textured    = 2
//   case SolidColor  = 3
//   case Video       = 4 
// }

public class Layer : LayerClient {

  public static var UILayerSettings: Compositor.LayerSettings {
    if Layer._layerSettings == nil {
      var settings = Compositor.LayerSettings(type: .SurfaceLayer)
      settings.useCompositorAnimationTimelines = true
      Layer._layerSettings = settings
    }
    return Layer._layerSettings!
  }

  public static func initializeUILayerSettings() {}

  public var delegate: LayerDelegate?

  public var compositor: UICompositor? {
    return Layer.getRoot(layer: self)._compositor
  }

  public var animator: LayerAnimator {
    get {
      guard let anim = _animator else {
        _animator = LayerAnimator.createDefaultAnimator()//createImplicitAnimator()
        _animator!.delegate = self
        return _animator!
      }
      return anim
    }
    set {
      _animator = newValue
      _animator!.delegate = self
    }
  }

  public var transform: Transform {
    get {
      return cclayer!.transform

    }
    set {
      animator.transform = newValue
    }
  }

  public var hideLayerAndSubtree: Bool {
    return cclayer!.hideLayerAndSubtree
  }

  // Return the target transform if animator is running, or the current
  // transform otherwise.
  public var targetTransform: Transform {
    if let anim = _animator, anim.isAnimatingProperty(property: .Transform) {
      return anim.transform
    }
    return Transform()
  }

  private (set) public var parent: Layer?

  private (set) public var type: LayerType

  public var position: FloatPoint {
    return cclayer.position
  }

  private (set) public var children: [Layer]

  public var opacity: Float {
    get {
      return cclayer.opacity
    }
    set {
      animator.opacity = newValue
    }
  }

  public var combinedOpacity: Float {
    var op = self.opacity
    var current = parent
    while current != nil {
      op = op * current!.opacity
      current = current!.parent
    }
    return op
  }

  public var targetOpacity: Float {
    if let anim = _animator, anim.isAnimatingProperty(property: .Opacity) {
      return anim.opacity
    }
    return opacity
  }

  public var bounds: IntRect {
    get {
      return _bounds
    }
    set {
      //_bounds = newValue
      animator.bounds = newValue
    }
  }

  public var targetBounds: IntRect {
    if let anim = _animator, anim.isAnimatingProperty(property: .Bounds) {
      return anim.bounds
    }
    return _bounds
  }

  public var masksToBounds: Bool {
    get {
      return cclayer.masksToBounds
    }
    set {
      cclayer.masksToBounds = newValue
    }
  }

  public var fillsBoundsOpaquely: Bool {
    get {
      return _fillsBoundsOpaquely
    }
    set {
      //guard _fillsBoundsOpaquely != newValue else {
      //  return
      //}
      _fillsBoundsOpaquely = newValue
      cclayer.contentsOpaque = _fillsBoundsOpaquely
    }
  }

  public var isVisible: Bool {
    get {
      return _visible
    }
    set {
      //_visible = newValue
      animator.visibility = newValue
    }
  }

  public var targetVisibility: Bool {
    if let anim = _animator, anim.isAnimatingProperty(property: .Visibility) {
      return anim.visibility
    }
    return _visible
  }

  public var name: String {
    get {
      return _name
    }
    set {
      _name = newValue
    }
  }

  public var size: IntSize {
    return _bounds.size
  }

  public var owner: LayerOwner?

  public var textureFlipped: Bool {
    get {
      if let tlayer = textureLayer {
        return tlayer.flipped
      }
      return false
    }
    set {
      if let tlayer = textureLayer {
        tlayer.flipped = newValue
      }
    }
  }

  public var textureSize: IntSize {
    get {
      return IntSize()
    }
    set (textureSizeInDip) {
      if let tlayer = textureLayer {
        if _frameSizeInDip == textureSizeInDip {
          return
        }
        _frameSizeInDip = textureSizeInDip
        recomputeDrawsContentAndUVRect()
        tlayer.setNeedsDisplay()
      }
    }
  }

  public var id: Int64 {
    return cclayer!.id
  }

  public var backgroundColor: Color {
    return cclayer.backgroundColor
  }

  public var targetColor: Color {
    if let anim = _animator, anim.isAnimatingProperty(property: .Color) {
      return anim.color
    }
    return cclayer.backgroundColor
  }

  public var backgroundBlur : Float {
    get {
      return _backgroundBlurRadius
    }
    set {
      _backgroundBlurRadius = newValue
      setLayerBackgroundFilters()
    }
  }

  public var layerSaturation: Float {
    get {
      return _layerSaturation
    }
    set {
      _layerSaturation = newValue
      setLayerFilters()
    }
  }

  public var layerBrightness: Float {
    get {
      return _layerBrightness
    }
    set {
      animator.brightness = newValue
    }
  }

  public var targetBrightness: Float {
    if let anim = _animator, anim.isAnimatingProperty(property: .Brightness) {
      return anim.brightness
    }
    return _layerBrightness
  }

  public var layerGrayscale: Float {
    get {
      return _layerGrayscale
    }
    set {
      animator.grayscale = newValue
    }
  }

  public var targetGrayscale: Float {
    if let anim = _animator, anim.isAnimatingProperty(property: .Grayscale) {
      return anim.grayscale
    }
    return _layerGrayscale
  }

  //  LayerAnimationDelegate


  public var subpixelPositionOffset: FloatVec2 {
    get {
      return _subpixelPositionOffset
    }
    set {
      _subpixelPositionOffset = newValue
      recomputePosition()
    }
  }

  public var alphaShape: ContiguousArray<IntRect>? {
    didSet {
      setLayerFilters()
    }
  }

  public var layerInverted: Bool {
    didSet {
      setLayerFilters()
    }
  }

  public var layerMask: Layer? {
    get {
      return _layerMask
    }
    set {
      if _layerMask === newValue {
        return
      }
      if _layerMask != nil {
        _layerMask!._layerMaskBackLink = nil
      }
      _layerMask = newValue
      if let layerMask = newValue {
        cclayer.layerMask = layerMask.cclayer
        layerMask._layerMaskBackLink = self
        layerMask.onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
      }
    }
  }

  public var isDrawn: Bool {
    var curLayer: Layer? = self
    while curLayer != nil && curLayer!._visible {
      curLayer = curLayer!.parent
    }
    return curLayer == nil
  }

  public var shouldDraw: Bool {
    return type != .None && combinedOpacity > 0.0
  }

  public var hasExternalContent: Bool {
    return textureLayer != nil || surfaceLayer != nil
  }

  public var paintableRegion: IntRect { 
    return IntRect(size: size)
  }

  public var fillsBoundsCompletely: Bool = false

  private (set) public var damagedRegion: Region
  private (set) public var paintRegion: Region  

  public var forceRenderSurface: Bool {
    get {
      return _forceRenderSurface
    }
    set {
      if _forceRenderSurface == newValue {
        return
      }
      _forceRenderSurface = newValue
      cclayer.forceRenderSurface = newValue
    }
  }

  public var hasPendingThreadedAnimations: Bool {
    return _pendingThreadedAnimations.count != 0
  }

  var isAnimating: Bool {
    if let anim = _animator {
      return anim.isAnimating
    }
    return false
  }

  public static func convertPointToLayer(source: Layer, target: Layer, point: inout IntPoint) {
    if source === target {
      return
    }

    let rootLayer = Layer.getRoot(layer: source)
    assert(rootLayer === Layer.getRoot(layer: target))

    if source !== rootLayer {
      let _ = source.convertPointForAncestor(ancestor: rootLayer, point: &point)
    }

    if target !== rootLayer {
      let _ = target.convertPointFromAncestor(ancestor: rootLayer, point: &point)
    }
  }

  public var syncBounds: Bool = false

  private static var _layerSettings: Compositor.LayerSettings?

  typealias Animations = [Compositor.Animation]

  private var observers: [LayerObserver] = []
  public var cclayer: Compositor.Layer!
  private var textureLayer: Compositor.TextureLayer?
  private var surfaceLayer: Compositor.SurfaceLayer?
  //private var delegatedRendererLayer: Compositor.DelegatedRendererLayer?
  private var solidColorLayer: Compositor.SolidColorLayer?
  private var contentLayer: Compositor.PictureLayer?
  private var ninePatchLayer: Compositor.NinePatchLayer?
  private var ninePatchLayerImage: Image?
  private var ninePatchLayerAperture: IntRect?
  private var mirrors: ContiguousArray<LayerMirror>
  private var cacheRenderSurfaceRequests: Int = 0
  private var deferredPaintRequests: Int = 0
  private var trilinearFilteringRequest: Int = 0
  private var _pendingThreadedAnimations: Animations
  private var _compositor: UICompositor?
  private var _animator: LayerAnimator?
  private var _layerMask: Layer?
  private var _layerMaskBackLink: Layer?
  private var _subpixelPositionOffset: FloatVec2
  private var _name: String
  private var _visible: Bool
  private var _forceRenderSurface: Bool
  private var _fillsBoundsOpaquely: Bool
  private var _backgroundBlurRadius: Float
  private var _layerSaturation: Float
  private var _layerBrightness: Float
  private var _layerGrayscale: Float
  private var _zoom: Float
  private var _zoomInset: Int
  private var _mailbox: TextureMailbox
  private var _mailboxReleaseCallback: SingleReleaseCallback?
  private var _frameSizeInDip: IntSize
  private var _bounds: IntRect
  private var _deviceScaleFactor: Float

  public init(type: LayerType) throws {

    children = [Layer]()
    self.type = type
    layerInverted = false
    damagedRegion = Region()
    paintRegion = Region()
    _pendingThreadedAnimations = Animations()
    _bounds = IntRect()
    _name = ""
    _visible = true
    _forceRenderSurface = false
    _frameSizeInDip = IntSize()
    _fillsBoundsOpaquely = true
    _backgroundBlurRadius = 0
    _layerSaturation = 0.0
    _layerBrightness = 0.0
    _layerGrayscale = 0.0
    _zoom = 1
    _zoomInset = 0
    _deviceScaleFactor = 1.0
    _subpixelPositionOffset = FloatVec2()
    _mailbox = TextureMailbox()
     mirrors = ContiguousArray<LayerMirror>()

    //print("UI.Layer: type = \(type) value = \(type.rawValue)")
    var layerSettings = Layer.UILayerSettings
    if type == .SolidColorLayer {
      //print("UI.Layer: creating solid color layer") 
      cclayer = try Compositor.Layer.createSolidColorLayer(settings: &layerSettings, client: self)
    } else if type == .NinePatchLayer {
      //print("UI.Layer: creating nine patch layer")
      cclayer = try Compositor.Layer.createNinePatchLayer(settings: &layerSettings, client: self)
    // note: in the classic setting Textured created a PictureLayer
    //       so we need to see how it affects the rendering 
    //       by using a real texture layer now
    } else if type == .TextureLayer {
      //print("UI.Layer: creating texture layer")
      textureLayer = try Compositor.Layer.createTextureLayer(settings: &layerSettings, client: self)
      cclayer = textureLayer!
    } else if type == .VideoLayer {
      //print("UI.Layer: creating video layer")
      cclayer = try Compositor.Layer.createVideoLayer(settings: &layerSettings, client: self)
    } else {
      //print("UI.Layer: creating picture layer") 
      cclayer = try Compositor.Layer.createPictureLayer(settings: &layerSettings, client: self)
    }

    guard cclayer != nil else {
      throw UIError.OnLayerCreate(exception: UIException.CreateLayer)
    }

    cclayer!.transformOrigin = FloatPoint3()
    cclayer!.contentsOpaque = true
    cclayer!.setIsDrawable(isDrawable: type != .None)
    cclayer!.client = self
    cclayer!.elementId = UInt64(cclayer!.id)
    recomputePosition()
  }

  public init(layer: Compositor.Layer) throws {

    children = [Layer]()
    type = .PictureLayer
    layerInverted = false
    damagedRegion = Region()
    paintRegion = Region()
    _pendingThreadedAnimations = Animations()
    _bounds = IntRect()
    _name = ""
    _visible = true
    _forceRenderSurface = false
    _frameSizeInDip = IntSize()
    _fillsBoundsOpaquely = true
    _backgroundBlurRadius = 0
    _layerSaturation = 0.0
    _layerBrightness = 0.0
    _layerGrayscale = 0.0
    _zoom = 1
    _zoomInset = 0
    _deviceScaleFactor = 1.0
    _subpixelPositionOffset = FloatVec2()
    _mailbox = TextureMailbox()
     mirrors = ContiguousArray<LayerMirror>()
    cclayer = layer
   
    guard cclayer != nil else {
      throw UIError.OnLayerCreate(exception: UIException.CreateLayer)
    }

    cclayer!.transformOrigin = FloatPoint3()
    cclayer!.contentsOpaque = true
    cclayer!.setIsDrawable(isDrawable: type != .None)
    cclayer!.client = self
    cclayer!.elementId = UInt64(cclayer!.id)
    recomputePosition()
  }

  public convenience init() throws {
    try self.init(type: .PictureLayer)
  }

  deinit {
    
    for observer in observers {
     observer.layerDestroyed(layer: self)
    }

    if _animator != nil{
      _animator!.delegate = nil
      _animator = nil
    }
    if let compositor = _compositor {
      compositor.rootLayer = nil
    }
    if let p = parent {
      p.remove(child: self)
    }

    if _layerMask != nil {
      _layerMask = nil
    }

    if let backLink = _layerMaskBackLink {
      backLink.layerMask = nil
    }

    for child in children {
      child.parent = nil
    }

    //cclayer.removeLayerAnimationEventObserver(animationObserver: self)
    cclayer.removeFromParent()
  }

  public func addObserver(observer: LayerObserver) {
    observers.append(observer)
  }

  public func removeObserver(observer: LayerObserver) {
    for (i, current) in observers.enumerated() {
      if current === observer {
        observers.remove(at: i)
        break
      }
    }
  }

  public func setCompositor(compositor: UICompositor, rootLayer: Compositor.Layer) {
     guard compositor.rootLayer === self else {
      return
     }
     _compositor = compositor
     onDeviceScaleFactorChanged(deviceScaleFactor: compositor.deviceScaleFactor)
     //addAnimatorsInTreeToCollection(collection: compositor.layerAnimatorCollection)
     rootLayer.addChild(child: cclayer)
     //sendPendingThreadedAnimations()
     setCompositorForAnimatorsInTree(compositor)
  }

  public func resetCompositor() {
    if _compositor != nil {
      removeAnimatorsInTreeFromCollection(collection: _compositor!.layerAnimatorCollection)
      _compositor = nil
    }
  }

  public func add(child: Layer) {
    //print("UI.Layer: adding layer \(child.id) as child of \(self.id)")
    if let parent = child.parent {
      parent.remove(child: child)
    }
    child.parent = self
    children.append(child)
    cclayer.addChild(child: child.cclayer)
    child.onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    if let c = compositor {
      child.setCompositorForAnimatorsInTree(c)
    }
  }

  public func remove(child: Layer) {
    if let childAnimator = child._animator {
      childAnimator.stopAnimatingProperty(property: .Bounds)
    }

    if let c = compositor {
      child.resetCompositorForAnimatorsInTree(c)
    }

    if let index = children.firstIndex(where: { child === $0 }) {
      children.remove(at: index)
    }

    child.parent = nil
    child.cclayer.removeFromParent()
  }

  public func stackAtTop(child: Layer) {
    if children.count <= 1 {
      return
    }
    let last = children[children.endIndex - 1]
    if child !== last {
      stackAbove(child: child, other: last)
    }
  }

  public func stackAbove(child: Layer, other: Layer) {
    stackRelativeTo(child: child, other: other, above: true)
  }

  public func stackAtBottom(child: Layer) {
    if children.count <= 1 {
      return
    }
    let first = children[0]
    if child !== first {
      stackBelow(child: child, other: first)
    }
  }

  public func stackBelow(child: Layer, other: Layer) {
    stackRelativeTo(child: child, other: other, above: false)
  }

  public func contains(other: Layer) -> Bool {
    var parent: Layer? = other
    while parent != nil {
      if parent === self {
        return true
      }
      parent = parent!.parent
    }
    return false
  }

  public func setBackgroundZoom(zoom: Float, inset: Int) {
    _zoom = zoom
    _zoomInset = inset

    setLayerBackgroundFilters()
  }

  public func getTargetTransformRelativeTo(ancestor: Layer, transform: inout Transform) -> Bool {
    var p: Layer? = self
    while p != nil && p !== ancestor {
      let current = p!
      var translation = Transform()
      translation.translate(x: Float(current.bounds.x), y: Float(current.bounds.y))
      if current.targetTransform.isIdentity {
        transform.concatTransform(transform: current.targetTransform)
      }
      transform.concatTransform(transform: translation)
      p = current.parent
    }
    return p === ancestor
  }

  public func setTextureMailbox(mailbox: TextureMailbox, releaseCallback: @escaping SingleReleaseCallback, textureSizeInDip: IntSize) throws {
    if textureLayer == nil {
      var layerSettings = Layer.UILayerSettings
      let newTextureLayer = try Compositor.Layer.createTextureLayer(settings: &layerSettings, client: self)
      newTextureLayer.flipped = true
      var newLayer = newTextureLayer as Compositor.Layer
      switchToLayer(newLayer: &newLayer)
      textureLayer = newTextureLayer
      _frameSizeInDip = IntSize()
    }
    if let callback = _mailboxReleaseCallback {
      callback(Gpu.SyncToken(), false)
    }
    _mailboxReleaseCallback = releaseCallback
    _mailbox = mailbox
    textureSize = textureSizeInDip
  }

  // public func setShowDelegatedContent(frameProvider: DelegatedFrameProvider, frameSizeInDip: IntSize) throws {
  //   guard type == .Textured || type == .SolidColor else {
  //     return
  //   }

  //   var layerSettings = Layer.UILayerSettings
  //   let newDelegatedLayer = try Compositor.Layer.createDelegatedRendererLayer(settings: &layerSettings,  client: self, frameProvider)
  //   var newLayer = newDelegatedLayer as Compositor.Layer
  //   switchToLayer(newLayer: &newLayer)
  //   delegatedRendererLayer = newDelegatedLayer

  //   _frameSizeInDip = frameSizeInDip
  //   recomputeDrawsContentAndUVRect()
  // }

  public func setShowSurface(surfaceId: SurfaceId,
    satisfyCallback: SurfaceLayer.SatisfyCallback,
    requireCallback: SurfaceLayer.RequireCallback,
    surfaceSize: IntSize,
    scale: Float,
    frameSizeInDip: IntSize) throws {
    assert(type == .TextureLayer || type == .SolidColorLayer || type == .PictureLayer)
    var layerSettings = Layer.UILayerSettings
    let newSurfaceLayer = try Compositor.Layer.createSurfaceLayer(settings: &layerSettings, client: self,
      satisfyCallback: satisfyCallback, requireCallback: requireCallback)

    newSurfaceLayer.setSurfaceId(surfaceId: surfaceId, scale: scale, size: surfaceSize)
    var newLayer = newSurfaceLayer as Compositor.Layer
    switchToLayer(newLayer: &newLayer)
    surfaceLayer = newSurfaceLayer
    _frameSizeInDip = frameSizeInDip
    recomputeDrawsContentAndUVRect()
  }

  public func setShowSolidColorContent() throws {
    guard type == .SolidColorLayer else {
      return
    }

    if solidColorLayer != nil {
      return
    }

    var layerSettings = Layer.UILayerSettings
    let newSolidColorLayer = try Compositor.Layer.createSolidColorLayer(settings: &layerSettings, client: self)
    var newLayer = newSolidColorLayer as Compositor.Layer
    switchToLayer(newLayer: &newLayer)
    solidColorLayer = newSolidColorLayer

    _mailbox = TextureMailbox()
    if let callback = _mailboxReleaseCallback {
      callback(Gpu.SyncToken(), false)
      _mailboxReleaseCallback = nil
    }
    recomputeDrawsContentAndUVRect()
  }

   public func updateNinePatchLayerImage(image: Image) {
    guard type == .NinePatchLayer && ninePatchLayer != nil else {
      return
    }
    ninePatchLayerImage = image
    //if let bitmap = ninePatchLayerImage!.getBitmapFor(scale: deviceScaleFactor) {
    //  var bitmapCopy = Bitmap()
    //  if bitmap.isImmutable {
    //    bitmapCopy = bitmap
    //   } else {
        // UIResourceBitmap requires an immutable copy of the input |bitmap|.
    //     let _ = bitmap.copy(to: &bitmapCopy)
    //     bitmapCopy.isImmutable = true
    //   }
    //   ninePatchLayer!.bitmap = bitmapCopy
    // }
    if let bitmap = image.getBitmapFor(scale: self.deviceScaleFactor) {
      ninePatchLayer!.bitmap = bitmap
    }
   }

   public func updateNinePatchLayerAperture(apertureInDip: IntRect) {
    guard type == .NinePatchLayer && ninePatchLayer != nil else {
      return
    }
    ninePatchLayerAperture = apertureInDip
    let apertureInPixel = IntRect.convertToPixel(scaleFactor: deviceScaleFactor, rectInDip: apertureInDip)
    ninePatchLayer!.aperture = apertureInPixel
   }

   public func updateNinePatchLayerBorder(border: IntRect) {
    guard type == .NinePatchLayer && ninePatchLayer != nil else {
      return
    }
    ninePatchLayer!.border = border
   }

   public func schedulePaint(invalidRect: IntRect) -> Bool {
    //print("Layer.schedulePaint")
    if type == .SolidColorLayer && textureLayer == nil {// || (delegate == nil && !_mailbox.isValid) {
      return false
    }

    if type == .NinePatchLayer {
      return false
    }

    let _ = damagedRegion.union(rect: invalidRect)
    if let mask = self.layerMask {
      let _ = mask.damagedRegion.union(rect: invalidRect)
    }
    if contentLayer == nil || deferredPaintRequests == 0 {
      //print("Layer.schedulePaint: calling scheduleDraw()")
      scheduleDraw()
    }
    
    return true
   }

   public func scheduleDraw() {
    //print("Layer.scheduleDraw")
    if let c = compositor {
      //print("Layer.scheduleDraw: calling compositor.scheduleDraw()")
      c.scheduleDraw()
    } else {
      //print("Layer.scheduleDraw: no compositor. doing nothing..")
    }
   }

   public func sendDamagedRects() {
    //print("Layer.sendDamagedRects")
     guard !damagedRegion.isEmpty else {
       return
     }

     // actually: delegate == nil && _transferResource.mailboxHolder.mailbox.isZero
     //guard delegate == nil && !_mailbox.isValid else {
     //  //print("Layer.sendDamagedRects: delegate == null mailbox.isValid == false. cancelling")
     //  return
     //}
   
     //guard (contentLayer == nil && deferredPaintRequests == 0) else {
     //  //print("Layer.sendDamagedRects: contentLayer != nil && deferredPaintRequests > 0 = \(deferredPaintRequests). cancelling")
     //  return
     //}
     //if contentLayer != nil && deferredPaintRequests > 0 {
     //  return
     //}

     let damagedRects = RegionIterator(region: damagedRegion)
     while damagedRects.hasRect {
       cclayer.setNeedsDisplayRect(dirtyRect: damagedRects.rect)
       damagedRects.next()
     }
    
    if let mask = self.layerMask {
      mask.sendDamagedRects()
    }

    if contentLayer != nil {
      let _ = paintRegion.union(region: damagedRegion)
    }
    
     damagedRegion.clear()
   }

  //  public func sendDamagedRects() {
  //   //print("Layer.sendDamagedRects")
  //   if damagedRegion.isEmpty {
  //     //print("Layer.sendDamagedRects: damagedRegion.isEmpty == true. cancelling")
  //     return
  //   }

  //   if delegate == nil && !_mailbox.isValid {
  //     //print("Layer.sendDamagedRects: delegate == null mailbox.isValid == false. cancelling")
  //     return
  //   }

  //   let iter = RegionIterator(region: damagedRegion)
  //   while iter.hasRect {
  //     cclayer.setNeedsDisplayRect(dirtyRect: iter.rect)
  //     iter.next()
  //   }
  //  }

   public func clearDamagedRects() {
    damagedRegion.clear()
   }

   public func completeAllAnimations() {
    var animators = [LayerAnimator]()
    collectAnimators(animators: &animators)
    for anim in animators {
      anim.stopAnimating()
    }
   }

   public func suppressPaint() {
    if delegate == nil {
      return
    }
    delegate = nil
    for child in children {
      child.suppressPaint()
    }
   }

   public func onDeviceScaleFactorChanged(deviceScaleFactor: Float) {
    if deviceScaleFactor == _deviceScaleFactor {
      return
    }
    if let anim = _animator {
      anim.stopAnimatingProperty(property: .Transform)
    }
    let oldScaleFactor = _deviceScaleFactor
    _deviceScaleFactor = deviceScaleFactor
    recomputeDrawsContentAndUVRect()
    recomputePosition()
    if ninePatchLayer != nil {
      updateNinePatchLayerImage(image: ninePatchLayerImage!)
      updateNinePatchLayerAperture(apertureInDip: ninePatchLayerAperture!)
    }
    let _ = schedulePaint(invalidRect: IntRect(size: _bounds.size))
    if let d = delegate {
      d.onDeviceScaleFactorChanged(oldScaleFactor: oldScaleFactor, newScaleFactor: deviceScaleFactor)
    }
    for child in children {
     child.onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    }

    if let layerMask = _layerMask {
      layerMask.onDeviceScaleFactorChanged(deviceScaleFactor: deviceScaleFactor)
    }
   }

   //public func onDelegatedFrameDamage(damageRectInDip: IntRect) {
   // assert(delegatedRendererLayer != nil || surfaceLayer != nil)
   // if let d = delegate {
   //   d.onDelegatedFrameDamage(damageRectInDip: damageRectInDip)
   // }
   //}

   public func requestCopyOfOutput(request: CopyOutputRequest) {
    cclayer.requestCopyOfOutput(request: request)
   }


  // should be called for LayerSolidColor layer only
  public func setColor(color: Color) {
    animator.color = color
  }

  public func addCacheRenderSurfaceRequest() {
    cacheRenderSurfaceRequests += 1
    if cacheRenderSurfaceRequests == 1 {
      cclayer?.cacheRenderSurface = true
    }
  }

  public func removeCacheRenderSurfaceRequest() {
    cacheRenderSurfaceRequests -= 1
    if cacheRenderSurfaceRequests == 0 {
      cclayer?.cacheRenderSurface = false
    }
  }

  public func addDeferredPaintRequest() {
    deferredPaintRequests += 1
  }

  public func removeDeferredPaintRequest() {
    deferredPaintRequests -= 1
    if deferredPaintRequests == 0 && !damagedRegion.isEmpty {
      scheduleDraw()
    }
  }

  public func addTrilinearFilteringRequest() {
    trilinearFilteringRequest += 1
    if trilinearFilteringRequest == 1 {
      cclayer?.trilinearFiltering = true
    }
  }

  public func removeTrilinearFilteringRequest() {
    trilinearFilteringRequest -= 1
    if trilinearFilteringRequest == 0 {
      cclayer?.trilinearFiltering = false
    }
  }

  public func getApproximateUnsharedMemoryUsage() -> Int {
    return 0
  }

  public func paintContentsToDisplayList(
    paintingStatus: PaintingControlSetting) -> DisplayItemList {
    //print("\n\nLayer.paintContentsToDisplayList\n\n")
     
    let localBounds  = IntRect(size: bounds.size)
    let invalidation = IntRect.intersectRects(a: paintRegion.bounds, b: localBounds)
    paintRegion.clear()

    let displayList = DisplayItemList()

    if let layerDelegate = delegate {
      layerDelegate.onPaintLayer(context: PaintContext(
        list: displayList, 
        scaleFactor: deviceScaleFactor, 
        invalidation: invalidation, 
        isPixelCanvas: compositor!.isPixelCanvas
      ))
    }

    displayList.finalize()
    
    for mirror in mirrors {
      let _ = mirror.dest.schedulePaint(invalidRect: invalidation)
    }
    
    //print("---- Layer.paintContentsToDisplayList: returning a display item list with \(displayList.totalOpCount) ops")
    
    return displayList
  }
  
  public func prepareTransferableResource(
    bitmapRegistrar: TextureLayer,
    transferableResource: TransferableResource,
    releaseCallback: inout SingleReleaseCallback?) -> Bool {

   guard let callback = _mailboxReleaseCallback else {
     return false
   }

   //transferableResource = _transferableResource
   releaseCallback = callback
   return true
  }

  func switchToLayer(newLayer: inout Compositor.Layer) {
    if let anim = _animator {
      anim.stopAnimatingProperty(property: .Transform)
      anim.stopAnimatingProperty(property: .Opacity)
    }

    if let tlayer = textureLayer {
      tlayer.clearClient()
    }

    cclayer.removeAllChildren()
    if let parent = cclayer.parent {
      parent.replaceChild(child: cclayer, newLayer: newLayer)
    }
    cclayer.client = nil
    //cclayer.removeLayerAnimationEventObserver(animationObserver: self)
    newLayer.opacity = cclayer.opacity
    newLayer.transform = cclayer.transform
    newLayer.position = cclayer.position
    newLayer.backgroundColor = cclayer.backgroundColor

    cclayer = newLayer
    textureLayer = nil
    //delegatedRendererLayer = nil
    surfaceLayer = nil
    solidColorLayer = nil
    contentLayer = nil
    ninePatchLayer = nil

    //cclayer.addLayerAnimationEventObserver(animationObserver: self)

    for child in children {
      if let layer = child.cclayer {
        layer.addChild(child: layer)
      }
    }
    cclayer.client = self
    cclayer.transformOrigin = FloatPoint3()
    cclayer.contentsOpaque = _fillsBoundsOpaquely
    cclayer.forceRenderSurface = _forceRenderSurface
    cclayer.setIsDrawable(isDrawable: type != .None)
    cclayer.hideLayerAndSubtree = !_visible

    setLayerFilters()
    setLayerBackgroundFilters()
  }

   func collectAnimators(animators: inout [LayerAnimator]) {
    if let anim = _animator, isAnimating {
      animators.append(anim)
    }
    for child in children {
      child.collectAnimators(animators: &animators)
    }
   }

   func stackRelativeTo(child: Layer, other: Layer, above: Bool) {
    assert(child !== other)       // TODO: use exception here.. instead of asserts
    assert(self === child.parent)
    assert(self === other.parent)

    var childIndex = 0, otherIndex = 0

    for (index, elem) in children.enumerated() {
      if elem === child {
        childIndex = index
      } else if elem === other {
        otherIndex = index
      }
    }

    if (above && childIndex == otherIndex + 1) || (!above && childIndex + 1 == otherIndex) {
      return
    }

    var destIndex = 0
    if above {
      if childIndex < otherIndex {
        destIndex = otherIndex
      } else {
        destIndex = otherIndex + 1
      }
    } else {
      if childIndex < otherIndex {
        destIndex = otherIndex - 1
      } else {
        destIndex = otherIndex
      }
    }

    children.remove(at: childIndex)
    children.insert(child, at: destIndex)

    child.cclayer.removeFromParent()
    cclayer.insertChild(child: child.cclayer, index: destIndex)
   }

   func convertPointForAncestor(ancestor: Layer, point: inout IntPoint) -> Bool {
    var transform = Transform()
    let result = getTargetTransformRelativeTo(ancestor: ancestor, transform: &transform)
    var p = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    transform.transformPoint(point: &p)
    point = IntPoint.toFloored(point: FloatPoint(p))
    return result
   }

   func convertPointFromAncestor(ancestor: Layer, point: inout IntPoint) -> Bool {
    var transform = Transform()
    let result = getTargetTransformRelativeTo(ancestor: ancestor, transform: &transform)
    var p = FloatPoint3(x: Float(point.x), y: Float(point.y), z: 0.0)
    let _ = transform.transformPointReverse(point: &p)
    point = IntPoint.toFloored(point: FloatPoint(p))
    return result
   }

   func recomputeDrawsContentAndUVRect() {
    guard cclayer != nil else {
      return
    }
    var size = IntSize(_bounds.size)
    if textureLayer != nil {
      size.setToMin(other: _frameSizeInDip)
      let uvTopLeft = FloatPoint(x: 0, y: 0)
      let uvBottomRight = FloatPoint(x: Float(size.width / _frameSizeInDip.width),
          y: Float(size.height / _frameSizeInDip.height))
      textureLayer!.setUV(topLeft: uvTopLeft, bottomRight: uvBottomRight)
    } //else if delegatedRendererLayer != nil || surfaceLayer != nil {
     // size.setToMin(other: _frameSizeInDip)
    //}
    cclayer.bounds = size
   }

   func recomputePosition() {
     cclayer.position = FloatPoint(_bounds.origin) + _subpixelPositionOffset
   }

   func setLayerFilters() {
    let filters = FilterOperations()

    if _layerSaturation > 0 {
      filters.append(filter: FilterOperation.createSaturateFilter(amount: _layerSaturation))
    }

    if _layerGrayscale > 0 {
      filters.append(filter: FilterOperation.createGrayscaleFilter(amount: _layerGrayscale))
    }

    if layerInverted {
      filters.append(filter: FilterOperation.createInvertFilter(amount: 1.0))
    }

    if _layerBrightness > 0 {
      filters.append(filter: FilterOperation.createSaturatingBrightnessFilter(amount: _layerBrightness))
    }

    if let shapes = alphaShape {
      filters.append(filter: FilterOperation.createAlphaThresholdFilter(shape: shapes, innerThreshold: 0, outerThreshold: 0))
    }

    cclayer.filters = filters
   }

   func setLayerBackgroundFilters() {
    let filters = FilterOperations()

    if _zoom != 1 {
      filters.append(filter: FilterOperation.createZoomFilter(amount: _zoom, inset:_zoomInset))
    }

    if _backgroundBlurRadius > 0 {
      filters.append(filter: FilterOperation.createBlurFilter(amount: _backgroundBlurRadius))
    }

    cclayer.backgroundFilters = filters
   }

  //  func sendPendingThreadedAnimations() {

  //   for elem in _pendingThreadedAnimations {
  //     let _ = cclayer.addAnimation(animation: elem)
  //   }
  //   _pendingThreadedAnimations.removeAll()

  //   for child in children {
  //     child.sendPendingThreadedAnimations()
  //   }
  //  }

   func addAnimatorsInTreeToCollection(collection: LayerAnimatorCollection) {
    if let anim = _animator, isAnimating {
      anim.addToCollection(collection: collection)
    }
    for child in children {
      child.addAnimatorsInTreeToCollection(collection: collection)
    }
   }

   func removeAnimatorsInTreeFromCollection(collection: LayerAnimatorCollection) {
    if let anim = _animator, isAnimating {
      anim.removeFromCollection(collection: collection)
    }
    for child in children {
      child.removeAnimatorsInTreeFromCollection(collection: collection)
    }
   }

  func setCompositorForAnimatorsInTree(_ compositor: UICompositor) {
    let collection = compositor.layerAnimatorCollection!
    if let currentAnimator = _animator {
      if currentAnimator.isAnimating {
        currentAnimator.addToCollection(collection: collection)
      }
      currentAnimator.attachLayerAndTimeline(compositor: compositor)
    }
    for child in children {
      child.setCompositorForAnimatorsInTree(compositor)
    }
  }
  
  func resetCompositorForAnimatorsInTree(_ compositor: UICompositor) {
    let collection = compositor.layerAnimatorCollection!
    if let anim = _animator {
      anim.detachLayerAndTimeline(compositor: compositor)
      anim.removeFromCollection(collection: collection)
    }
    for child in children {
      child.resetCompositorForAnimatorsInTree(compositor)
    }
  }

   func onMirrorDestroyed(_ mirror: LayerMirror) {
     if let index = mirrors.firstIndex(where: { mirror === $0 }) {
       mirrors.remove(at: index)
     }
   }

   static func getRoot(layer: Layer) -> Layer {
     var root = layer
     while root.parent != nil {
       root = root.parent!
     }
     return root
   }

}

extension Layer : LayerAnimationDelegate {

  public var layerAnimatorCollection: LayerAnimatorCollection? {
    if let c = compositor {
      return c.layerAnimatorCollection!
    }
    return nil
  }

  public var deviceScaleFactor: Float {
    return _deviceScaleFactor
  }

  public var boundsForAnimation: IntRect {
    //get {
      return bounds
    //}
    // set (newBounds) {
    //  let oldBounds = _bounds
    //  //let newBounds = IntRect(x:0, y: 0, width: 300, height: 300)
    //  ////print("newvalue: \(newValue) bounds: \(_bounds)")
    //  if newBounds == _bounds {
    //    return
    //  }

    //  var closure: LayerChangeCallback? = nil
    //  let wasMove = _bounds.size == newBounds.size
    //  _bounds = newBounds

    //  recomputeDrawsContentAndUVRect()
    //  recomputePosition()

    //  if let closurefn = closure {
    //    closurefn(oldBounds)
    //  }
    //  if let layerDelegate = delegate {
    //    // TODO: see if we dont really need GetBoundsForAnimation/SetBoundsFromAnimation duo
    //   layerDelegate.onLayerBoundsChange(oldBounds: oldBounds, reason: PropertyChangeReason.FromAnimation)
    //  }

    //  if wasMove {
    //    // Don't schedule a draw if we're invisible. We'll schedule one
    //    // automatically when we get visible.
    //    if isDrawn {
    //      scheduleDraw()
    //    }
    //  } else {
    //    // Always schedule a paint, even if we're invisible.
    //    let _ = schedulePaint(invalidRect: IntRect(size: bounds.size))
    //  }
    // }
  }

  public var transformForAnimation: Transform {
    //get {
      return transform
    //}
    //set {
    // cclayer.transform = newValue
    //}
  }

  public var opacityForAnimation: Float {
    //get {
      return opacity
    //}
    //set {
     //cclayer.opacity = newValue
     //scheduleDraw()
    //}
  }

  public var visibilityForAnimation: Bool {
    //get {
      return isVisible
    //}
    //set {
    // if _visible == newValue {
    //   return
    // }
    // _visible = newValue
    // cclayer.hideLayerAndSubtree = !_visible
    //}
  }

  public var brightnessForAnimation: Float {
    //get {
      return layerBrightness
    //}
    //set {
    // _layerBrightness = newValue
    // setLayerFilters()
    //}
  }

  public var grayscaleForAnimation: Float {
    //get {
      return layerGrayscale
    //}
    //set {
    // _layerGrayscale = newValue
    // setLayerFilters()
    //}
  }

  public var colorForAnimation: Color {
    //get {
     if solidColorLayer != nil {
       return solidColorLayer!.backgroundColor
     }
     return Color.Black
    //}
    //set {
    // assert(type == .SolidColor)
    // cclayer.backgroundColor = newValue
    // fillsBoundsOpaquely = (Color.alpha(color: newValue) == 0xFF)
    //}
  }
 
  public var uiLayer: UI.Layer? {
    return self
  }
  
  public var compositorLayer: Compositor.Layer? {
    return cclayer
  }
   
  public var threadedAnimationDelegate: LayerThreadedAnimationDelegate? { 
    return animator
  }
  
  public var frameNumber: Int {
    if let c = _compositor {
      return c.activatedFrameCount
    }
    return 0
  }

  public var refreshRate: Float {
    if let c = _compositor {
      return c.refreshRate
    }
    return 60.0
  }

  public func scheduleDrawForAnimation() {
    scheduleDraw()
  }

  // public func addThreadedAnimation(animation: Compositor.Animation) {
  //  guard cclayer != nil else {
  //    return
  //  }
  //  /// Until this layer has a compositor (and hence cc_layer_ has a
  //  /// LayerTreeHost), addAnimation will fail.
  //  if compositor != nil {
  //    let _ = cclayer.addAnimation(animation: animation)
  //  } else {
  //    _pendingThreadedAnimations.append(animation)
  //  }
  // }

  // public func removeThreadedAnimation(animationId: Int) {
  //  guard cclayer != nil else {
  //    return
  //  }
  //  if _pendingThreadedAnimations.count == 0 {
  //    cclayer.removeAnimation(animationId: animationId)
  //    return
  //  }

  //  for (index, elem) in _pendingThreadedAnimations.enumerated() {
  //    if elem.id == animationId {
  //      _pendingThreadedAnimations.remove(at: index)
  //    }
  //  }
  // }

  public func setBoundsFromAnimation(bounds toBounds: IntRect, reason: PropertyChangeReason) {
    guard toBounds != _bounds else {
      return
    }

    let oldBounds = _bounds
    _bounds = toBounds

    recomputeDrawsContentAndUVRect()
    recomputePosition()

    if let d = delegate {
      d.onLayerBoundsChanged(oldBounds: oldBounds, reason: reason)
    }

    if toBounds.size == oldBounds.size {
      /// Don't schedule a draw if we're invisible. We'll schedule one
      /// automatically when we get visible.
      if isDrawn {
        scheduleDraw()
      }
    } else {
      /// Always schedule a paint, even if we're invisible.
      let _ = schedulePaint(invalidRect: IntRect(size: toBounds.size))
    }

    if syncBounds {
      for mirror in mirrors {
        mirror.dest.bounds = toBounds
      }
    }
  }
  
  public func setTransformFromAnimation(transform: Transform, reason: PropertyChangeReason) {
    let oldTransform = self.transform
    cclayer.transform = transform
    if let d = delegate {
      d.onLayerTransformed(oldTransform: oldTransform, reason: reason)
    }
  }
  
  public func setOpacityFromAnimation(opacity: Float, reason: PropertyChangeReason) {
    cclayer.opacity = opacity
    if let d = delegate {
      d.onLayerOpacityChanged(reason: reason)
    }
    scheduleDraw()
  }
  
  public func setVisibilityFromAnimation(visibility: Bool, reason: PropertyChangeReason) {
    if _visible == visibility {
      return
    }

    _visible = visibility
    cclayer.hideLayerAndSubtree = !_visible
  }

  public func debug() {
    var current: Compositor.Layer? = cclayer
    while current != nil {
      //print("layer \(current!.id): \n hideLayerAndSubtree: \(current!.hideLayerAndSubtree)\n drawsContent: \(current!.drawsContent)\n visibleLayerRect: w: \(current!.visibleLayerRect.width) h: \(current!.visibleLayerRect.height)\n  contentsOpaque: \(current!.contentsOpaque)\n opacity: \(current!.opacity)\n effectiveOpacity: \(current!.effectiveOpacity)\n masksToBounds: \(current!.masksToBounds)\n")
      current = current!.parent
    }
  }
  
  public func setBrightnessFromAnimation(brightness: Float, reason: PropertyChangeReason) {
    _layerBrightness = brightness
    setLayerFilters()
  }
  
  public func setGrayscaleFromAnimation(grayscale: Float,reason: PropertyChangeReason) {
    _layerGrayscale = grayscale
    setLayerFilters()
  }

  public func setColorFromAnimation(color: Color, reason: PropertyChangeReason) {
    cclayer.backgroundColor = color
    fillsBoundsOpaquely = color.a == 0xff
  }

}

// extension Layer : Compositor.LayerAnimationEventObserver {

//   public func onAnimationStarted(event: AnimationEvent) {
//     _animator.onThreadedAnimationStarted(event: event, targetProperty: , groupId:)
//   }

// }

internal class LayerMirror : LayerDelegate, LayerObserver {
  public let source: Layer
  public let dest: Layer

  init(source: Layer, dest: Layer) {
    self.source = source
    self.dest = dest
    dest.addObserver(observer: self)
    dest.delegate = self
  }

  deinit {
    dest.removeObserver(observer: self)
    dest.delegate = nil
  }

  public func onPaintLayer(context: PaintContext) {
    //print(" --- LayerMirror.onPaintLayer() ---")
    if let d = source.delegate {
      d.onPaintLayer(context: context)
    }
  }

  public func onLayerDestroyed() {
    source.onMirrorDestroyed(self)
  }

}