// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics
import Base

public typealias RendererCapabilities = Int
public typealias ResourceProvider = Int
public typealias TileManager = Int
public typealias FrameRateCounter = Int
public typealias MemoryHistory = Int
public typealias VideoFrameControllerClient = Int
public typealias HeadsUpDisplayLayer = Int
public typealias ScaleGroup = Int
public typealias SyncedElasticOverscroll = Int
public typealias SyncedTopControls = Int
public typealias GpuRasterizationStatus = Int
public typealias TaskRunnerProvider = Int
public typealias LayerList = Int
public typealias UIResourceRequestQueue = Int
public typealias ScrollbarAnimationController = Int
public typealias PrioritizedTile = Int
public typealias ScrollState = Int
public typealias UIResourceId = Int
public typealias ScrollbarLayer = Int
public typealias ScrollbarSet = Int
public typealias PendingPageScaleAnimation = Int
public typealias ResourceId = Int

public class LayerTree {

	public var settings: LayerTreeSettings {
		return LayerTreeSettings()
	}

	public var debugState: LayerTreeDebugState {
		return LayerTreeDebugState()
	}

	public var rendererCapabilities: RendererCapabilities {
		return RendererCapabilities()
	}

	public var contextProvider: ContextProvider? {
		return nil
	}

	public var outputSurface: OutputSurface? {
		return nil
	}

	public var resourceProvider: ResourceProvider {
		return ResourceProvider()
	}

	public var tileManager: TileManager {
		return TileManager()
	}

	public var frameRateCounter: FrameRateCounter {
		return FrameRateCounter()
	}

	public var memoryHistory: MemoryHistory {
		return MemoryHistory()
	}

	public var deviceViewportSize: IntSize {
		return IntSize()
	}

	public var isActiveTree: Bool {
		return false
	}

	public var isPendingTree: Bool {
		return false
	}

	public var isRecycleTree: Bool {
		return false
	}

	public var isSyncTree: Bool {
		return false
	}

	public var pinchGestureActive: Bool {
		return false
	}

	public var videoFrameControllerClient: VideoFrameControllerClient? {
		return nil
	}

	public var currentBeginFrameArgs: BeginFrameArgs {
		return BeginFrameArgs()
	} 

	public var currentBeginFrameInterval: TimeDelta {
		return TimeDelta()
	}

	public var deviceViewport: IntRect {
		return IntRect()
	}

	public var drawViewportSize: IntSize {
		return IntSize()
	}

	public var viewportRectForTilePriority: IntRect {
		return IntRect()
	} 

	public var useGPURasterization: Bool {
		return false
	}

	public var rootLayer: Layer? {
		
		get {
			return nil
		}
		
		set {

		}

	}

	public var propertyTrees: PropertyTrees? {
		
		get {
			return nil
		}
		
		set {

		}

	}

	public var hudLayer: HeadsUpDisplayLayer? {
   	
   		get {
   			return nil
   		}
   		
   		set {

   		}

   	}

   	public var innerViewportScrollLayer: Layer? {
   		return nil
  	}

  	public var outerViewportScrollLayer: Layer? {
  		return nil
  	}

  	public var totalScrollOffset: ScrollOffset {
  		return ScrollOffset()
  	}

  	public var totalMaxScrollOffset: ScrollOffset {
  		return ScrollOffset()
  	}

  	public var innerViewportContainerLayer: Layer? {
  		return nil
  	}

 	public var outerViewportContainerLayer: Layer? {
 		return nil
 	}

  	public var currentlyScrollingLayer: Layer? {
  		
  		get {
  			return nil
  		}

  		set {

  		}

  	}

    public var overscrollElasticityLayer: Layer? {
    	return nil
    } 

  	public var pageScaleLayer: Layer? {
  		return nil
  	}

   	public var backgroundColor: Color {
   		
   		get {
   			return Color()
   		}
   		
   		set {

   		}
   	}

  	public var hasTransparentBackground: Bool {
  		
  		get {
  			return false
  		}

  		set {

  		}
  	}
    
    public var currentPageScaleFactor: Float {
    	return 0.0
    }

  	public var minPageScaleFactor: Float {
  		return 0.0
  	}

  	public var maxPageScaleFactor: Float { 
  		return 0.0
  	}

  	public var pageScaleDelta: Float { 
  		return 0.0
  	}

  	public var pageScaleFactor: ScaleGroup? {
  		return nil
  	}

  	public var deviceScaleFactor: Float {
  		
  		get {
  			return 0.0
  		}
  		
  		set {

  		}	
  	}  

  	public var paintedDeviceScaleFactor: Float {
    	
    	get {
    		return 0.0
    	}

    	set {

    	}

  	}

  	public var elasticOverscroll: SyncedElasticOverscroll? {
    	return nil
  	}

  	public var topControlsShownratio: SyncedTopControls? {
 		return nil
  	}

    public var needsUpdateDrawProperties: Bool {
 
    	get {
    		return false
    	}

    	set {

    	}

  	}
  
  	public var pictureLayers: [PictureLayer] {
    	return []
  	}

    public var layersWithCopyOutputRequest: [Layer] {
    	return []
    }

  	public var currentRenderSurfaceListId: Int {
    	return 0
  	}

  	public var topControlsShrinkBlinkSize: Bool {

    	get {
    		return false
    	}
    
    	set {

    	}
  	}

  	public var currentTopControlsShownRatio: Float {
  
  		get {
  			return 0.0
  		}
  
  		set {

  		}

  	}
  
  	public var topControlsHeight: Float {
  	
  		get {
  			return 0.0
  		}

  		set {

  		}
  	}

  	public var needsFullTreeSync: Bool {
  		
  		get {
  			return false
  		}

  		set {

  		}

  	}

  	public var sourceFrameNumber: Int {
  		
  		get {
  			return 0
  		}

  		set {

  		}
  	}

  	public var hasEverBeenDrawn: Bool { 
  		
  		get {
  			return false
  		}

  		set {

  		}
  	}

  	public var createLowResTiling: Bool {
  		return false
  	}

  	public var requiresHighResToDraw: Bool {
  		return false	
  	}
 
  	public var smoothnessTakesPriority: Bool {
  		return false
  	}

  	public var gpuRasterizationStatus: GpuRasterizationStatus {
  		return GpuRasterizationStatus()
  	}

  	public var taskRunnerProvider: TaskRunnerProvider? {
  		return nil
  	}

  	public var layerCount: Int {
  		return 0
  	}

  	public var renderSurfaceLayerList: LayerList {
  		return LayerList()
  	}

	public var unoccludedScreenSpaceRegion: Graphics.Region {
		return Graphics.Region()
	}

	public var scrollableSize: FloatSize {
		return FloatSize()
	}

	public var scrollableViewportSize: FloatSize {
		return FloatSize()
	}

	public var rootScrollLayerDeviceViewportBounds: IntRect {
		return IntRect()
	}

	// public var animationRegistrar: AnimationRegistrar? {
	// 	return nil
	// }

	public var viewportSelection: ViewportSelection {
		return ViewportSelection()
	}

	public var gatherFrameTimingRequestIds: [Int64] {
		return []
	}

  	//var reference: LayerTreeRef

  	public func shutdown() {

  	}
  
  	public func releaseResources() {

  	}
  
  	public func recreateResources() {

  	}

  	public func setUIResourceRequestQueue(queue: UIResourceRequestQueue) {

  	}

  	public func findActiveTreeLayerById(id: Int) -> Layer? {
  		return nil
  	}

  	public func findPendingTreeLayerById(id: Int) -> Layer? {
  		return nil
  	}

  	public func setNeedsCommit() {

  	}
  	
  	public func createScrollbarAnimationController(scrollLayerId: Int) -> ScrollbarAnimationController {
  		return ScrollbarAnimationController()
  	}
  	
  	public func didAnimateScrollOffset() {

  	}
  	
  	public func inputScrollAnimationFinished() {

  	}
 
	public func setNeedsRedraw() {

	}

	public func getAllPrioritizedTilesForTracing() -> [PrioritizedTile] {
		return []
	}

	public func detachLayerTree() -> Layer? {
		return nil
	}

	public func updatePropertyTreesForBoundsDelta() {

	}

	public func pushPropertiesTo(tree: LayerTree) {

	}

	public func clearCurrentlyScrollingLayer() {

	}

	public func setViewportLayersFromIds(
		overscrollElasticityLayer: Int,
		pageScaleLayerId: Int,
	    innerViewportScrollLayerId: Int,
	    outerViewportScrollLayerId: Int) {

	}
	
	public func clearViewportLayers() {

	}

	public func applySentScrollAndScaleDeltasFromAbortedCommit() {

	}

	public func updatePropertyTreeScrollingAndAnimationFromMainThread() {

	}

	public func setPageScaleOnActiveTree(activePageScale: Float) {

	}

	public func pushPageScaleFromMainThread(
		pageScaleFactor: Float,
		minPageScaleFactor: Float,
	    maxPageScaleFactor: Float) {

	}

	public func updateDrawProperties(updateLCDText: Bool) -> Bool {
		return false
	}

	public func forceRedrawNextActivation() {

	}

	public func getLayerBy(id: Int) -> Layer? {
		return nil
	}

	public func registerLayer(layer: Layer) {

	}

	public func unregisterLayer(layer: Layer) {

	}

	public func didBecomeActive() {

	}

	public func viewportSizeInvalid() -> Bool {
		return false
	}

	public func setViewportSizeInvalid() {

	}
	
	public func resetViewportSizeInvalid() {

	}

	public func distributeRootScrollOffset(rootOffset: ScrollOffset) -> Bool {
		return false
	}

	public func applyScroll(layer: Layer, scrollState: inout ScrollState) {

	}

	public func queueSwapPromise(swapPromise: SwapPromise) {

	}

	public func queuePinnedSwapPromise(swapPromise: SwapPromise) {

	}

	public func passSwapPromises(newSwapPromise: SwapPromise) {

	}
	
	public func finishSwapPromises(metadata: CompositorFrameMetadata) {

	}
	
	public func breakSwapPromises(reason: DidNotSwapReason) {

	}

	public func didModifyTilePriorities() {

	}

	public func resourceIdForUIResource(uid: UIResourceId) -> ResourceId {
		return 0
	}
	
	public func processUIResourceRequestQueue() {

	}

	public func isUIResourceOpaque(uid: UIResourceId) -> Bool {
		return false
	}

	public func registerPictureLayerImpl(layer: PictureLayer) {

	}
	
	public func unregisterPictureLayerImpl(layer: PictureLayer) {

	}

	public func registerScrollbar(scrollbarLayer: ScrollbarLayer) {

	}
	
	public func unregisterScrollbar(scrollbarLayer: ScrollbarLayer) {

	}
	
	public func scrollbarsFor(scrollLayerId: Int) -> ScrollbarSet? {
		return nil
	}

	public func registerScrollLayer(layer: Layer) {

	}
	
	public func unregisterScrollLayer(layer: Layer) {

	}

	public func addLayerWithCopyOutputRequest(layer: Layer) {

	}
	
	public func removeLayerWithCopyOutputRequest(layer: Layer) {

	}

	public func findFirstScrollingLayerThatIsHitByPoint(screenSpacePoint: FloatPoint) -> Layer? {
		return nil
	}

	public func findLayerThatIsHitByPoint(screenSpacePoint: FloatPoint) -> Layer? {
		return nil
	}

	public func findLayerWithWheelHandlerThatIsHitByPoint(screenSpacePoint: FloatPoint) -> Layer? {
		return nil
	}

	public func findLayerThatIsHitByPointInTouchHandlerRegion(screenSpacePoint: FloatPoint) -> Layer? {
		return nil
	}

	public func RegisterSelection(selection: LayerSelection) {

	}

	public func PushTopControlsFromMainThread(topControlsShownRatio: Float) {

	}

	public func setPendingPageScaleAnimation(pendingAnimation: PendingPageScaleAnimation) {

	}
	
	public func takePendingPageScaleAnimation() -> PendingPageScaleAnimation {
		return PendingPageScaleAnimation()
	}

	public func didUpdateScrollState(layerId: Int) {

	}

	public func isAnimatingFilterProperty(layer: Layer) -> Bool {
		return false
	}
	
	public func isAnimatingOpacityProperty(layer: Layer) -> Bool {
		return false
	}
	
	public func isAnimatingTransformProperty(layer: Layer) -> Bool {
		return false
	}

	public func hasPotentiallyRunningFilterAnimation(layer: Layer) -> Bool {
		return false
	}
	
	public func hasPotentiallyRunningOpacityAnimation(layer: Layer) -> Bool {
		return false
	}
	
	public func hasPotentiallyRunningTransformAnimation(layer: Layer) -> Bool {
		return false
	}

	public func hasAnyAnimationTargetingProperty(layer: Layer, property: Int) -> Bool {
		return false
	}

	public func filterIsAnimatingOnImplOnly(layer: Layer) -> Bool {
		return false
	}
	
	public func opacityIsAnimatingOnImplOnly(layer: Layer) -> Bool {
		return false
	}

	public func transformIsAnimatingOnImplOnly(layer: Layer) -> Bool {
		return false
	}

	public func hasOnlyTranslationTransforms(layer: Layer) -> Bool {
		return false
	}

	public func maximumTargetScale(layer: Layer) -> Float? {
		return nil
	}

	public func animationStartScale(layer: Layer) -> Float? {
		return nil
	}

	public func hasFilterAnimationThatInflatesBounds(layer: Layer) -> Bool {
		return false
	}
	
	public func hasTransformAnimationThatInflatesBounds(layer: Layer) -> Bool {
		return false
	}
	
	public func hasAnimationThatInflatesBounds(layer: Layer) -> Bool {
		return false
	}

	public func filterAnimationBoundsForBox(layer: Layer, box: FloatBox) -> FloatBox? {
		return nil
	}

	public func transformAnimationBoundsForBox(layer: Layer, box: FloatBox) -> FloatBox? {
		return nil
	}

}