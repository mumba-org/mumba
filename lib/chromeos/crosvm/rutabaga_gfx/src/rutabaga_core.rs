// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! rutabaga_core: Cross-platform, Rust-based, Wayland and Vulkan centric GPU virtualization.

use std::collections::BTreeMap as Map;
use std::sync::Arc;

use base::{ExternalMapping, SafeDescriptor};
use data_model::VolatileSlice;

use crate::cross_domain::CrossDomain;

#[cfg(feature = "gfxstream")]
use crate::gfxstream::Gfxstream;

use crate::rutabaga_2d::Rutabaga2D;
use crate::rutabaga_utils::*;

#[cfg(feature = "virgl_renderer")]
use crate::virgl_renderer::VirglRenderer;

/// Information required for 2D functionality.
pub struct Rutabaga2DInfo {
    pub width: u32,
    pub height: u32,
    pub host_mem: Vec<u8>,
}

/// A Rutabaga resource, supporting 2D and 3D rutabaga features.  Assumes a single-threaded library.
pub struct RutabagaResource {
    pub resource_id: u32,
    pub handle: Option<Arc<RutabagaHandle>>,
    pub blob: bool,
    pub blob_mem: u32,
    pub blob_flags: u32,
    pub map_info: Option<u32>,
    pub info_2d: Option<Rutabaga2DInfo>,
    pub info_3d: Option<Resource3DInfo>,
    pub vulkan_info: Option<VulkanInfo>,
    pub backing_iovecs: Option<Vec<RutabagaIovec>>,
}

/// A RutabagaComponent is a building block of the Virtual Graphics Interface (VGI).  Each component
/// on it's own is sufficient to virtualize graphics on many Google products.  These components wrap
/// libraries like gfxstream or virglrenderer, and Rutabaga's own 2D and cross-domain prototype
/// functionality.
///
/// Most methods return a `RutabagaResult` that indicate the success, failure, or requested data for
/// the given command.
pub trait RutabagaComponent {
    /// Implementations should return the version and size of the given capset_id.  (0, 0) is
    /// returned by default.
    fn get_capset_info(&self, _capset_id: u32) -> (u32, u32) {
        (0, 0)
    }

    /// Implementations should return the capabilites of given a `capset_id` and `version`.  A
    /// zero-sized array is returned by default.
    fn get_capset(&self, _capset_id: u32, _version: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Implementations should set their internal context to be the reserved context 0.
    fn force_ctx_0(&self) {}

    /// Implementations must create a fence that represents the completion of prior work.  This is
    /// required for synchronization with the guest kernel.
    fn create_fence(&mut self, _fence: RutabagaFence) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Used only by VirglRenderer to poll when its poll_descriptor is signaled.
    fn poll(&self) {}

    /// Used only by VirglRenderer to return a poll_descriptor that is signaled when a poll() is
    /// necessary.
    fn poll_descriptor(&self) -> Option<SafeDescriptor> {
        None
    }

    /// Implementations must create a resource with the given metadata.  For 2D rutabaga components,
    /// this a system memory allocation.  For 3D components, this is typically a GL texture or
    /// buffer.  Vulkan components should use blob resources instead.
    fn create_3d(
        &self,
        _resource_id: u32,
        _resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must attach `vecs` to the resource.
    fn attach_backing(
        &self,
        _resource_id: u32,
        _vecs: &mut Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        Ok(())
    }

    /// Implementations must detach `vecs` from the resource.
    fn detach_backing(&self, _resource_id: u32) {}

    /// Implementations must release the guest kernel reference on the resource.
    fn unref_resource(&self, _resource_id: u32) {}

    /// Implementations must perform the transfer write operation.  For 2D rutabaga components, this
    /// done via memcpy().  For 3D components, this is typically done via glTexSubImage(..).
    fn transfer_write(
        &self,
        _ctx_id: u32,
        _resource: &mut RutabagaResource,
        _transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must perform the transfer read operation.  For 2D rutabaga components, this
    /// done via memcpy().  For 3D components, this is typically done via glReadPixels(..).
    fn transfer_read(
        &self,
        _ctx_id: u32,
        _resource: &mut RutabagaResource,
        _transfer: Transfer3D,
        _buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must create a blob resource on success.  The memory parameters, size, and
    /// usage of the blob resource is given by `resource_create_blob`.
    fn create_blob(
        &mut self,
        _ctx_id: u32,
        _resource_id: u32,
        _resource_create_blob: ResourceCreateBlob,
        _iovec_opt: Option<Vec<RutabagaIovec>>,
        _handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must map the blob resource on success.  This is typically done by
    /// glMapBufferRange(...) or vkMapMemory.
    fn map(&self, _resource_id: u32) -> RutabagaResult<ExternalMapping> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return a RutabagaHandle of the fence on success.
    fn export_fence(&self, _fence_id: u32) -> RutabagaResult<RutabagaHandle> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must create a context for submitting commands.  The command stream of the
    /// context is determined by `context_init`.  For virgl contexts, it is a Gallium/TGSI command
    /// stream.  For gfxstream contexts, it's an autogenerated Vulkan or GLES streams.
    fn create_context(
        &self,
        _ctx_id: u32,
        _context_init: u32,
        _fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        Err(RutabagaError::Unsupported)
    }
}

pub trait RutabagaContext {
    /// Implementations must return a RutabagaResource given the `resource_create_blob` parameters.
    fn context_create_blob(
        &mut self,
        _resource_id: u32,
        _resource_create_blob: ResourceCreateBlob,
        _handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must handle the context-specific command stream.
    fn submit_cmd(&mut self, _commands: &mut [u8]) -> RutabagaResult<()>;

    /// Implementations may use `resource` in this context's command stream.
    fn attach(&mut self, _resource: &mut RutabagaResource);

    /// Implementations must stop using `resource` in this context's command stream.
    fn detach(&mut self, _resource: &RutabagaResource);

    /// Implementations must create a fence on specified `ring_idx` in `fence`.  This
    /// allows for multiple synchronizations timelines per RutabagaContext.
    fn context_create_fence(&mut self, _fence: RutabagaFence) -> RutabagaResult<()> {
        Err(RutabagaError::Unsupported)
    }

    /// Implementations must return the component type associated with the context.
    fn component_type(&self) -> RutabagaComponentType;
}

#[derive(Copy, Clone)]
struct RutabagaCapsetInfo {
    pub capset_id: u32,
    pub component: RutabagaComponentType,
}

/// The global libary handle used to query capability sets, create resources and contexts.
///
/// Currently, Rutabaga only supports one default component.  Many components running at the
/// same time is a stretch goal of Rutabaga GFX.
///
/// Not thread-safe, but can be made so easily.  Making non-Rutabaga, C/C++ components
/// thread-safe is more difficult.
pub struct Rutabaga {
    resources: Map<u32, RutabagaResource>,
    contexts: Map<u32, Box<dyn RutabagaContext>>,
    // Declare components after resources and contexts such that it is dropped last.
    components: Map<RutabagaComponentType, Box<dyn RutabagaComponent>>,
    default_component: RutabagaComponentType,
    capset_info: Vec<RutabagaCapsetInfo>,
    fence_handler: RutabagaFenceHandler,
}

impl Rutabaga {
    fn capset_id_to_component_type(&self, capset_id: u32) -> RutabagaResult<RutabagaComponentType> {
        let component = self
            .capset_info
            .iter()
            .find(|capset_info| capset_info.capset_id == capset_id)
            .ok_or(RutabagaError::InvalidCapset)?
            .component;

        Ok(component)
    }

    fn capset_index_to_component_info(&self, index: u32) -> RutabagaResult<RutabagaCapsetInfo> {
        let idx = index as usize;
        if idx >= self.capset_info.len() {
            return Err(RutabagaError::InvalidCapset);
        }

        Ok(self.capset_info[idx])
    }

    /// Gets the version and size for the capabilty set `index`.
    pub fn get_capset_info(&self, index: u32) -> RutabagaResult<(u32, u32, u32)> {
        let capset_info = self.capset_index_to_component_info(index)?;

        let component = self
            .components
            .get(&capset_info.component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let (capset_version, capset_size) = component.get_capset_info(capset_info.capset_id);
        Ok((capset_info.capset_id, capset_version, capset_size))
    }

    /// Gets the capability set for the `capset_id` and `version`.
    /// Each capability set is associated with a context type, which is associated
    /// with a rutabaga component.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> RutabagaResult<Vec<u8>> {
        // The default workaround is just until context types are fully supported in all
        // Google kernels.
        let component_type = self
            .capset_id_to_component_type(capset_id)
            .unwrap_or(self.default_component);

        let component = self
            .components
            .get(&component_type)
            .ok_or(RutabagaError::InvalidComponent)?;

        Ok(component.get_capset(capset_id, version))
    }

    /// Forces context zero for the default rutabaga component.
    pub fn force_ctx_0(&self) {
        if let Some(component) = self.components.get(&self.default_component) {
            component.force_ctx_0();
        }
    }

    /// Creates a fence with the given `fence`.
    /// If the flags include RUTABAGA_FLAG_INFO_RING_IDX, then the fence is created on a
    /// specific timeline on the specific context.
    pub fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        if fence.flags & RUTABAGA_FLAG_INFO_RING_IDX != 0 {
            let ctx = self
                .contexts
                .get_mut(&fence.ctx_id)
                .ok_or(RutabagaError::InvalidContextId)?;

            ctx.context_create_fence(fence)?;
        } else {
            let component = self
                .components
                .get_mut(&self.default_component)
                .ok_or(RutabagaError::InvalidComponent)?;

            component.create_fence(fence)?;
        }

        Ok(())
    }

    /// Polls the default rutabaga component. In practice, only called if the default component is
    /// virglrenderer.
    pub fn poll(&self) {
        if let Some(component) = self.components.get(&self.default_component) {
            component.poll();
        }
    }

    /// Returns a pollable descriptor for the default rutabaga component. In practice, it is only
    /// not None if the default component is virglrenderer.
    pub fn poll_descriptor(&self) -> Option<SafeDescriptor> {
        let component = self.components.get(&self.default_component).or(None)?;
        component.poll_descriptor()
    }

    /// Creates a resource with the `resource_create_3d` metadata.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        if self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        let resource = component.create_3d(resource_id, resource_create_3d)?;
        self.resources.insert(resource_id, resource);
        Ok(())
    }

    /// Attaches `vecs` to the resource.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mut vecs: Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let mut resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.attach_backing(resource_id, &mut vecs)?;
        resource.backing_iovecs = Some(vecs);
        Ok(())
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.detach_backing(resource_id);
        resource.backing_iovecs = None;
        Ok(())
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> RutabagaResult<()> {
        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        self.resources
            .remove(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.unref_resource(resource_id);
        Ok(())
    }

    /// For HOST3D_GUEST resources, copies from the attached iovecs to the host resource.  For
    /// HOST3D resources, this may flush caches, though this feature is unused by guest userspace.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.transfer_write(ctx_id, resource, transfer)
    }

    /// 1) If specified, copies to `buf` from the host resource.
    /// 2) Otherwise, for HOST3D_GUEST resources, copies to the attached iovecs from the host
    ///    resource.  For HOST3D resources, this may invalidate caches, though this feature is
    ///    unused by guest userspace.
    pub fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> RutabagaResult<()> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        component.transfer_read(ctx_id, resource, transfer, buf)
    }

    /// Creates a blob resource with the `ctx_id` and `resource_create_blob` metadata.
    /// Associates `iovecs` with the resource, if there are any.  Associates externally
    /// created `handle` with the resource, if there is any.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        iovecs: Option<Vec<RutabagaIovec>>,
        handle: Option<RutabagaHandle>,
    ) -> RutabagaResult<()> {
        if self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        let component = self
            .components
            .get_mut(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        let mut context = None;
        // For the cross-domain context, we'll need to create the blob resource via a home-grown
        // rutabaga context rather than one from an external C/C++ component.  Use `ctx_id` and
        // the component type if it happens to be a cross-domain context.
        if ctx_id > 0 {
            let ctx = self
                .contexts
                .get_mut(&ctx_id)
                .ok_or(RutabagaError::InvalidContextId)?;

            if ctx.component_type() == RutabagaComponentType::CrossDomain {
                context = Some(ctx);
            }
        }

        let resource = match context {
            Some(ctx) => ctx.context_create_blob(resource_id, resource_create_blob, handle)?,
            None => {
                component.create_blob(ctx_id, resource_id, resource_create_blob, iovecs, handle)?
            }
        };

        self.resources.insert(resource_id, resource);
        Ok(())
    }

    /// Returns a memory mapping of the blob resource.
    pub fn map(&self, resource_id: u32) -> RutabagaResult<ExternalMapping> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        if !self.resources.contains_key(&resource_id) {
            return Err(RutabagaError::InvalidResourceId);
        }

        component.map(resource_id)
    }

    /// Returns the `map_info` of the blob resource. The valid values for `map_info`
    /// are defined in the virtio-gpu spec.
    pub fn map_info(&self, resource_id: u32) -> RutabagaResult<u32> {
        let resource = self
            .resources
            .get(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        resource
            .map_info
            .ok_or(RutabagaError::SpecViolation("no map info available"))
    }

    /// Returns the `vulkan_info` of the blob resource, which consists of the physical device
    /// index and memory index associated with the resource.
    pub fn vulkan_info(&self, resource_id: u32) -> RutabagaResult<VulkanInfo> {
        let resource = self
            .resources
            .get(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        resource.vulkan_info.ok_or(RutabagaError::InvalidVulkanInfo)
    }

    /// Returns the 3D info associated with the resource, if any.
    pub fn query(&self, resource_id: u32) -> RutabagaResult<Resource3DInfo> {
        let resource = self
            .resources
            .get(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        resource
            .info_3d
            .ok_or(RutabagaError::SpecViolation("no 3d info available"))
    }

    /// Exports a blob resource.  See virtio-gpu spec for blob flag use flags.
    pub fn export_blob(&mut self, resource_id: u32) -> RutabagaResult<RutabagaHandle> {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        // We can inspect blob flags only once guest minigbm is fully transitioned to blob.
        let share_mask = RUTABAGA_BLOB_FLAG_USE_SHAREABLE | RUTABAGA_BLOB_FLAG_USE_CROSS_DEVICE;
        let shareable = (resource.blob_flags & share_mask != 0) || !resource.blob;

        let opt = resource.handle.take();

        match (opt, shareable) {
            (Some(handle), true) => {
                let clone = handle.try_clone()?;
                resource.handle = Some(handle);
                Ok(clone)
            }
            (Some(handle), false) => {
                // Exactly one strong reference in this case.
                let hnd =
                    Arc::try_unwrap(handle).map_err(|_| RutabagaError::InvalidRutabagaHandle)?;
                Ok(hnd)
            }
            _ => Err(RutabagaError::InvalidRutabagaHandle),
        }
    }

    /// Exports the given fence for import into other processes.
    pub fn export_fence(&self, fence_id: u32) -> RutabagaResult<RutabagaHandle> {
        let component = self
            .components
            .get(&self.default_component)
            .ok_or(RutabagaError::InvalidComponent)?;

        component.export_fence(fence_id)
    }

    /// Creates a context with the given `ctx_id` and `context_init` variable.
    /// `context_init` is used to determine which rutabaga component creates the context.
    pub fn create_context(&mut self, ctx_id: u32, context_init: u32) -> RutabagaResult<()> {
        // The default workaround is just until context types are fully supported in all
        // Google kernels.
        let capset_id = context_init & RUTABAGA_CONTEXT_INIT_CAPSET_ID_MASK;
        let component_type = self
            .capset_id_to_component_type(capset_id)
            .unwrap_or(self.default_component);

        let component = self
            .components
            .get_mut(&component_type)
            .ok_or(RutabagaError::InvalidComponent)?;

        if self.contexts.contains_key(&ctx_id) {
            return Err(RutabagaError::InvalidContextId);
        }

        let ctx = component.create_context(ctx_id, context_init, self.fence_handler.clone())?;
        self.contexts.insert(ctx_id, ctx);
        Ok(())
    }

    /// Destroys the context given by `ctx_id`.
    pub fn destroy_context(&mut self, ctx_id: u32) -> RutabagaResult<()> {
        self.contexts
            .remove(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;
        Ok(())
    }

    /// Attaches the resource given by `resource_id` to the context given by `ctx_id`.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        ctx.attach(resource);
        Ok(())
    }

    /// Detaches the resource given by `resource_id` from the context given by `ctx_id`.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(RutabagaError::InvalidResourceId)?;

        ctx.detach(resource);
        Ok(())
    }

    /// Submits `commands` to the context given by `ctx_id`.
    pub fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> RutabagaResult<()> {
        let ctx = self
            .contexts
            .get_mut(&ctx_id)
            .ok_or(RutabagaError::InvalidContextId)?;

        ctx.submit_cmd(commands)
    }
}

/// Rutabaga Builder, following the Rust builder pattern.
pub struct RutabagaBuilder {
    display_width: Option<u32>,
    display_height: Option<u32>,
    default_component: RutabagaComponentType,
    virglrenderer_flags: Option<VirglRendererFlags>,
    gfxstream_flags: Option<GfxstreamFlags>,
    channels: Option<Vec<RutabagaChannel>>,
}

impl RutabagaBuilder {
    /// Create new a RutabagaBuilder.
    pub fn new(default_component: RutabagaComponentType) -> RutabagaBuilder {
        RutabagaBuilder {
            display_width: None,
            display_height: None,
            default_component,
            virglrenderer_flags: None,
            gfxstream_flags: None,
            channels: None,
        }
    }

    /// Set display width for the RutabagaBuilder
    pub fn set_display_width(mut self, display_width: u32) -> RutabagaBuilder {
        self.display_width = Some(display_width);
        self
    }

    /// Set display height for the RutabagaBuilder
    pub fn set_display_height(mut self, display_height: u32) -> RutabagaBuilder {
        self.display_height = Some(display_height);
        self
    }

    /// Set virglrenderer flags for the RutabagaBuilder
    pub fn set_virglrenderer_flags(
        mut self,
        virglrenderer_flags: VirglRendererFlags,
    ) -> RutabagaBuilder {
        self.virglrenderer_flags = Some(virglrenderer_flags);
        self
    }

    /// Set gfxstream flags for the RutabagaBuilder
    pub fn set_gfxstream_flags(mut self, gfxstream_flags: GfxstreamFlags) -> RutabagaBuilder {
        self.gfxstream_flags = Some(gfxstream_flags);
        self
    }

    /// Set rutabaga channels for the RutabagaBuilder
    pub fn set_rutabaga_channels(
        mut self,
        channels: Option<Vec<RutabagaChannel>>,
    ) -> RutabagaBuilder {
        self.channels = channels;
        self
    }

    /// Builds Rutabaga and returns a handle to it.
    ///
    /// This should be only called once per every virtual machine instance.  Rutabaga tries to
    /// intialize all 3D components which have been built. In 2D mode, only the 2D component is
    /// initialized.
    pub fn build(
        self,
        fence_handler: RutabagaFenceHandler,
        render_server_fd: Option<SafeDescriptor>,
    ) -> RutabagaResult<Rutabaga> {
        let mut rutabaga_components: Map<RutabagaComponentType, Box<dyn RutabagaComponent>> =
            Default::default();

        let mut rutabaga_capsets: Vec<RutabagaCapsetInfo> = Default::default();

        // Make sure that disabled components are not used as default.
        #[cfg(not(feature = "virgl_renderer"))]
        if self.default_component == RutabagaComponentType::VirglRenderer {
            return Err(RutabagaError::InvalidRutabagaBuild(
                "virgl renderer feature not enabled",
            ));
        }
        #[cfg(not(feature = "gfxstream"))]
        if self.default_component == RutabagaComponentType::Gfxstream {
            return Err(RutabagaError::InvalidRutabagaBuild(
                "gfxstream feature not enabled",
            ));
        }

        #[cfg(not(feature = "virgl_renderer_next"))]
        if render_server_fd.is_some() {
            return Err(RutabagaError::InvalidRutabagaBuild(
                "render server FD is not supported with virgl_renderer_next feature",
            ));
        }

        if self.default_component == RutabagaComponentType::Rutabaga2D {
            let rutabaga_2d = Rutabaga2D::init(fence_handler.clone())?;
            rutabaga_components.insert(RutabagaComponentType::Rutabaga2D, rutabaga_2d);
        } else {
            #[cfg(feature = "virgl_renderer")]
            if self.default_component == RutabagaComponentType::VirglRenderer {
                let virglrenderer_flags =
                    self.virglrenderer_flags
                        .ok_or(RutabagaError::InvalidRutabagaBuild(
                            "missing virgl renderer flags",
                        ))?;

                let virgl = VirglRenderer::init(
                    virglrenderer_flags,
                    fence_handler.clone(),
                    render_server_fd,
                )?;
                rutabaga_components.insert(RutabagaComponentType::VirglRenderer, virgl);

                rutabaga_capsets.push(RutabagaCapsetInfo {
                    capset_id: RUTABAGA_CAPSET_VIRGL,
                    component: RutabagaComponentType::VirglRenderer,
                });
                rutabaga_capsets.push(RutabagaCapsetInfo {
                    capset_id: RUTABAGA_CAPSET_VIRGL2,
                    component: RutabagaComponentType::VirglRenderer,
                });
                rutabaga_capsets.push(RutabagaCapsetInfo {
                    capset_id: RUTABAGA_CAPSET_VENUS,
                    component: RutabagaComponentType::VirglRenderer,
                });
            }

            #[cfg(feature = "gfxstream")]
            if self.default_component == RutabagaComponentType::Gfxstream {
                let display_width = self
                    .display_width
                    .ok_or(RutabagaError::InvalidRutabagaBuild("missing display width"))?;
                let display_height =
                    self.display_height
                        .ok_or(RutabagaError::InvalidRutabagaBuild(
                            "missing display height",
                        ))?;

                let gfxstream_flags =
                    self.gfxstream_flags
                        .ok_or(RutabagaError::InvalidRutabagaBuild(
                            "missing gfxstream flags",
                        ))?;

                let gfxstream = Gfxstream::init(
                    display_width,
                    display_height,
                    gfxstream_flags,
                    fence_handler.clone(),
                )?;
                rutabaga_components.insert(RutabagaComponentType::Gfxstream, gfxstream);

                rutabaga_capsets.push(RutabagaCapsetInfo {
                    capset_id: RUTABAGA_CAPSET_GFXSTREAM,
                    component: RutabagaComponentType::Gfxstream,
                });
            }

            let cross_domain = CrossDomain::init(self.channels)?;
            rutabaga_components.insert(RutabagaComponentType::CrossDomain, cross_domain);

            rutabaga_capsets.push(RutabagaCapsetInfo {
                capset_id: RUTABAGA_CAPSET_CROSS_DOMAIN,
                component: RutabagaComponentType::CrossDomain,
            });
        }

        Ok(Rutabaga {
            resources: Default::default(),
            contexts: Default::default(),
            components: rutabaga_components,
            default_component: self.default_component,
            capset_info: rutabaga_capsets,
            fence_handler,
        })
    }
}
