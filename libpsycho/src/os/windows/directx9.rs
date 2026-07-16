//! Direct3D 9 wrappers used by injected rendering modules.
//!
//! Host applications own their renderer and `IDirect3DDevice9`. Use `Device9Ref`
//! for borrowed device pointers so Rust does not call `Release` on objects it
//! does not own. Resource wrappers in this module are owned COM references.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{NonNull, null, null_mut};
use core::slice;
use std::ffi::CString;
use std::sync::OnceLock;

use thiserror::Error;

use windows::Win32::Foundation::{E_POINTER, HANDLE, RECT};
use windows::Win32::Graphics::Direct3D::ID3DBlob;
use windows::Win32::Graphics::Direct3D9::{
    D3DADAPTER_DEFAULT, D3DBACKBUFFER_TYPE, D3DBACKBUFFER_TYPE_MONO, D3DCLEAR_ZBUFFER, D3DDEVTYPE,
    D3DDEVTYPE_HAL, D3DDISPLAYMODE, D3DLOCKED_RECT, D3DPOOL, D3DPRESENT_PARAMETERS,
    D3DPRIMITIVETYPE, D3DRENDERSTATETYPE, D3DRESOURCETYPE, D3DRTYPE_SURFACE, D3DRTYPE_TEXTURE,
    D3DSAMPLERSTATETYPE, D3DSTATEBLOCKTYPE, D3DTEXTUREFILTERTYPE, D3DTEXTURESTAGESTATETYPE,
    D3DUSAGE_DEPTHSTENCIL, D3DUSAGE_RENDERTARGET, D3DVERTEXELEMENT9, IDirect3D9,
    IDirect3DBaseTexture9, IDirect3DDevice9, IDirect3DPixelShader9, IDirect3DStateBlock9,
    IDirect3DSurface9, IDirect3DTexture9, IDirect3DVertexBuffer9, IDirect3DVertexShader9,
};
pub use windows::Win32::Graphics::Direct3D9::{
    D3DCULL, D3DCULL_CCW, D3DCULL_CW, D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DFORMAT, D3DFVF_DIFFUSE,
    D3DFVF_TEX1, D3DFVF_XYZ, D3DFVF_XYZRHW, D3DPOOL_DEFAULT, D3DPOOL_MANAGED, D3DPT_POINTLIST,
    D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE,
    D3DRS_CULLMODE, D3DRS_POINTSIZE, D3DRS_ZENABLE, D3DRS_ZFUNC, D3DRS_ZWRITEENABLE,
    D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER,
    D3DSBT_ALL, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE,
    D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1,
    D3DTSS_COLOROP, D3DVIEWPORT9,
};
pub use windows::core::Error as Direct3DError;
use windows::core::{HRESULT, Interface, InterfaceRef, PCSTR, Result as WindowsResult};

use Direct3DError as WindowsError;

use crate::ffi::fnptr::FnPtr;
use crate::os::windows::winapi::{get_proc_address, load_library_a};

/// Byte offset of `IDirect3DDevice9::TestCooperativeLevel` in the device vtable.
pub const DEVICE9_VTBL_TEST_COOPERATIVE_LEVEL: usize = 0x0c;
/// Byte offset of `IDirect3DDevice9::GetAvailableTextureMem` in the device vtable.
pub const DEVICE9_VTBL_GET_AVAILABLE_TEXTURE_MEM: usize = 0x10;
/// Byte offset of `IDirect3DDevice9::EvictManagedResources` in the device vtable.
pub const DEVICE9_VTBL_EVICT_MANAGED_RESOURCES: usize = 0x14;
/// Byte offset of `IDirect3DDevice9::Reset` in the device vtable.
pub const DEVICE9_VTBL_RESET: usize = 0x40;
/// Byte offset of `IDirect3DDevice9::Present` in the device vtable.
pub const DEVICE9_VTBL_PRESENT: usize = 0x44;
/// Byte offset of `IDirect3DDevice9::GetBackBuffer` in the device vtable.
pub const DEVICE9_VTBL_GET_BACK_BUFFER: usize = 0x48;
/// Byte offset of `IDirect3DDevice9::CreateTexture` in the device vtable.
pub const DEVICE9_VTBL_CREATE_TEXTURE: usize = 0x5c;
/// Byte offset of `IDirect3DDevice9::CreateDepthStencilSurface` in the device vtable.
pub const DEVICE9_VTBL_CREATE_DEPTH_STENCIL_SURFACE: usize = 0x74;
/// Byte offset of `IDirect3DDevice9::SetRenderTarget` in the device vtable.
pub const DEVICE9_VTBL_SET_RENDER_TARGET: usize = 0x94;
/// Byte offset of `IDirect3DDevice9::SetDepthStencilSurface` in the device vtable.
pub const DEVICE9_VTBL_SET_DEPTH_STENCIL_SURFACE: usize = 0x9c;
/// Byte offset of `IDirect3DDevice9::Clear` in the device vtable.
pub const DEVICE9_VTBL_CLEAR: usize = 0xac;
/// Byte offset of `IDirect3DDevice9::DrawPrimitive` in the device vtable.
pub const DEVICE9_VTBL_DRAW_PRIMITIVE: usize = 0x144;
/// Byte offset of `IDirect3DDevice9::DrawIndexedPrimitive` in the device vtable.
pub const DEVICE9_VTBL_DRAW_INDEXED_PRIMITIVE: usize = 0x148;
/// Byte offset of `IDirect3DDevice9::DrawPrimitiveUP` in the device vtable.
pub const DEVICE9_VTBL_DRAW_PRIMITIVE_UP: usize = 0x14c;
/// Byte offset of `IDirect3DDevice9::DrawIndexedPrimitiveUP` in the device vtable.
pub const DEVICE9_VTBL_DRAW_INDEXED_PRIMITIVE_UP: usize = 0x150;
/// Byte offset of `IDirect3DDevice9::CreateVertexDeclaration` in the device vtable.
pub const DEVICE9_VTBL_CREATE_VERTEX_DECLARATION: usize = 0x158;
/// Byte offset of `IDirect3DDevice9::SetVertexDeclaration` in the device vtable.
pub const DEVICE9_VTBL_SET_VERTEX_DECLARATION: usize = 0x15c;
/// Byte offset of `IDirect3DDevice9::GetVertexDeclaration` in the device vtable.
pub const DEVICE9_VTBL_GET_VERTEX_DECLARATION: usize = 0x160;
/// Byte offset of `IDirect3DDevice9::SetFVF` in the device vtable.
pub const DEVICE9_VTBL_SET_FVF: usize = 0x164;
/// Byte offset of `IDirect3DDevice9::GetFVF` in the device vtable.
pub const DEVICE9_VTBL_GET_FVF: usize = 0x168;
/// Byte offset of `IDirect3DDevice9::CreateVertexShader` in the device vtable.
pub const DEVICE9_VTBL_CREATE_VERTEX_SHADER: usize = 0x16c;
/// Byte offset of `IDirect3DDevice9::CreatePixelShader` in the device vtable.
pub const DEVICE9_VTBL_CREATE_PIXEL_SHADER: usize = 0x1a8;

/// Result type returned by Direct3D wrapper calls.
pub type Direct3DResult<T> = WindowsResult<T>;

/// ABI value returned when a D3D hook cannot call its original function.
pub const D3D_FAILURE_CODE: i32 = windows::Win32::Foundation::E_FAIL.0;

/// Construct a generic Direct3D failure for higher-level validation errors.
pub fn direct3d_failure() -> Direct3DError {
    Direct3DError::from_hresult(windows::Win32::Foundation::E_FAIL)
}

/// Maximum D3D9 vertex declaration elements captured for diagnostics.
pub const MAX_VERTEX_DECLARATION_ELEMENTS: usize = 32;

/// Snapshot of the currently bound D3D9 vertex declaration.
#[derive(Clone, Copy, Debug)]
pub struct VertexDeclarationSnapshot {
    pub handle: *mut c_void,
    pub element_count: u32,
    pub elements: [D3DVERTEXELEMENT9; MAX_VERTEX_DECLARATION_ELEMENTS],
}

/// Snapshot of one D3D9 vertex stream binding.
#[derive(Clone, Copy, Debug)]
pub struct VertexStreamSourceSnapshot {
    pub buffer: *mut c_void,
    pub offset: u32,
    pub stride: u32,
}

/// D3D9 INTZ depth texture format used for shader-readable depth.
pub const D3DFMT_INTZ: D3DFORMAT = D3DFORMAT(make_fourcc(b'I', b'N', b'T', b'Z'));

/// Two-channel 16-bit float render target used for compact intermediate buffers.
pub const D3DFMT_G16R16F: D3DFORMAT = D3DFORMAT(112);

/// Single-channel 16-bit float render target used for scalar intermediate buffers.
pub const D3DFMT_R16F: D3DFORMAT = D3DFORMAT(111);

/// Four-channel 16-bit float render target used for high-quality color intermediates.
pub const D3DFMT_A16B16G16R16F: D3DFORMAT = D3DFORMAT(113);

/// Magic render-state value that triggers RESZ depth resolve on supported D3D9 drivers.
pub const D3DRESZ_POINT_SIZE: u32 = 0x7FA0_5000;

const D3DFMT_RESZ: D3DFORMAT = D3DFORMAT(make_fourcc(b'R', b'E', b'S', b'Z'));

const fn make_fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    a as u32 | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

/// Borrowed `IDirect3DDevice9` pointer.
///
/// This wrapper does not call `AddRef` or `Release`. It is meant for pointers
/// read from a host renderer, where ownership remains with the host.
#[derive(Clone, Copy)]
pub struct Device9Ref<'a> {
    inner: InterfaceRef<'a, IDirect3DDevice9>,
}

impl<'a> Device9Ref<'a> {
    /// Create a borrowed device wrapper from a raw COM pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be a live `IDirect3DDevice9*` for the returned lifetime.
    pub unsafe fn from_raw(ptr: *mut IDirect3DDevice9) -> Option<Self> {
        let ptr = NonNull::new(ptr.cast::<c_void>())?;
        Some(Self {
            inner: unsafe { InterfaceRef::from_raw(ptr) },
        })
    }

    /// Create a borrowed device wrapper from a raw erased COM pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be a live `IDirect3DDevice9*` for the returned lifetime.
    pub unsafe fn from_raw_void(ptr: *mut c_void) -> Option<Self> {
        let ptr = NonNull::new(ptr)?;
        Some(Self {
            inner: unsafe { InterfaceRef::from_raw(ptr) },
        })
    }

    /// Return the raw `IDirect3DDevice9*` pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
    }

    /// Return the borrowed Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DDevice9 {
        &self.inner
    }

    /// Check cooperative level for lost/reset state.
    pub fn test_cooperative_level(&self) -> Direct3DResult<()> {
        unsafe { self.inner.TestCooperativeLevel() }
    }

    /// Query the driver's approximate available texture memory.
    pub fn available_texture_mem(&self) -> u32 {
        unsafe { self.inner.GetAvailableTextureMem() }
    }

    /// Release managed resources held by the driver.
    pub fn evict_managed_resources(&self) -> Direct3DResult<()> {
        unsafe { self.inner.EvictManagedResources() }
    }

    /// Get the owning Direct3D object. The returned wrapper owns that COM reference.
    pub fn direct3d(&self) -> Direct3DResult<Direct3D9> {
        unsafe { self.inner.GetDirect3D().map(Direct3D9::new) }
    }

    /// Reset the device with caller-provided presentation parameters.
    ///
    /// # Safety
    ///
    /// The caller must follow D3D9 lost-device rules and release/reset all
    /// default-pool resources around this call.
    pub unsafe fn reset(&self, params: *mut D3DPRESENT_PARAMETERS) -> Direct3DResult<()> {
        unsafe { self.inner.Reset(params) }
    }

    /// Present the current backbuffer.
    pub fn present(&self) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .Present(null_mut(), null_mut(), Default::default(), null_mut())
        }
    }

    /// Get a backbuffer surface. The returned wrapper owns that COM reference.
    pub fn back_buffer(&self, swap_chain: u32, back_buffer: u32) -> Direct3DResult<Surface9> {
        unsafe {
            self.inner
                .GetBackBuffer(swap_chain, back_buffer, D3DBACKBUFFER_TYPE_MONO)
                .map(Surface9::new)
        }
    }

    /// Create a texture. The returned wrapper owns that COM reference.
    pub fn create_texture(
        &self,
        width: u32,
        height: u32,
        levels: u32,
        usage: u32,
        format: D3DFORMAT,
        pool: D3DPOOL,
    ) -> Direct3DResult<Texture9> {
        let mut texture = None;
        unsafe {
            self.inner.CreateTexture(
                width,
                height,
                levels,
                usage,
                format,
                pool,
                &mut texture,
                null_mut::<HANDLE>(),
            )?;
        }
        let Some(texture) = texture else {
            return Err(WindowsError::from_hresult(E_POINTER));
        };

        Texture9::new(texture)
    }

    /// Create a default-pool render-target texture.
    pub fn create_render_target_texture(
        &self,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Texture9> {
        self.create_texture(
            width,
            height,
            1,
            D3DUSAGE_RENDERTARGET as u32,
            format,
            D3DPOOL_DEFAULT,
        )
    }

    /// Create a default-pool shader-readable depth-stencil texture.
    pub fn create_depth_stencil_texture(
        &self,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Texture9> {
        self.create_texture(
            width,
            height,
            1,
            D3DUSAGE_DEPTHSTENCIL as u32,
            format,
            D3DPOOL_DEFAULT,
        )
    }

    /// Create a render target texture using `D3DFMT_A8R8G8B8`.
    pub fn create_argb_render_target_texture(
        &self,
        width: u32,
        height: u32,
    ) -> Direct3DResult<Texture9> {
        self.create_render_target_texture(width, height, D3DFMT_A8R8G8B8)
    }

    /// Get the current render target. The returned wrapper owns that COM reference.
    pub fn render_target(&self, index: u32) -> Direct3DResult<Surface9> {
        unsafe { self.inner.GetRenderTarget(index).map(Surface9::new) }
    }

    /// Set a render target surface.
    pub fn set_render_target(&self, index: u32, surface: &Surface9) -> Direct3DResult<()> {
        unsafe { self.inner.SetRenderTarget(index, surface.as_inner()) }
    }

    /// Set a borrowed raw `IDirect3DSurface9` as current render target.
    ///
    /// # Safety
    ///
    /// `surface` must be a live `IDirect3DSurface9*` for the duration of the call.
    /// This does not take ownership of the caller's reference.
    pub unsafe fn set_raw_render_target(
        &self,
        index: u32,
        surface: *mut c_void,
    ) -> Direct3DResult<()> {
        let ptr = NonNull::new(surface).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let surface = unsafe { InterfaceRef::<IDirect3DSurface9>::from_raw(ptr) };
        unsafe { self.inner.SetRenderTarget(index, surface) }
    }

    /// Clear the currently bound depth buffer to the default far depth.
    pub fn clear_zbuffer(&self) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .Clear(0, null(), D3DCLEAR_ZBUFFER as u32, 0, 1.0, 0)
        }
    }

    /// Get the current depth-stencil surface. The returned wrapper owns that COM reference.
    pub fn depth_stencil_surface(&self) -> Direct3DResult<Option<Surface9>> {
        match unsafe { self.inner.GetDepthStencilSurface() } {
            Ok(surface) => Ok(Some(Surface9::new(surface))),
            Err(err) if err.code() == E_POINTER => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Set the current depth-stencil surface.
    pub fn set_depth_stencil_surface(&self, surface: Option<&Surface9>) -> Direct3DResult<()> {
        unsafe {
            match surface {
                Some(surface) => self.inner.SetDepthStencilSurface(surface.as_inner()),
                None => self
                    .inner
                    .SetDepthStencilSurface(Option::<&IDirect3DSurface9>::None),
            }
        }
    }

    /// Set a borrowed raw `IDirect3DSurface9` as current depth-stencil surface.
    ///
    /// # Safety
    ///
    /// `surface` must be a live `IDirect3DSurface9*` for the duration of the call.
    /// This does not call `AddRef`; it is for engine-owned surfaces.
    pub unsafe fn set_raw_depth_stencil_surface(&self, surface: *mut c_void) -> Direct3DResult<()> {
        let ptr = NonNull::new(surface).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let surface = unsafe { InterfaceRef::<IDirect3DSurface9>::from_raw(ptr) };
        unsafe { self.inner.SetDepthStencilSurface(surface) }
    }

    /// Copy pixels between render-target surfaces.
    pub fn stretch_rect(
        &self,
        source: &Surface9,
        source_rect: Option<&RECT>,
        dest: &Surface9,
        dest_rect: Option<&RECT>,
        filter: D3DTEXTUREFILTERTYPE,
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.StretchRect(
                source.as_inner(),
                source_rect.map_or(null(), |rect| rect as *const RECT),
                dest.as_inner(),
                dest_rect.map_or(null(), |rect| rect as *const RECT),
                filter,
            )
        }
    }

    /// Set the viewport.
    pub fn set_viewport(&self, viewport: &D3DVIEWPORT9) -> Direct3DResult<()> {
        unsafe { self.inner.SetViewport(viewport) }
    }

    /// Get the current viewport.
    pub fn viewport(&self) -> Direct3DResult<D3DVIEWPORT9> {
        let mut viewport = D3DVIEWPORT9::default();
        unsafe { self.inner.GetViewport(&mut viewport)? };
        Ok(viewport)
    }

    /// Get a render state value.
    pub fn render_state(&self, state: D3DRENDERSTATETYPE) -> Direct3DResult<u32> {
        let mut value = 0;
        unsafe { self.inner.GetRenderState(state, &mut value)? };
        Ok(value)
    }

    /// Set a render state value.
    pub fn set_render_state(&self, state: D3DRENDERSTATETYPE, value: u32) -> Direct3DResult<()> {
        unsafe { self.inner.SetRenderState(state, value) }
    }

    /// Get a sampler state value.
    pub fn sampler_state(&self, sampler: u32, state: D3DSAMPLERSTATETYPE) -> Direct3DResult<u32> {
        let mut value = 0;
        unsafe { self.inner.GetSamplerState(sampler, state, &mut value)? };
        Ok(value)
    }

    /// Set a sampler state value.
    pub fn set_sampler_state(
        &self,
        sampler: u32,
        state: D3DSAMPLERSTATETYPE,
        value: u32,
    ) -> Direct3DResult<()> {
        unsafe { self.inner.SetSamplerState(sampler, state, value) }
    }

    /// Get a texture stage state value.
    pub fn texture_stage_state(
        &self,
        stage: u32,
        state: D3DTEXTURESTAGESTATETYPE,
    ) -> Direct3DResult<u32> {
        let mut value = 0;
        unsafe { self.inner.GetTextureStageState(stage, state, &mut value)? };
        Ok(value)
    }

    /// Set a texture stage state value.
    pub fn set_texture_stage_state(
        &self,
        stage: u32,
        state: D3DTEXTURESTAGESTATETYPE,
        value: u32,
    ) -> Direct3DResult<()> {
        unsafe { self.inner.SetTextureStageState(stage, state, value) }
    }

    /// Set a texture by casting it to `IDirect3DBaseTexture9`.
    pub fn set_texture(&self, stage: u32, texture: &Texture9) -> Direct3DResult<()> {
        unsafe { self.inner.SetTexture(stage, texture.as_base_texture()) }
    }

    /// Return whether a texture is currently bound to a sampler stage.
    ///
    /// `GetTexture` returns an owned COM reference when a texture exists; the
    /// wrapper drops it immediately. The result is only a presence check.
    pub fn texture_bound(&self, stage: u32) -> bool {
        unsafe { self.inner.GetTexture(stage) }.is_ok()
    }

    /// Return the currently bound texture identity without retaining a COM reference.
    pub fn texture_raw(&self, stage: u32) -> Option<*mut c_void> {
        let texture = unsafe { self.inner.GetTexture(stage) }.ok()?;
        Some(texture.as_raw())
    }

    /// Set a borrowed raw `IDirect3DBaseTexture9` pointer.
    ///
    /// # Safety
    ///
    /// `texture` must be a live base texture for the duration of the call.
    /// This does not call `AddRef`; it is for engine-owned textures.
    pub unsafe fn set_raw_base_texture(
        &self,
        stage: u32,
        texture: *mut c_void,
    ) -> Direct3DResult<()> {
        let ptr = NonNull::new(texture).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let texture = unsafe { InterfaceRef::<IDirect3DBaseTexture9>::from_raw(ptr) };
        unsafe { self.inner.SetTexture(stage, texture) }
    }

    /// Clear a texture sampler binding.
    pub fn clear_texture(&self, stage: u32) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .SetTexture(stage, Option::<&IDirect3DBaseTexture9>::None)
        }
    }

    /// Create a reusable D3D state block.
    pub fn create_state_block(&self, kind: D3DSTATEBLOCKTYPE) -> Direct3DResult<StateBlock9> {
        unsafe { self.inner.CreateStateBlock(kind).map(StateBlock9::new) }
    }

    /// Get the current fixed-function vertex format.
    pub fn fvf(&self) -> Direct3DResult<u32> {
        let mut fvf = 0;
        unsafe { self.inner.GetFVF(&mut fvf)? };
        Ok(fvf)
    }

    /// Capture the currently bound programmable vertex declaration.
    pub fn vertex_declaration_snapshot(&self) -> Direct3DResult<VertexDeclarationSnapshot> {
        let declaration = unsafe { self.inner.GetVertexDeclaration()? };
        let handle = declaration.as_raw();
        let mut elements = [D3DVERTEXELEMENT9::default(); MAX_VERTEX_DECLARATION_ELEMENTS];
        let mut element_count = elements.len() as u32;
        unsafe { declaration.GetDeclaration(elements.as_mut_ptr(), &mut element_count)? };
        Ok(VertexDeclarationSnapshot {
            handle,
            element_count: element_count.min(MAX_VERTEX_DECLARATION_ELEMENTS as u32),
            elements,
        })
    }

    /// Capture one currently bound vertex stream source.
    pub fn stream_source(&self, stream: u32) -> Direct3DResult<VertexStreamSourceSnapshot> {
        let mut buffer = None::<IDirect3DVertexBuffer9>;
        let mut offset = 0;
        let mut stride = 0;
        unsafe {
            self.inner
                .GetStreamSource(stream, &mut buffer, &mut offset, &mut stride)?
        };
        Ok(VertexStreamSourceSnapshot {
            buffer: buffer
                .as_ref()
                .map(Interface::as_raw)
                .unwrap_or_else(null_mut),
            offset,
            stride,
        })
    }

    /// Set the fixed-function vertex format.
    pub fn set_fvf(&self, fvf: u32) -> Direct3DResult<()> {
        unsafe { self.inner.SetFVF(fvf) }
    }

    /// Draw caller-owned vertex data.
    ///
    /// # Safety
    ///
    /// `vertices` must match the current FVF/vertex declaration and D3D primitive
    /// requirements for `primitive_count`.
    pub unsafe fn draw_primitive_up<T>(
        &self,
        primitive_type: D3DPRIMITIVETYPE,
        primitive_count: u32,
        vertices: &[T],
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.DrawPrimitiveUP(
                primitive_type,
                primitive_count,
                vertices.as_ptr().cast::<c_void>(),
                size_of::<T>() as u32,
            )
        }
    }

    /// Create a pixel shader from compiled shader bytecode.
    pub fn create_pixel_shader(&self, bytecode: &[u32]) -> Direct3DResult<PixelShader9> {
        unsafe {
            self.inner
                .CreatePixelShader(bytecode.as_ptr())
                .map(PixelShader9::new)
        }
    }

    /// Set the current pixel shader.
    pub fn set_pixel_shader(&self, shader: &PixelShader9) -> Direct3DResult<()> {
        unsafe { self.inner.SetPixelShader(shader.as_inner()) }
    }

    /// Set a borrowed raw `IDirect3DPixelShader9` pointer.
    ///
    /// # Safety
    ///
    /// `shader` must be a live pixel shader for the duration of the call.
    /// This does not call `AddRef`; it is for engine-owned or otherwise
    /// lifetime-managed shader objects.
    pub unsafe fn set_raw_pixel_shader(&self, shader: *mut c_void) -> Direct3DResult<()> {
        let ptr = NonNull::new(shader).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let shader = unsafe { InterfaceRef::<IDirect3DPixelShader9>::from_raw(ptr) };
        unsafe { self.inner.SetPixelShader(shader) }
    }

    /// Clear the current programmable pixel shader.
    pub fn clear_pixel_shader(&self) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .SetPixelShader(Option::<&IDirect3DPixelShader9>::None)
        }
    }

    /// Return the current programmable pixel shader pointer, if one is bound.
    pub fn current_pixel_shader_raw(&self) -> Direct3DResult<*mut c_void> {
        let shader = unsafe { self.inner.GetPixelShader()? };
        Ok(shader.as_raw())
    }

    /// Set pixel shader float constants.
    pub fn set_pixel_shader_constant_f(
        &self,
        start_register: u32,
        constants: &[[f32; 4]],
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.SetPixelShaderConstantF(
                start_register,
                constants.as_ptr().cast::<f32>(),
                constants.len() as u32,
            )
        }
    }

    /// Read pixel shader float constants from the device state.
    pub fn pixel_shader_constant_f(
        &self,
        start_register: u32,
        constants: &mut [[f32; 4]],
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.GetPixelShaderConstantF(
                start_register,
                constants.as_mut_ptr().cast::<f32>(),
                constants.len() as u32,
            )
        }
    }

    /// Create a vertex shader from compiled shader bytecode.
    pub fn create_vertex_shader(&self, bytecode: &[u32]) -> Direct3DResult<VertexShader9> {
        unsafe {
            self.inner
                .CreateVertexShader(bytecode.as_ptr())
                .map(VertexShader9::new)
        }
    }

    /// Set the current vertex shader.
    pub fn set_vertex_shader(&self, shader: &VertexShader9) -> Direct3DResult<()> {
        unsafe { self.inner.SetVertexShader(shader.as_inner()) }
    }

    /// Set a borrowed raw `IDirect3DVertexShader9` pointer.
    ///
    /// # Safety
    ///
    /// `shader` must be a live vertex shader for the duration of the call.
    /// This does not call `AddRef`; it is for engine-owned or otherwise
    /// lifetime-managed shader objects.
    pub unsafe fn set_raw_vertex_shader(&self, shader: *mut c_void) -> Direct3DResult<()> {
        let ptr = NonNull::new(shader).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let shader = unsafe { InterfaceRef::<IDirect3DVertexShader9>::from_raw(ptr) };
        unsafe { self.inner.SetVertexShader(shader) }
    }

    /// Clear the current programmable vertex shader so FVF vertices can be used.
    pub fn clear_vertex_shader(&self) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .SetVertexShader(Option::<&IDirect3DVertexShader9>::None)
        }
    }

    /// Return the current programmable vertex shader pointer, if one is bound.
    pub fn current_vertex_shader_raw(&self) -> Direct3DResult<*mut c_void> {
        let shader = unsafe { self.inner.GetVertexShader()? };
        Ok(shader.as_raw())
    }

    /// Read vertex shader float constants from the device state.
    pub fn vertex_shader_constant_f(
        &self,
        start_register: u32,
        constants: &mut [[f32; 4]],
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.GetVertexShaderConstantF(
                start_register,
                constants.as_mut_ptr().cast::<f32>(),
                constants.len() as u32,
            )
        }
    }
}

/// Owned `IDirect3D9` reference.
#[derive(Clone, Debug)]
pub struct Direct3D9 {
    inner: IDirect3D9,
}

// Safety: this wrapper only owns a COM reference. Callers must still obey the
// D3D threading contract for actual resource use.
unsafe impl Send for Direct3D9 {}

impl Direct3D9 {
    fn new(inner: IDirect3D9) -> Self {
        Self { inner }
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3D9 {
        &self.inner
    }

    /// Get the current adapter display mode.
    pub fn adapter_display_mode(&self, adapter: u32) -> Direct3DResult<D3DDISPLAYMODE> {
        let mut mode = D3DDISPLAYMODE::default();
        unsafe { self.inner.GetAdapterDisplayMode(adapter, &mut mode)? };
        Ok(mode)
    }

    /// Check whether a resource format is supported by the adapter.
    pub fn check_device_format(
        &self,
        adapter: u32,
        device_type: D3DDEVTYPE,
        adapter_format: D3DFORMAT,
        usage: u32,
        resource_type: D3DRESOURCETYPE,
        check_format: D3DFORMAT,
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.CheckDeviceFormat(
                adapter,
                device_type,
                adapter_format,
                usage,
                resource_type,
                check_format,
            )
        }
    }

    /// Check RESZ support for the default HAL device.
    pub fn check_default_resz_support(&self) -> Direct3DResult<()> {
        let mode = self.adapter_display_mode(D3DADAPTER_DEFAULT)?;
        self.check_device_format(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            mode.Format,
            D3DUSAGE_RENDERTARGET as u32,
            D3DRTYPE_SURFACE,
            D3DFMT_RESZ,
        )
    }

    /// Check render-target texture support for the default HAL device.
    pub fn check_default_render_target_texture_support(
        &self,
        format: D3DFORMAT,
    ) -> Direct3DResult<()> {
        let mode = self.adapter_display_mode(D3DADAPTER_DEFAULT)?;
        self.check_device_format(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            mode.Format,
            D3DUSAGE_RENDERTARGET as u32,
            D3DRTYPE_TEXTURE,
            format,
        )
    }
}

/// Owned `IDirect3DSurface9` reference.
#[derive(Clone, Debug)]
pub struct Surface9 {
    inner: IDirect3DSurface9,
}

// Safety: this wrapper only owns a COM reference. Callers must still obey the
// D3D device threading contract for actual resource use.
unsafe impl Send for Surface9 {}

impl Surface9 {
    fn new(inner: IDirect3DSurface9) -> Self {
        Self { inner }
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DSurface9 {
        &self.inner
    }

    /// Return the raw `IDirect3DSurface9*` pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
    }

    /// Consume the wrapper and return the owned Windows binding interface.
    pub fn into_inner(self) -> IDirect3DSurface9 {
        self.inner
    }

    /// Return surface description.
    pub fn desc(&self) -> Direct3DResult<D3DSURFACE_DESC> {
        let mut desc = D3DSURFACE_DESC::default();
        unsafe { self.inner.GetDesc(&mut desc)? };
        Ok(desc)
    }

    /// Read a description from a borrowed raw `IDirect3DSurface9`.
    ///
    /// # Safety
    ///
    /// `surface` must be a live `IDirect3DSurface9*` for the duration of the call.
    /// This does not call `AddRef`; it is for engine-owned surfaces.
    pub unsafe fn raw_desc(surface: *mut c_void) -> Direct3DResult<D3DSURFACE_DESC> {
        let ptr = NonNull::new(surface).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let surface = unsafe { InterfaceRef::<IDirect3DSurface9>::from_raw(ptr) };
        let mut desc = D3DSURFACE_DESC::default();
        unsafe { surface.GetDesc(&mut desc)? };
        Ok(desc)
    }
}

/// Owned `IDirect3DTexture9` reference.
#[derive(Clone, Debug)]
pub struct Texture9 {
    inner: IDirect3DTexture9,
    base: IDirect3DBaseTexture9,
}

// Safety: this wrapper only owns COM references. Callers must still obey the
// D3D device threading contract for actual resource use.
unsafe impl Send for Texture9 {}

impl Texture9 {
    fn new(inner: IDirect3DTexture9) -> Direct3DResult<Self> {
        let base = inner.cast::<IDirect3DBaseTexture9>()?;
        Ok(Self { inner, base })
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DTexture9 {
        &self.inner
    }

    /// Return the cached base texture interface used by `SetTexture`.
    pub fn as_base_texture(&self) -> &IDirect3DBaseTexture9 {
        &self.base
    }

    /// Return the cached base texture raw pointer.
    pub fn as_raw_base_texture(&self) -> *mut c_void {
        self.base.as_raw()
    }

    /// Consume the wrapper and return the owned Windows binding interface.
    pub fn into_inner(self) -> IDirect3DTexture9 {
        self.inner
    }

    /// Return the number of mip levels.
    pub fn level_count(&self) -> u32 {
        unsafe { self.inner.GetLevelCount() }
    }

    /// Get a surface level. The returned wrapper owns that COM reference.
    pub fn surface_level(&self, level: u32) -> Direct3DResult<Surface9> {
        unsafe { self.inner.GetSurfaceLevel(level).map(Surface9::new) }
    }

    /// Write one ARGB texel into a lockable level-0 texture.
    pub fn write_level0_argb_pixel(&self, pixel: u32) -> Direct3DResult<()> {
        let mut locked = D3DLOCKED_RECT::default();
        unsafe {
            self.inner.LockRect(0, &mut locked, null(), 0)?;
            locked.pBits.cast::<u32>().write(pixel);
            self.inner.UnlockRect(0)
        }
    }
}

/// Owned `IDirect3DStateBlock9` reference.
#[derive(Clone, Debug)]
pub struct StateBlock9 {
    inner: IDirect3DStateBlock9,
}

// Safety: this wrapper only owns a COM reference. Callers must still obey the
// D3D device threading contract for actual resource use.
unsafe impl Send for StateBlock9 {}

impl StateBlock9 {
    fn new(inner: IDirect3DStateBlock9) -> Self {
        Self { inner }
    }

    /// Capture the current device state into this state block.
    pub fn capture(&self) -> Direct3DResult<()> {
        unsafe { self.inner.Capture() }
    }

    /// Apply the previously captured device state.
    pub fn apply(&self) -> Direct3DResult<()> {
        unsafe { self.inner.Apply() }
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DStateBlock9 {
        &self.inner
    }

    /// Consume the wrapper and return the owned Windows binding interface.
    pub fn into_inner(self) -> IDirect3DStateBlock9 {
        self.inner
    }
}

/// Owned `IDirect3DPixelShader9` reference.
#[derive(Clone, Debug)]
pub struct PixelShader9 {
    inner: IDirect3DPixelShader9,
}

// Safety: this wrapper only owns a COM reference. Callers must still obey the
// D3D device threading contract for actual resource use.
unsafe impl Send for PixelShader9 {}

impl PixelShader9 {
    fn new(inner: IDirect3DPixelShader9) -> Self {
        Self { inner }
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DPixelShader9 {
        &self.inner
    }

    /// Return the raw `IDirect3DPixelShader9*` pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
    }

    /// Consume the wrapper and return the owned Windows binding interface.
    pub fn into_inner(self) -> IDirect3DPixelShader9 {
        self.inner
    }
}

/// Owned `IDirect3DVertexShader9` reference.
#[derive(Clone, Debug)]
pub struct VertexShader9 {
    inner: IDirect3DVertexShader9,
}

// Safety: this wrapper only owns a COM reference. Callers must still obey the
// D3D device threading contract for actual resource use.
unsafe impl Send for VertexShader9 {}

impl VertexShader9 {
    fn new(inner: IDirect3DVertexShader9) -> Self {
        Self { inner }
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DVertexShader9 {
        &self.inner
    }

    /// Return the raw `IDirect3DVertexShader9*` pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
    }

    /// Consume the wrapper and return the owned Windows binding interface.
    pub fn into_inner(self) -> IDirect3DVertexShader9 {
        self.inner
    }
}

/// Plain XYZ point used for RESZ depth resolves.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PositionVertex {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl PositionVertex {
    /// FVF used by `PositionVertex`.
    pub const FVF: u32 = D3DFVF_XYZ;

    pub const fn origin() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }
    }
}

/// Plain layout matching D3D9 transformed textured vertex data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ScreenVertex {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub rhw: f32,
    pub u: f32,
    pub v: f32,
}

impl ScreenVertex {
    /// FVF used by `ScreenVertex`.
    pub const FVF: u32 = D3DFVF_XYZRHW | D3DFVF_TEX1;

    pub const fn new(x: f32, y: f32, u: f32, v: f32) -> Self {
        Self {
            x,
            y,
            z: 0.0,
            rhw: 1.0,
            u,
            v,
        }
    }
}

/// Common backbuffer selector for mono swap chains.
pub const BACKBUFFER_MONO: D3DBACKBUFFER_TYPE = D3DBACKBUFFER_TYPE_MONO;

/// Default-pool render-target usage flag as a `u32`.
pub const USAGE_RENDER_TARGET: u32 = D3DUSAGE_RENDERTARGET as u32;

const D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY: u32 = 1 << 12;
const D3DCOMPILE_OPTIMIZATION_LEVEL3: u32 = 1 << 15;
const D3D_COMPILER_DLLS: &[&str] = &[
    "d3dcompiler_47.dll",
    "d3dcompiler_46.dll",
    "d3dcompiler_43.dll",
    "d3dcompiler_42.dll",
    "d3dcompiler_41.dll",
];

type D3DCompileFn = unsafe extern "system" fn(
    src_data: *const c_void,
    src_data_size: usize,
    source_name: PCSTR,
    defines: *const c_void,
    include: *mut c_void,
    entry_point: PCSTR,
    target: PCSTR,
    flags1: u32,
    flags2: u32,
    code: *mut *mut c_void,
    error_messages: *mut *mut c_void,
) -> HRESULT;

static D3D_COMPILE_FN: OnceLock<Result<D3DCompileFn, String>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ShaderCompileError {
    #[error("shader compiler input contains an interior nul byte: {0}")]
    Nul(#[from] std::ffi::NulError),
    #[error("{0}")]
    CompilerUnavailable(String),
    #[error("{0}")]
    CompilationFailed(String),
    #[error("D3DCompile returned no shader bytecode")]
    MissingBytecode,
    #[error("shader bytecode is empty")]
    EmptyBytecode,
    #[error("shader bytecode length is not DWORD aligned")]
    UnalignedBytecode,
}

/// Compile HLSL source through the newest available legacy D3D compiler.
pub fn compile_hlsl(
    source_name: &str,
    source: &[u8],
    target: &str,
) -> Result<Vec<u32>, ShaderCompileError> {
    let compiler = d3d_compile_fn()?;
    let source_name = CString::new(source_name)?;
    let entry = CString::new("Main")?;
    let target = CString::new(target)?;
    let flags = D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY | D3DCOMPILE_OPTIMIZATION_LEVEL3;

    let mut code = null_mut();
    let mut errors = null_mut();
    let result = unsafe {
        compiler(
            source.as_ptr().cast(),
            source.len(),
            PCSTR::from_raw(source_name.as_ptr().cast()),
            null(),
            null_mut(),
            PCSTR::from_raw(entry.as_ptr().cast()),
            PCSTR::from_raw(target.as_ptr().cast()),
            flags,
            0,
            &mut code,
            &mut errors,
        )
    };

    let diagnostics = unsafe { take_blob(errors) }.and_then(|blob| blob_text(&blob));
    if result.is_err() {
        return Err(ShaderCompileError::CompilationFailed(
            diagnostics.unwrap_or_else(|| format!("D3DCompile failed: {result:?}")),
        ));
    }

    if let Some(message) = diagnostics {
        log::debug!("D3D compiler diagnostics for {source_name:?}: {message}");
    }

    let code = unsafe { take_blob(code) }.ok_or(ShaderCompileError::MissingBytecode)?;
    dword_aligned_shader_bytecode(unsafe { blob_bytes(&code) })
}

fn d3d_compile_fn() -> Result<D3DCompileFn, ShaderCompileError> {
    match D3D_COMPILE_FN.get_or_init(resolve_d3d_compile_fn) {
        Ok(function) => Ok(*function),
        Err(error) => Err(ShaderCompileError::CompilerUnavailable(error.clone())),
    }
}

fn resolve_d3d_compile_fn() -> Result<D3DCompileFn, String> {
    for dll in D3D_COMPILER_DLLS {
        if let Ok(module) = load_library_a(dll)
            && let Ok(proc) = get_proc_address(module, "D3DCompile")
        {
            let function = unsafe { FnPtr::<D3DCompileFn>::from_raw(proc) }
                .map_err(|error| format!("D3DCompile export is invalid: {error}"))?;
            return Ok(function.as_fn());
        }
    }

    Err(format!(
        "D3DCompile not found; tried {}",
        D3D_COMPILER_DLLS.join(", ")
    ))
}

unsafe fn take_blob(ptr: *mut c_void) -> Option<ID3DBlob> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { ID3DBlob::from_raw(ptr) })
}

unsafe fn blob_bytes(blob: &ID3DBlob) -> &[u8] {
    let ptr = unsafe { blob.GetBufferPointer() };
    let len = unsafe { blob.GetBufferSize() };
    unsafe { slice::from_raw_parts(ptr.cast(), len) }
}

fn blob_text(blob: &ID3DBlob) -> Option<String> {
    let bytes = unsafe { blob_bytes(blob) };
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    (end != 0).then(|| String::from_utf8_lossy(&bytes[..end]).trim().to_owned())
}

/// Validate and convert precompiled D3D shader bytes to DWORD bytecode.
pub fn dword_aligned_shader_bytecode(bytes: &[u8]) -> Result<Vec<u32>, ShaderCompileError> {
    if bytes.is_empty() {
        return Err(ShaderCompileError::EmptyBytecode);
    }
    if !bytes.len().is_multiple_of(size_of::<u32>()) {
        return Err(ShaderCompileError::UnalignedBytecode);
    }

    Ok(bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}
