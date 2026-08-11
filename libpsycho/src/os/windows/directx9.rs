//! Direct3D 9 wrappers used by injected rendering modules.
//!
//! Host applications own their renderer and `IDirect3DDevice9`. Use `Device9Ref`
//! for borrowed device pointers so Rust does not call `Release` on objects it
//! does not own. Resource wrappers in this module are owned COM references.
//! DXVK devices additionally expose their exact Vulkan physical-device handle
//! through DXVK's documented D3D9 interop interface. That path is required for
//! physical GPU identity because DXVK may deliberately spoof the D3D9 adapter
//! description and PCI IDs for application compatibility. Device-bound format
//! probes likewise use the live device's creation adapter and device type;
//! default-adapter helpers are appropriate only for independent inventory.

use core::ffi::{c_char, c_void};
use core::mem::size_of;
use core::ptr::{NonNull, addr_of, null, null_mut};
use core::slice;
use std::ffi::CString;
use std::sync::OnceLock;

use ash::vk;
use thiserror::Error;

pub use windows::Win32::Foundation::RECT;
use windows::Win32::Foundation::{E_FAIL, E_NOINTERFACE, E_POINTER, HANDLE};
use windows::Win32::Graphics::Direct3D::ID3DBlob;
pub use windows::Win32::Graphics::Direct3D9::{
    D3D_SDK_VERSION, D3DBLEND_ONE, D3DBLENDOP_ADD, D3DCAPS9, D3DCLEAR_STENCIL, D3DCLEAR_TARGET,
    D3DCLEAR_ZBUFFER, D3DCMP_ALWAYS, D3DCMP_LESSEQUAL, D3DCUBEMAP_FACE_NEGATIVE_X,
    D3DCUBEMAP_FACE_NEGATIVE_Y, D3DCUBEMAP_FACE_NEGATIVE_Z, D3DCUBEMAP_FACE_POSITIVE_X,
    D3DCUBEMAP_FACE_POSITIVE_Y, D3DCUBEMAP_FACE_POSITIVE_Z, D3DCUBEMAP_FACES, D3DCULL, D3DCULL_CCW,
    D3DCULL_CW, D3DCULL_NONE, D3DDEVTYPE, D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, D3DDEVTYPE_REF,
    D3DDEVTYPE_SW, D3DFMT_A8R8G8B8, D3DFMT_R32F, D3DFORMAT, D3DFVF_DIFFUSE, D3DFVF_TEX1,
    D3DFVF_XYZ, D3DFVF_XYZRHW, D3DMULTISAMPLE_4_SAMPLES, D3DMULTISAMPLE_NONE, D3DPOOL_DEFAULT,
    D3DPOOL_MANAGED, D3DPT_POINTLIST, D3DPT_TRIANGLELIST, D3DPT_TRIANGLESTRIP,
    D3DRS_ADAPTIVETESS_Y, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHAFUNC, D3DRS_ALPHAREF,
    D3DRS_ALPHATESTENABLE, D3DRS_BLENDOP, D3DRS_COLORWRITEENABLE, D3DRS_COLORWRITEENABLE1,
    D3DRS_CULLMODE, D3DRS_DEPTHBIAS, D3DRS_DESTBLEND, D3DRS_MULTISAMPLEANTIALIAS,
    D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE, D3DRS_SLOPESCALEDEPTHBIAS,
    D3DRS_SRCBLEND, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE, D3DRS_ZFUNC,
    D3DRS_ZWRITEENABLE, D3DRTYPE_SURFACE, D3DRTYPE_TEXTURE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
    D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSBT_ALL,
    D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTADDRESS_WRAP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP,
    D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9,
};
use windows::Win32::Graphics::Direct3D9::{
    D3DADAPTER_DEFAULT, D3DADAPTER_IDENTIFIER9, D3DBACKBUFFER_TYPE, D3DBACKBUFFER_TYPE_MONO,
    D3DDEVICE_CREATION_PARAMETERS, D3DDISPLAYMODE, D3DLOCK_DISCARD, D3DLOCKED_RECT,
    D3DMULTISAMPLE_TYPE, D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS, D3DPOOL, D3DPRESENT_PARAMETERS,
    D3DPRIMITIVETYPE, D3DRENDERSTATETYPE, D3DRESOURCETYPE, D3DSAMPLERSTATETYPE, D3DSTATEBLOCKTYPE,
    D3DTEXTUREFILTERTYPE, D3DTEXTURESTAGESTATETYPE, D3DUSAGE_DEPTHSTENCIL, D3DUSAGE_DYNAMIC,
    D3DUSAGE_QUERY_FILTER, D3DUSAGE_QUERY_POSTPIXELSHADER_BLENDING, D3DUSAGE_RENDERTARGET,
    D3DVERTEXELEMENT9, Direct3DCreate9, IDirect3D9, IDirect3DBaseTexture9, IDirect3DCubeTexture9,
    IDirect3DDevice9, IDirect3DIndexBuffer9, IDirect3DPixelShader9, IDirect3DStateBlock9,
    IDirect3DSurface9, IDirect3DTexture9, IDirect3DVertexBuffer9, IDirect3DVertexDeclaration9,
    IDirect3DVertexShader9,
};
pub use windows::core::Error as Direct3DError;
use windows::core::{
    GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface, InterfaceRef, PCSTR, Result as WindowsResult,
};

use Direct3DError as WindowsError;

use crate::ffi::fnptr::FnPtr;
use crate::os::windows::winapi::{
    get_module_handle_a, get_proc_address, load_library_a, load_system_library_w,
};

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
/// Byte offset of `IDirect3DDevice9::SetRenderState` in the device vtable.
pub const DEVICE9_VTBL_SET_RENDER_STATE: usize = 0xe4;
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
/// ABI value returned when a nonblocking Reset preflight must be retried.
pub const D3D_DEVICE_LOST_CODE: i32 = 0x8876_0868u32 as i32;
const D3DERR_NOTFOUND: HRESULT = HRESULT(0x8876_0866u32 as i32);
const D3DERR_NOTAVAILABLE: HRESULT = HRESULT(0x8876_086au32 as i32);

/// Aligned, owned copy of a D3D9 adapter identifier.
///
/// The native identifier is packed on x86 and stores text in fixed C arrays.
/// This representation is safe to retain and compare after the native call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterIdentifier9 {
    /// Driver module name reported by D3D9.
    pub driver: String,
    /// Human-readable adapter description.
    pub description: String,
    /// Win32 display-device name.
    pub device_name: String,
    /// Driver version encoded as the native signed 64-bit `LARGE_INTEGER`.
    pub driver_version: i64,
    /// PCI or virtual-vendor identifier.
    pub vendor_id: u32,
    /// PCI or virtual-device identifier.
    pub device_id: u32,
    /// PCI subsystem identifier.
    pub subsystem_id: u32,
    /// PCI revision identifier.
    pub revision: u32,
    /// Stable D3D9 device GUID encoded in canonical `u128` form.
    pub device_identifier: u128,
    /// WHQL certification level reported by D3D9.
    pub whql_level: u32,
}

/// Stable subset of `D3DDEVICE_CREATION_PARAMETERS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceCreationParameters9 {
    /// Adapter ordinal used to create the device.
    pub adapter_ordinal: u32,
    /// D3D9 device implementation type.
    pub device_type: D3DDEVTYPE,
    /// Focus window identity, represented without transferring ownership.
    pub focus_window: usize,
    /// D3D9 behavior flags used to create the device.
    pub behavior_flags: u32,
}

/// Physical Vulkan device properties obtained from a DXVK D3D9 device.
///
/// These fields come from the Vulkan physical device selected by DXVK rather
/// than `IDirect3D9::GetAdapterIdentifier`, whose identity may be intentionally
/// replaced by a DXVK application profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DxvkPhysicalDeviceProperties9 {
    /// Vulkan physical-device name.
    pub description: String,
    /// PCI or platform vendor identifier reported by Vulkan.
    pub vendor_id: u32,
    /// PCI or platform device identifier reported by Vulkan.
    pub device_id: u32,
    /// Raw `VkPhysicalDeviceType`.
    pub device_type: i32,
    /// Packed Vulkan API version supported by the physical device.
    pub api_version: u32,
    /// Vendor-specific packed Vulkan driver version.
    pub driver_version: u32,
    /// Vulkan device UUID encoded in network byte order.
    ///
    /// Zero means the optional Vulkan 1.1 properties query was unavailable.
    pub device_uuid: u128,
    /// Vulkan driver name, when exposed by Vulkan 1.2 driver properties.
    pub driver_name: String,
    /// Vulkan driver information, when exposed by Vulkan 1.2 driver properties.
    pub driver_info: String,
}

#[repr(transparent)]
#[derive(Clone, Eq, PartialEq)]
struct ID3D9VkInteropDevice(IUnknown);

#[repr(C)]
struct ID3D9VkInteropDeviceVtbl {
    base__: IUnknown_Vtbl,
    get_vulkan_handles: unsafe extern "system" fn(
        this: *mut c_void,
        instance: *mut vk::Instance,
        physical_device: *mut vk::PhysicalDevice,
        device: *mut vk::Device,
    ),
}

// Safety: the IID and vtable layout are the public ID3D9VkInteropDevice ABI
// shipped by DXVK 2.7.1. The interface begins with IUnknown and its first
// extension method is GetVulkanHandles.
unsafe impl Interface for ID3D9VkInteropDevice {
    type Vtable = ID3D9VkInteropDeviceVtbl;
    const IID: GUID = GUID::from_u128(0x2eaa4b89_0107_4bdb_87f7_0f541c493ce0);
}

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

/// 32-bit depth surface.
pub const D3DFMT_D32: D3DFORMAT = D3DFORMAT(71);

/// 15-bit depth and 1-bit stencil surface.
pub const D3DFMT_D15S1: D3DFORMAT = D3DFORMAT(73);

/// 24-bit depth and 8-bit stencil surface.
pub const D3DFMT_D24S8: D3DFORMAT = D3DFORMAT(75);

/// 24-bit depth surface stored in 32 bits.
pub const D3DFMT_D24X8: D3DFORMAT = D3DFORMAT(77);

/// 24-bit depth and 4-bit stencil surface.
pub const D3DFMT_D24X4S4: D3DFORMAT = D3DFORMAT(79);

/// 16-bit depth surface.
pub const D3DFMT_D16: D3DFORMAT = D3DFORMAT(80);

/// Lockable 32-bit floating-point depth surface.
pub const D3DFMT_D32F_LOCKABLE: D3DFORMAT = D3DFORMAT(82);

/// 24-bit floating-point depth and 8-bit stencil surface.
pub const D3DFMT_D24FS8: D3DFORMAT = D3DFORMAT(83);

/// Two-channel 16-bit float render target used for compact intermediate buffers.
pub const D3DFMT_G16R16F: D3DFORMAT = D3DFORMAT(112);

/// Single-channel 16-bit float render target used for scalar intermediate buffers.
pub const D3DFMT_R16F: D3DFORMAT = D3DFORMAT(111);

/// Four-channel 16-bit float render target used for high-quality color intermediates.
pub const D3DFMT_A16B16G16R16F: D3DFORMAT = D3DFORMAT(113);

/// Four-channel 32-bit float texture format used for exact shader data payloads.
pub const D3DFMT_A32B32G32R32F: D3DFORMAT = D3DFORMAT(116);

/// Magic render-state value that triggers RESZ depth resolve on supported D3D9 drivers.
pub const D3DRESZ_POINT_SIZE: u32 = 0x7FA0_5000;

/// Vendor extension format used to query RESZ depth-resolve support.
pub const D3DFMT_RESZ: D3DFORMAT = D3DFORMAT(make_fourcc(b'R', b'E', b'S', b'Z'));

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

/// Owned `IDirect3DDevice9` reference for a host-published device lifetime.
///
/// Graphics integrations normally borrow the renderer's pointer through
/// [`Device9Ref`]. This owner is for lifecycle coordinators that must keep one
/// balanced COM identity alive while publishing an allocation-free borrowed
/// pointer to serialized render callbacks.
#[derive(Clone, Debug)]
pub struct Device9 {
    inner: IDirect3DDevice9,
}

// Safety: this wrapper only owns a COM reference. Actual D3D calls still have
// to obey the host renderer's threading contract.
unsafe impl Send for Device9 {}

impl Device9 {
    /// Retain a live host-owned device as one owned COM reference.
    ///
    /// # Safety
    ///
    /// `device` must point to a live `IDirect3DDevice9`. The returned owner
    /// performs `QueryInterface`/`AddRef` and releases that reference on drop.
    pub unsafe fn retain_raw(device: *mut c_void) -> Direct3DResult<Self> {
        let ptr = NonNull::new(device).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let borrowed = unsafe { InterfaceRef::<IDirect3DDevice9>::from_raw(ptr) };
        borrowed
            .cast::<IDirect3DDevice9>()
            .map(|inner| Self { inner })
    }

    /// Return the raw retained `IDirect3DDevice9*` identity.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
    }

    /// Borrow the retained identity for a serialized render-thread call.
    pub fn as_ref(&self) -> Device9Ref<'_> {
        // The owned interface keeps the pointer live for this borrow.
        unsafe { Device9Ref::from_raw_void(self.as_raw()) }
            .expect("an owned D3D9 device cannot contain a null interface")
    }
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

    /// Return the adapter, device type, window, and flags used at creation.
    ///
    /// Hardware detection uses the adapter ordinal from this call instead of
    /// assuming adapter zero, which may describe the wrong GPU on multi-adapter
    /// systems.
    pub fn creation_parameters(&self) -> Direct3DResult<DeviceCreationParameters9> {
        let mut parameters = D3DDEVICE_CREATION_PARAMETERS::default();
        unsafe { self.inner.GetCreationParameters(&mut parameters)? };
        Ok(DeviceCreationParameters9 {
            adapter_ordinal: parameters.AdapterOrdinal,
            device_type: parameters.DeviceType,
            focus_window: parameters.hFocusWindow.0 as usize,
            behavior_flags: parameters.BehaviorFlags,
        })
    }

    /// Return the effective capabilities of this created device.
    pub fn device_caps(&self) -> Direct3DResult<D3DCAPS9> {
        let mut caps = D3DCAPS9::default();
        unsafe { self.inner.GetDeviceCaps(&mut caps)? };
        Ok(caps)
    }

    /// Query the primary swap chain's current presentation parameters.
    pub fn presentation_parameters(&self) -> Direct3DResult<D3DPRESENT_PARAMETERS> {
        let swap_chain = unsafe { self.inner.GetSwapChain(0)? };
        let mut parameters = D3DPRESENT_PARAMETERS::default();
        unsafe { swap_chain.GetPresentParameters(&mut parameters)? };
        Ok(parameters)
    }

    /// Release managed resources held by the driver.
    pub fn evict_managed_resources(&self) -> Direct3DResult<()> {
        unsafe { self.inner.EvictManagedResources() }
    }

    /// Get the owning Direct3D object. The returned wrapper owns that COM reference.
    pub fn direct3d(&self) -> Direct3DResult<Direct3D9> {
        unsafe { self.inner.GetDirect3D().map(Direct3D9::new) }
    }

    /// Return whether the live device's adapter and device type expose RESZ.
    ///
    /// The adapter ordinal and `D3DDEVTYPE` come from this device's creation
    /// parameters. This is intentionally different from probing adapter zero
    /// as HAL: hybrid-GPU systems and compatibility layers may create the game
    /// device on another adapter or with another implementation type.
    /// `D3DERR_NOTAVAILABLE` is returned as `Ok(false)`; other Direct3D errors
    /// remain errors so callers can distinguish an unsupported capability from
    /// an invalid or temporarily unavailable query path.
    pub fn supports_resz(&self) -> Direct3DResult<bool> {
        let creation = self.creation_parameters()?;
        let direct3d = self.direct3d()?;
        let mode = direct3d.adapter_display_mode(creation.adapter_ordinal)?;
        direct3d.supports_device_format(
            creation.adapter_ordinal,
            creation.device_type,
            mode.Format,
            D3DUSAGE_RENDERTARGET as u32,
            D3DRTYPE_SURFACE,
            D3DFMT_RESZ,
        )
    }

    /// Return whether the live device can render to and linearly filter a
    /// texture format.
    ///
    /// Render-target and filtering capabilities are independent D3D9 format
    /// queries. Both use this device's creation adapter and device type so the
    /// result remains correct on hybrid-GPU systems and compatibility layers
    /// which do not create the game device as adapter-zero HAL.
    pub fn supports_linearly_filtered_render_target_texture(
        &self,
        format: D3DFORMAT,
    ) -> Direct3DResult<bool> {
        let creation = self.creation_parameters()?;
        let direct3d = self.direct3d()?;
        let mode = direct3d.adapter_display_mode(creation.adapter_ordinal)?;
        for usage in [D3DUSAGE_RENDERTARGET, D3DUSAGE_QUERY_FILTER] {
            if !direct3d.supports_device_format(
                creation.adapter_ordinal,
                creation.device_type,
                mode.Format,
                usage as u32,
                D3DRTYPE_TEXTURE,
                format,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Query the physical Vulkan device selected by DXVK.
    ///
    /// Returns `Ok(None)` when the D3D9 device is not implemented by DXVK.
    /// DXVK exposes the exact physical-device handle through
    /// `ID3D9VkInteropDevice`; querying Vulkan properties from that handle
    /// bypasses application-profile vendor spoofing without enumerating or
    /// guessing among unrelated host GPUs.
    pub fn dxvk_physical_device_properties(
        &self,
    ) -> Direct3DResult<Option<DxvkPhysicalDeviceProperties9>> {
        let interop = match self.inner.cast::<ID3D9VkInteropDevice>() {
            Ok(interop) => interop,
            Err(error) if error.code() == E_NOINTERFACE => return Ok(None),
            Err(error) => return Err(error),
        };

        let mut instance = vk::Instance::null();
        let mut physical_device = vk::PhysicalDevice::null();
        // The successful QueryInterface fixes the vtable ABI and ties both
        // returned handles to this D3D9 device. Requesting the logical Vulkan
        // device is unnecessary for a read-only physical-property query.
        unsafe {
            (interop.vtable().get_vulkan_handles)(
                interop.as_raw(),
                &mut instance,
                &mut physical_device,
                null_mut(),
            );
        }
        if instance == vk::Instance::null() || physical_device == vk::PhysicalDevice::null() {
            return Err(dxvk_identity_error(
                "DXVK returned null Vulkan instance or physical-device handle",
            ));
        }

        query_vulkan_physical_device_properties(instance, physical_device).map(Some)
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

    /// Create a one-level dynamic RGBA32F texture in the default pool.
    ///
    /// The returned owner records the immutable dimensions so subsequent
    /// discard writes validate their payload without querying D3D state in a
    /// render callback. Default-pool lifetime still follows normal D3D9 reset
    /// rules and remains the caller's responsibility.
    pub fn create_dynamic_rgba32f_texture(
        &self,
        width: u32,
        height: u32,
    ) -> Direct3DResult<DynamicRgba32fTexture9> {
        if width == 0 || height == 0 {
            return Err(direct3d_failure());
        }
        let texture = self.create_texture(
            width,
            height,
            1,
            D3DUSAGE_DYNAMIC as u32,
            D3DFMT_A32B32G32R32F,
            D3DPOOL_DEFAULT,
        )?;
        Ok(DynamicRgba32fTexture9 {
            texture,
            width,
            height,
        })
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

    /// Create a one-level default-pool cube texture usable as a render target.
    ///
    /// Cube faces remain individually addressable through
    /// [`CubeTexture9::surface`], while the cached base interface can be bound
    /// directly to a pixel sampler without another `QueryInterface`.
    pub fn create_cube_render_target_texture(
        &self,
        edge_length: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<CubeTexture9> {
        if edge_length == 0 {
            return Err(direct3d_failure());
        }
        let mut texture = None;
        unsafe {
            self.inner.CreateCubeTexture(
                edge_length,
                1,
                D3DUSAGE_RENDERTARGET as u32,
                format,
                D3DPOOL_DEFAULT,
                &mut texture,
                null_mut::<HANDLE>(),
            )?;
        }
        let Some(texture) = texture else {
            return Err(WindowsError::from_hresult(E_POINTER));
        };
        CubeTexture9::new(texture)
    }

    /// Create a default-pool render-target surface with an explicit sample mode.
    ///
    /// A multisampled surface is intentionally not shader-readable. Callers
    /// resolve it into a single-sample texture surface with [`Self::stretch_rect`].
    pub fn create_render_target_surface(
        &self,
        width: u32,
        height: u32,
        format: D3DFORMAT,
        multisample: D3DMULTISAMPLE_TYPE,
        multisample_quality: u32,
        lockable: bool,
    ) -> Direct3DResult<Surface9> {
        if width == 0 || height == 0 {
            return Err(direct3d_failure());
        }
        let mut surface = None;
        unsafe {
            self.inner.CreateRenderTarget(
                width,
                height,
                format,
                multisample,
                multisample_quality,
                lockable,
                &mut surface,
                null_mut::<HANDLE>(),
            )?;
        }
        surface
            .map(Surface9::new)
            .ok_or_else(|| WindowsError::from_hresult(E_POINTER))
    }

    /// Create a default-pool depth/stencil surface with an explicit sample mode.
    pub fn create_depth_stencil_surface(
        &self,
        width: u32,
        height: u32,
        format: D3DFORMAT,
        multisample: D3DMULTISAMPLE_TYPE,
        multisample_quality: u32,
        discard: bool,
    ) -> Direct3DResult<Surface9> {
        if width == 0 || height == 0 {
            return Err(direct3d_failure());
        }
        let mut surface = None;
        unsafe {
            self.inner.CreateDepthStencilSurface(
                width,
                height,
                format,
                multisample,
                multisample_quality,
                discard,
                &mut surface,
                null_mut::<HANDLE>(),
            )?;
        }
        surface
            .map(Surface9::new)
            .ok_or_else(|| WindowsError::from_hresult(E_POINTER))
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

    /// Get an optional auxiliary render target.
    pub fn optional_render_target(&self, index: u32) -> Direct3DResult<Option<Surface9>> {
        match unsafe { self.inner.GetRenderTarget(index) } {
            Ok(surface) => Ok(Some(Surface9::new(surface))),
            Err(err) if err.code() == D3DERR_NOTFOUND => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Return the number of simultaneous render-target slots exposed by the device.
    ///
    /// Direct3D 9 devices always have slot zero. The defensive lower bound keeps
    /// callers safe if a compatibility layer reports a malformed zero value.
    pub fn simultaneous_render_target_count(&self) -> Direct3DResult<u32> {
        let mut caps = D3DCAPS9::default();
        unsafe { self.inner.GetDeviceCaps(&mut caps)? };
        Ok(caps.NumSimultaneousRTs.max(1))
    }

    /// Return whether MRT slots may use render targets with different bit depths.
    ///
    /// Direct3D 9 requires this capability when, for example, one pixel shader
    /// writes FP16 RGBA color and an R16F depth key in the same draw.
    pub fn supports_independent_mrt_bit_depths(&self) -> Direct3DResult<bool> {
        let mut caps = D3DCAPS9::default();
        unsafe { self.inner.GetDeviceCaps(&mut caps)? };
        Ok(caps.PrimitiveMiscCaps & D3DPMISCCAPS_MRTINDEPENDENTBITDEPTHS as u32 != 0)
    }

    /// Set a render target surface.
    pub fn set_render_target(&self, index: u32, surface: &Surface9) -> Direct3DResult<()> {
        unsafe { self.inner.SetRenderTarget(index, surface.as_inner()) }
    }

    /// Unbind an auxiliary render target. Render target zero cannot be null.
    pub fn clear_render_target(&self, index: u32) -> Direct3DResult<()> {
        unsafe {
            self.inner
                .SetRenderTarget(index, Option::<&IDirect3DSurface9>::None)
        }
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

    /// Clear any combination of target, depth, and stencil attachments.
    ///
    /// `flags` is a bitwise combination of `D3DCLEAR_TARGET`,
    /// `D3DCLEAR_ZBUFFER`, and `D3DCLEAR_STENCIL`.
    pub fn clear_attachments(
        &self,
        flags: u32,
        color: u32,
        depth: f32,
        stencil: u32,
    ) -> Direct3DResult<()> {
        let known = D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32;
        if flags == 0 || flags & !known != 0 || !depth.is_finite() {
            return Err(direct3d_failure());
        }
        unsafe { self.inner.Clear(0, null(), flags, color, depth, stencil) }
    }

    /// Begin one explicit D3D9 scene transaction.
    pub fn begin_scene(&self) -> Direct3DResult<()> {
        unsafe { self.inner.BeginScene() }
    }

    /// End a scene that previously completed [`Self::begin_scene`].
    pub fn end_scene(&self) -> Direct3DResult<()> {
        unsafe { self.inner.EndScene() }
    }

    /// Get the current depth-stencil surface.
    ///
    /// The returned wrapper owns its COM reference. `None` means the device has
    /// no depth-stencil surface bound; other Direct3D failures are preserved.
    pub fn depth_stencil_surface(&self) -> Direct3DResult<Option<Surface9>> {
        match unsafe { self.inner.GetDepthStencilSurface() } {
            Ok(surface) => Ok(Some(Surface9::new(surface))),
            Err(err) if err.code() == D3DERR_NOTFOUND => Ok(None),
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

    /// Set the rasterizer scissor rectangle.
    pub fn set_scissor_rect(
        &self,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Direct3DResult<()> {
        let rect = RECT {
            left,
            top,
            right,
            bottom,
        };
        unsafe { self.inner.SetScissorRect(&rect) }
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

    /// Bind a cube texture to a pixel sampler stage.
    pub fn set_cube_texture(&self, stage: u32, texture: &CubeTexture9) -> Direct3DResult<()> {
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

    /// Capture the bounded D3D9 state changed by a RESZ marker transaction.
    ///
    /// Unlike `D3DSBT_ALL`, this retains only the bindings and render states
    /// required by the documented RESZ point-draw sequence.
    pub fn capture_resz_state(&self) -> Direct3DResult<ReszState9> {
        ReszState9::capture(self)
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

    /// Bind or clear a borrowed engine-owned vertex declaration.
    ///
    /// # Safety
    ///
    /// A non-null `declaration` must remain a live
    /// `IDirect3DVertexDeclaration9*` for the duration of the call.
    pub unsafe fn set_raw_vertex_declaration(
        &self,
        declaration: *mut c_void,
    ) -> Direct3DResult<()> {
        if declaration.is_null() {
            return unsafe {
                self.inner
                    .SetVertexDeclaration(Option::<&IDirect3DVertexDeclaration9>::None)
            };
        }
        let declaration = unsafe {
            InterfaceRef::<IDirect3DVertexDeclaration9>::from_raw(NonNull::new_unchecked(
                declaration,
            ))
        };
        unsafe { self.inner.SetVertexDeclaration(declaration) }
    }

    /// Bind a borrowed engine-owned vertex buffer to one stream.
    ///
    /// # Safety
    ///
    /// `buffer` must be a live `IDirect3DVertexBuffer9*` and `offset`/`stride`
    /// must describe the geometry that will be submitted next.
    pub unsafe fn set_raw_stream_source(
        &self,
        stream: u32,
        buffer: *mut c_void,
        offset: u32,
        stride: u32,
    ) -> Direct3DResult<()> {
        let buffer = NonNull::new(buffer).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let buffer = unsafe { InterfaceRef::<IDirect3DVertexBuffer9>::from_raw(buffer) };
        unsafe { self.inner.SetStreamSource(stream, buffer, offset, stride) }
    }

    /// Bind or clear a borrowed engine-owned index buffer.
    ///
    /// # Safety
    ///
    /// A non-null `buffer` must remain a live `IDirect3DIndexBuffer9*` through
    /// the following indexed submission.
    pub unsafe fn set_raw_indices(&self, buffer: *mut c_void) -> Direct3DResult<()> {
        if buffer.is_null() {
            return unsafe {
                self.inner
                    .SetIndices(Option::<&IDirect3DIndexBuffer9>::None)
            };
        }
        let buffer = unsafe {
            InterfaceRef::<IDirect3DIndexBuffer9>::from_raw(NonNull::new_unchecked(buffer))
        };
        unsafe { self.inner.SetIndices(buffer) }
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

    /// Set vertex shader float constants.
    pub fn set_vertex_shader_constant_f(
        &self,
        start_register: u32,
        constants: &[[f32; 4]],
    ) -> Direct3DResult<()> {
        unsafe {
            self.inner.SetVertexShaderConstantF(
                start_register,
                constants.as_ptr().cast::<f32>(),
                constants.len() as u32,
            )
        }
    }
}

type VkGetInstanceProcAddr = unsafe extern "system" fn(
    instance: vk::Instance,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction;
type VkGetPhysicalDeviceProperties = unsafe extern "system" fn(
    physical_device: vk::PhysicalDevice,
    properties: *mut vk::PhysicalDeviceProperties,
);
type VkGetPhysicalDeviceProperties2 = unsafe extern "system" fn(
    physical_device: vk::PhysicalDevice,
    properties: *mut vk::PhysicalDeviceProperties2<'_>,
);

fn query_vulkan_physical_device_properties(
    instance: vk::Instance,
    physical_device: vk::PhysicalDevice,
) -> Direct3DResult<DxvkPhysicalDeviceProperties9> {
    let module = get_module_handle_a(Some("vulkan-1.dll"))
        .or_else(|_| load_system_library_w("vulkan-1.dll"))
        .map_err(|error| dxvk_identity_error(format!("failed to load Vulkan loader: {error}")))?;
    let get_instance_proc_address =
        get_proc_address(module, "vkGetInstanceProcAddr").map_err(|error| {
            dxvk_identity_error(format!(
                "Vulkan loader has no vkGetInstanceProcAddr: {error}"
            ))
        })?;
    let get_instance_proc_address =
        unsafe { FnPtr::<VkGetInstanceProcAddr>::from_raw(get_instance_proc_address) }
            .map_err(|error| {
                dxvk_identity_error(format!("vkGetInstanceProcAddr is invalid: {error}"))
            })?
            .as_fn();

    // Resolve commands through DXVK's own VkInstance. This follows the
    // instance's Vulkan loader dispatch table instead of assuming a separately
    // exported command belongs to the same loader implementation.
    let core_properties =
        unsafe { get_instance_proc_address(instance, c"vkGetPhysicalDeviceProperties".as_ptr()) };
    let core_properties = core_properties.ok_or_else(|| {
        dxvk_identity_error("Vulkan loader returned no vkGetPhysicalDeviceProperties")
    })?;
    // Safety: vkGetInstanceProcAddr returned a non-null pointer for this exact
    // core command name. The alias reproduces the Vulkan system-call ABI.
    let core_properties: VkGetPhysicalDeviceProperties =
        unsafe { core::mem::transmute(core_properties) };
    let mut properties = vk::PhysicalDeviceProperties::default();
    unsafe { core_properties(physical_device, &mut properties) };

    let mut device_uuid = 0;
    let mut driver_name = String::new();
    let mut driver_info = String::new();
    // Core 1.0 properties are sufficient to correct name and PCI identity.
    // Properties2 is optional so older DXVK/Vulkan combinations still work;
    // when present, its output chain adds stable UUID and driver strings
    // without creating a device or enumerating unrelated physical adapters.
    if let Some(properties2) =
        unsafe { get_instance_proc_address(instance, c"vkGetPhysicalDeviceProperties2".as_ptr()) }
    {
        // Safety: the non-null pointer was resolved for the exact Properties2
        // command, whose output ABI is represented by the ash Vulkan types.
        let properties2: VkGetPhysicalDeviceProperties2 =
            unsafe { core::mem::transmute(properties2) };
        let mut id_properties = vk::PhysicalDeviceIDProperties::default();
        let mut driver_properties = vk::PhysicalDeviceDriverProperties::default();
        id_properties.p_next = core::ptr::from_mut(&mut driver_properties).cast();
        let mut extended_properties = vk::PhysicalDeviceProperties2 {
            p_next: core::ptr::from_mut(&mut id_properties).cast(),
            ..Default::default()
        };
        unsafe { properties2(physical_device, &mut extended_properties) };
        properties = extended_properties.properties;
        device_uuid = u128::from_be_bytes(id_properties.device_uuid);
        driver_name = fixed_vk_string(&driver_properties.driver_name);
        driver_info = fixed_vk_string(&driver_properties.driver_info);
    }

    Ok(DxvkPhysicalDeviceProperties9 {
        description: fixed_vk_string(&properties.device_name),
        vendor_id: properties.vendor_id,
        device_id: properties.device_id,
        device_type: properties.device_type.as_raw(),
        api_version: properties.api_version,
        driver_version: properties.driver_version,
        device_uuid,
        driver_name,
        driver_info,
    })
}

fn fixed_vk_string<const N: usize>(bytes: &[c_char; N]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(N);
    let bytes = &bytes[..end];
    // Vulkan device and driver strings are UTF-8. Lossy conversion keeps a
    // malformed third-party driver string bounded and safe for diagnostics.
    String::from_utf8_lossy(unsafe {
        slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len())
    })
    .into_owned()
}

fn dxvk_identity_error(message: impl AsRef<str>) -> Direct3DError {
    Direct3DError::new(E_FAIL, message)
}

/// Create an owned Direct3D 9 interface for explicit adapter enumeration.
///
/// This loads the platform D3D9 runtime on first use. Renderer integrations
/// that already have a device should prefer `Device9Ref::direct3d` so queries
/// are guaranteed to use the same D3D9 implementation as the active device.
pub fn create_direct3d9() -> Direct3DResult<Direct3D9> {
    let inner = unsafe { Direct3DCreate9(D3D_SDK_VERSION) }
        .ok_or_else(|| WindowsError::from_hresult(windows::Win32::Foundation::E_FAIL))?;
    Ok(Direct3D9::new(inner))
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

    /// Return the number of adapters exposed by this D3D9 implementation.
    pub fn adapter_count(&self) -> u32 {
        unsafe { self.inner.GetAdapterCount() }
    }

    /// Return an aligned, owned identifier for one adapter.
    pub fn adapter_identifier(&self, adapter: u32) -> Direct3DResult<AdapterIdentifier9> {
        let mut identifier = D3DADAPTER_IDENTIFIER9::default();
        unsafe {
            self.inner
                .GetAdapterIdentifier(adapter, 0, &mut identifier)?
        };

        // D3DADAPTER_IDENTIFIER9 is packed to four-byte alignment on x86.
        // Reading each non-byte field unaligned avoids forming invalid aligned
        // references and keeps this wrapper sound on the supported game target.
        let driver = unsafe { addr_of!(identifier.Driver).read_unaligned() };
        let description = unsafe { addr_of!(identifier.Description).read_unaligned() };
        let device_name = unsafe { addr_of!(identifier.DeviceName).read_unaligned() };
        let device_identifier = unsafe { addr_of!(identifier.DeviceIdentifier).read_unaligned() };
        Ok(AdapterIdentifier9 {
            driver: fixed_c_string(&driver),
            description: fixed_c_string(&description),
            device_name: fixed_c_string(&device_name),
            driver_version: unsafe { addr_of!(identifier.DriverVersion).read_unaligned() },
            vendor_id: unsafe { addr_of!(identifier.VendorId).read_unaligned() },
            device_id: unsafe { addr_of!(identifier.DeviceId).read_unaligned() },
            subsystem_id: unsafe { addr_of!(identifier.SubSysId).read_unaligned() },
            revision: unsafe { addr_of!(identifier.Revision).read_unaligned() },
            device_identifier: device_identifier.to_u128(),
            whql_level: unsafe { addr_of!(identifier.WHQLLevel).read_unaligned() },
        })
    }

    /// Return capabilities for an adapter and D3D9 device implementation.
    pub fn device_caps(&self, adapter: u32, device_type: D3DDEVTYPE) -> Direct3DResult<D3DCAPS9> {
        let mut caps = D3DCAPS9::default();
        unsafe { self.inner.GetDeviceCaps(adapter, device_type, &mut caps)? };
        Ok(caps)
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

    /// Return whether a format probe is supported.
    ///
    /// `D3DERR_NOTAVAILABLE` is the documented negative capability result.
    /// Other failures are preserved so device loss, invalid parameters, and
    /// compatibility-layer faults cannot be misreported as missing hardware.
    pub fn supports_device_format(
        &self,
        adapter: u32,
        device_type: D3DDEVTYPE,
        adapter_format: D3DFORMAT,
        usage: u32,
        resource_type: D3DRESOURCETYPE,
        check_format: D3DFORMAT,
    ) -> Direct3DResult<bool> {
        match self.check_device_format(
            adapter,
            device_type,
            adapter_format,
            usage,
            resource_type,
            check_format,
        ) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == D3DERR_NOTAVAILABLE => Ok(false),
            Err(error) => Err(error),
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

    /// Check whether the default HAL can blend into a render-target texture.
    pub fn check_default_render_target_blending_support(
        &self,
        format: D3DFORMAT,
    ) -> Direct3DResult<()> {
        let mode = self.adapter_display_mode(D3DADAPTER_DEFAULT)?;
        self.check_device_format(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            mode.Format,
            (D3DUSAGE_RENDERTARGET | D3DUSAGE_QUERY_POSTPIXELSHADER_BLENDING) as u32,
            D3DRTYPE_TEXTURE,
            format,
        )
    }
}

fn fixed_c_string<const N: usize>(bytes: &[i8; N]) -> String {
    let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(N);
    let bytes = &bytes[..length];
    let bytes = unsafe { slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len()) };
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// Description of a borrowed raw two-dimensional D3D texture.
#[derive(Clone, Copy, Debug)]
pub struct RawTexture9Description {
    pub level_zero: D3DSURFACE_DESC,
    pub level_count: u32,
    pub device_identity: usize,
}

/// Inspect an engine-owned `IDirect3DBaseTexture9` without retaining it.
///
/// # Safety
///
/// `texture` must remain a live COM object for the duration of this call.
pub unsafe fn raw_texture_2d_description(
    texture: *mut c_void,
) -> Direct3DResult<RawTexture9Description> {
    let ptr = NonNull::new(texture).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
    let base = unsafe { InterfaceRef::<IDirect3DBaseTexture9>::from_raw(ptr) };
    if unsafe { base.GetType() } != D3DRTYPE_TEXTURE {
        return Err(direct3d_failure());
    }
    let texture = unsafe { InterfaceRef::<IDirect3DTexture9>::from_raw(ptr) };
    let mut level_zero = D3DSURFACE_DESC::default();
    unsafe { texture.GetLevelDesc(0, &mut level_zero)? };
    let device = unsafe { texture.GetDevice()? };
    Ok(RawTexture9Description {
        level_zero,
        level_count: unsafe { texture.GetLevelCount() },
        device_identity: device.as_raw() as usize,
    })
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

    /// Retain an engine-owned raw surface as an owned COM reference.
    ///
    /// # Safety
    ///
    /// `surface` must be a live `IDirect3DSurface9*`.
    pub unsafe fn retain_raw(surface: *mut c_void) -> Direct3DResult<Self> {
        let ptr = NonNull::new(surface).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let surface = unsafe { InterfaceRef::<IDirect3DSurface9>::from_raw(ptr) };
        surface.cast::<IDirect3DSurface9>().map(Self::new)
    }

    /// Return the owning texture when this surface is a texture level.
    pub fn texture_container(&self) -> Direct3DResult<Option<Texture9>> {
        let mut container = null_mut();
        match unsafe {
            self.inner
                .GetContainer(&IDirect3DTexture9::IID, &mut container)
        } {
            Ok(()) if container.is_null() => Ok(None),
            Ok(()) => {
                let texture = unsafe { IDirect3DTexture9::from_raw(container) };
                Texture9::new(texture).map(Some)
            }
            Err(err) if err.code() == D3DERR_NOTFOUND || err.code() == E_NOINTERFACE => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Owned `IDirect3DCubeTexture9` reference with a cached sampler interface.
#[derive(Clone, Debug)]
pub struct CubeTexture9 {
    inner: IDirect3DCubeTexture9,
    base: IDirect3DBaseTexture9,
}

// Safety: this wrapper only owns COM references. Actual resource access must
// still remain on the host renderer's serialized D3D thread.
unsafe impl Send for CubeTexture9 {}

impl CubeTexture9 {
    fn new(inner: IDirect3DCubeTexture9) -> Direct3DResult<Self> {
        let base = inner.cast::<IDirect3DBaseTexture9>()?;
        Ok(Self { inner, base })
    }

    /// Return the wrapped cube-texture interface.
    pub fn as_inner(&self) -> &IDirect3DCubeTexture9 {
        &self.inner
    }

    /// Return the cached base-texture interface accepted by `SetTexture`.
    pub fn as_base_texture(&self) -> &IDirect3DBaseTexture9 {
        &self.base
    }

    /// Return the cached base-texture pointer without transferring ownership.
    pub fn as_raw_base_texture(&self) -> *mut c_void {
        self.base.as_raw()
    }

    /// Acquire one owned render-target surface for `face` and mip `level`.
    pub fn surface(&self, face: D3DCUBEMAP_FACES, level: u32) -> Direct3DResult<Surface9> {
        unsafe { self.inner.GetCubeMapSurface(face, level).map(Surface9::new) }
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

    /// Adopt one owned `IDirect3DTexture9` reference returned through a raw out pointer.
    ///
    /// This is for COM APIs that transfer a successful result reference to the
    /// caller. Unlike [`Self::retain_raw`], it does not first retain the raw
    /// texture pointer. Construction obtains the wrapper's separate base-
    /// texture interface reference through `QueryInterface`; both owned
    /// references are released normally when the wrapper is dropped.
    ///
    /// # Safety
    ///
    /// `texture` must be a live `IDirect3DTexture9` pointer for which the
    /// caller owns one reference. The pointer must not be used to construct a
    /// second owner after this call succeeds.
    pub unsafe fn adopt_raw(texture: *mut c_void) -> Direct3DResult<Self> {
        let texture = NonNull::new(texture).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let inner = unsafe { IDirect3DTexture9::from_raw(texture.as_ptr()) };
        Self::new(inner)
    }

    /// Retain an engine-owned raw texture as an owned COM reference.
    ///
    /// The returned wrapper calls `AddRef` through `QueryInterface`, so it may
    /// outlive the borrowed pointer used to create it. This is intended for
    /// validated renderer resources exposed by the host or another graphics
    /// provider.
    ///
    /// # Safety
    ///
    /// `texture` must point to a live `IDirect3DBaseTexture9` whose concrete
    /// resource is a two-dimensional `IDirect3DTexture9`. This accepts the
    /// base-interface pointer commonly stored by game renderers.
    pub unsafe fn retain_raw(texture: *mut c_void) -> Direct3DResult<Self> {
        let ptr = NonNull::new(texture).ok_or_else(|| WindowsError::from_hresult(E_POINTER))?;
        let borrowed = unsafe { InterfaceRef::<IDirect3DBaseTexture9>::from_raw(ptr) };
        borrowed.cast::<IDirect3DTexture9>().and_then(Self::new)
    }

    /// Return the wrapped Windows binding interface.
    pub fn as_inner(&self) -> &IDirect3DTexture9 {
        &self.inner
    }

    /// Return the cached base texture interface used by `SetTexture`.
    pub fn as_base_texture(&self) -> &IDirect3DBaseTexture9 {
        &self.base
    }

    /// Return the underlying `IDirect3DTexture9` resource pointer.
    pub fn as_raw(&self) -> *mut c_void {
        self.inner.as_raw()
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

    /// Write a tightly packed ARGB image into a matching lockable level-0 texture.
    pub fn write_level0_argb(&self, width: u32, height: u32, pixels: &[u32]) -> Direct3DResult<()> {
        let desc = self.surface_level(0)?.desc()?;
        let pixel_count = width
            .checked_mul(height)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(direct3d_failure)?;
        if desc.Width != width
            || desc.Height != height
            || desc.Format != D3DFMT_A8R8G8B8
            || width == 0
            || height == 0
            || pixels.len() != pixel_count
        {
            return Err(direct3d_failure());
        }
        let row_bytes = usize::try_from(width)
            .ok()
            .and_then(|width| width.checked_mul(size_of::<u32>()))
            .ok_or_else(direct3d_failure)?;

        let mut locked = D3DLOCKED_RECT::default();
        unsafe { self.inner.LockRect(0, &mut locked, null(), 0)? };
        let copy_result = (|| {
            let pitch = usize::try_from(locked.Pitch).map_err(|_| direct3d_failure())?;
            if locked.pBits.is_null() || pitch < row_bytes {
                return Err(direct3d_failure());
            }
            let row_count = height as usize;
            let _destination_span = row_count
                .checked_sub(1)
                .and_then(|last_row| last_row.checked_mul(pitch))
                .and_then(|offset| offset.checked_add(row_bytes))
                .ok_or_else(direct3d_failure)?;
            for (row, source) in pixels.chunks_exact(width as usize).enumerate() {
                let destination_offset = row.checked_mul(pitch).ok_or_else(direct3d_failure)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source.as_ptr().cast::<u8>(),
                        locked.pBits.cast::<u8>().add(destination_offset),
                        row_bytes,
                    );
                }
            }
            Ok(())
        })();
        let unlock_result = unsafe { self.inner.UnlockRect(0) };
        copy_result?;
        unlock_result
    }

    /// Write one ARGB texel into a lockable 1x1 level-0 texture.
    pub fn write_level0_argb_pixel(&self, pixel: u32) -> Direct3DResult<()> {
        self.write_level0_argb(1, 1, &[pixel])
    }
}

/// Owned one-level dynamic RGBA32F texture with query-free discard uploads.
///
/// This wrapper is intentionally narrower than [`Texture9`]. It can only be
/// constructed by [`Device9Ref::create_dynamic_rgba32f_texture`], which fixes
/// its format, usage, pool, mip count, and dimensions. That construction
/// contract makes [`Self::write_discard`] safe without a per-write descriptor
/// query on the render thread.
#[derive(Clone, Debug)]
pub struct DynamicRgba32fTexture9 {
    texture: Texture9,
    width: u32,
    height: u32,
}

impl DynamicRgba32fTexture9 {
    /// Borrow the underlying texture for a D3D sampler binding.
    pub fn texture(&self) -> &Texture9 {
        &self.texture
    }

    /// Replace level zero with one tightly packed RGBA32F payload.
    ///
    /// `D3DLOCK_DISCARD` allows the driver to rename storage instead of
    /// waiting for prior draws that still consume the previous payload. The
    /// input must contain exactly `width * height` texels from construction.
    pub fn write_discard(&self, pixels: &[[f32; 4]]) -> Direct3DResult<()> {
        let pixel_count = self
            .width
            .checked_mul(self.height)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or_else(direct3d_failure)?;
        if pixels.len() != pixel_count {
            return Err(direct3d_failure());
        }
        let row_bytes = usize::try_from(self.width)
            .ok()
            .and_then(|width| width.checked_mul(size_of::<[f32; 4]>()))
            .ok_or_else(direct3d_failure)?;

        let mut locked = D3DLOCKED_RECT::default();
        unsafe {
            self.texture
                .inner
                .LockRect(0, &mut locked, null(), D3DLOCK_DISCARD as u32)?
        };
        let copy_result = (|| {
            let pitch = usize::try_from(locked.Pitch).map_err(|_| direct3d_failure())?;
            if locked.pBits.is_null() || pitch < row_bytes {
                return Err(direct3d_failure());
            }
            let _destination_span = (self.height as usize)
                .checked_sub(1)
                .and_then(|last_row| last_row.checked_mul(pitch))
                .and_then(|offset| offset.checked_add(row_bytes))
                .ok_or_else(direct3d_failure)?;
            for (row, source) in pixels.chunks_exact(self.width as usize).enumerate() {
                let destination_offset = row.checked_mul(pitch).ok_or_else(direct3d_failure)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source.as_ptr().cast::<u8>(),
                        locked.pBits.cast::<u8>().add(destination_offset),
                        row_bytes,
                    );
                }
            }
            Ok(())
        })();
        let unlock_result = unsafe { self.texture.inner.UnlockRect(0) };
        copy_result?;
        unlock_result
    }
}

/// Owned snapshot of the exact D3D9 state changed by a RESZ marker draw.
pub struct ReszState9 {
    fvf: u32,
    declaration: Option<IDirect3DVertexDeclaration9>,
    texture0: Option<IDirect3DBaseTexture9>,
    vertex_shader: Option<IDirect3DVertexShader9>,
    pixel_shader: Option<IDirect3DPixelShader9>,
    stream0: Option<IDirect3DVertexBuffer9>,
    stream0_offset: u32,
    stream0_stride: u32,
    z_enable: u32,
    z_write: u32,
    color_write: u32,
    point_size: u32,
}

impl ReszState9 {
    fn capture(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        let mut fvf = 0;
        unsafe { device.inner.GetFVF(&mut fvf)? };
        let declaration = optional_binding(unsafe { device.inner.GetVertexDeclaration() })?;
        let texture0 = optional_binding(unsafe { device.inner.GetTexture(0) })?;
        let vertex_shader = optional_binding(unsafe { device.inner.GetVertexShader() })?;
        let pixel_shader = optional_binding(unsafe { device.inner.GetPixelShader() })?;
        let mut stream0 = None;
        let mut stream0_offset = 0;
        let mut stream0_stride = 0;
        unsafe {
            device.inner.GetStreamSource(
                0,
                &mut stream0,
                &mut stream0_offset,
                &mut stream0_stride,
            )?;
        }

        Ok(Self {
            fvf,
            declaration,
            texture0,
            vertex_shader,
            pixel_shader,
            stream0,
            stream0_offset,
            stream0_stride,
            z_enable: device.render_state(D3DRS_ZENABLE)?,
            z_write: device.render_state(D3DRS_ZWRITEENABLE)?,
            color_write: device.render_state(D3DRS_COLORWRITEENABLE)?,
            point_size: device.render_state(D3DRS_POINTSIZE)?,
        })
    }

    /// Restore render states before issuing the RESZ marker.
    pub fn restore_render_states(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        let mut result = device.set_render_state(D3DRS_ZENABLE, self.z_enable);
        keep_first_error(
            &mut result,
            device.set_render_state(D3DRS_ZWRITEENABLE, self.z_write),
        );
        keep_first_error(
            &mut result,
            device.set_render_state(D3DRS_COLORWRITEENABLE, self.color_write),
        );
        result
    }

    /// Restore point size and every binding changed by the marker draw.
    pub fn restore_bindings(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        let mut result = device.set_render_state(D3DRS_POINTSIZE, self.point_size);
        keep_first_error(&mut result, unsafe { device.inner.SetFVF(self.fvf) });
        keep_first_error(&mut result, unsafe {
            device.inner.SetVertexDeclaration(self.declaration.as_ref())
        });
        keep_first_error(&mut result, unsafe {
            device.inner.SetTexture(0, self.texture0.as_ref())
        });
        keep_first_error(&mut result, unsafe {
            device.inner.SetVertexShader(self.vertex_shader.as_ref())
        });
        keep_first_error(&mut result, unsafe {
            device.inner.SetPixelShader(self.pixel_shader.as_ref())
        });
        keep_first_error(&mut result, unsafe {
            device.inner.SetStreamSource(
                0,
                self.stream0.as_ref(),
                self.stream0_offset,
                self.stream0_stride,
            )
        });
        result
    }
}

fn optional_binding<T>(result: Direct3DResult<T>) -> Direct3DResult<Option<T>> {
    match result {
        Ok(binding) => Ok(Some(binding)),
        Err(err) if err.code() == E_POINTER || err.code() == D3DERR_NOTFOUND => Ok(None),
        Err(err) => Err(err),
    }
}

fn keep_first_error(result: &mut Direct3DResult<()>, next: Direct3DResult<()>) {
    if result.is_ok() && next.is_err() {
        *result = next;
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
/// Compiler flags that are part of the shader cache contract.
pub const HLSL_COMPILER_FLAGS: u32 =
    D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY | D3DCOMPILE_OPTIMIZATION_LEVEL3;
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
            HLSL_COMPILER_FLAGS,
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
