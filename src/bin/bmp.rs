use std::{ffi::c_void, ptr, time::SystemTime};

use windows::Win32::{Graphics::Gdi::{HBITMAP, BITMAPINFOHEADER, BI_RGB, GetDC, CreateDIBSection, DIB_RGB_COLORS, BITMAPINFO, RGBQUAD, SetDIBits, ReleaseDC, CreateCompatibleDC, SelectObject, SRCCOPY, BitBlt, DeleteDC, DeleteObject, BITMAPFILEHEADER}, Foundation::{E_INVALIDARG, E_NOTIMPL}};
use windows::core::Result;

const TILE_IMAGE: &[u8; 49206] = include_bytes!("../tileimage.bmp");

// Siginificant help from
// https://github.com/rust-windowing/winit-blit/blob/master/src/platform_impl/windows/mod.rs
// https://stackoverflow.com/questions/2886831/win32-c-c-load-image-from-memory-buffer
// https://stackoverflow.com/questions/67765151/my-windows-rs-script-doesnt-render-bitmap-or-doesnt-create-one-but-doesnt-c
fn get_tile_image() -> Result<HBITMAP> {
    const BMPFHSZ: usize = std::mem::size_of::<BITMAPFILEHEADER>();
    const BMPIHSZ: usize = std::mem::size_of::<BITMAPINFOHEADER>();
    const RGBQSZ: usize = std::mem::size_of::<RGBQUAD>();
    unsafe {
        let bmpfh = std::mem::transmute_copy::<[u8; BMPFHSZ], BITMAPFILEHEADER>(TILE_IMAGE[0..BMPFHSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let bmpih = std::mem::transmute_copy::<[u8; BMPIHSZ], BITMAPINFOHEADER>(TILE_IMAGE[BMPFHSZ..BMPFHSZ+BMPIHSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let rgb = std::mem::transmute_copy::<[u8;RGBQSZ], RGBQUAD>(TILE_IMAGE[BMPFHSZ+BMPIHSZ..BMPFHSZ+BMPIHSZ+RGBQSZ].try_into().map_err(|_| E_INVALIDARG)?);
        let bmpi = BITMAPINFO {
            bmiColors: [rgb],
            bmiHeader: bmpih
        };
        let tile = &TILE_IMAGE[bmpfh.bfOffBits as usize..] as *const _ as *const c_void;
        let dib_section = CreateDIBSection(None, &bmpi, DIB_RGB_COLORS, ptr::null_mut(), None, 0)?;
        SetDIBits(None, dib_section, 0, bmpih.biHeight as u32, tile, &bmpi, DIB_RGB_COLORS);
        Ok(dib_section)
    }
}

pub fn display_bitmap(handle: HBITMAP) -> Result<()> {
    unsafe {
        let dc_src = CreateCompatibleDC(None);
        let bmp_prev = SelectObject(dc_src, handle);
        let dc_dst = GetDC(None);
        let t = SystemTime::now();
        while SystemTime::now().duration_since(t).map_err(|_| E_INVALIDARG)?.as_secs() < 10 {
            BitBlt(dc_dst, 0, 0, 128, 128, dc_src, 0, 0, SRCCOPY);
        }
        ReleaseDC(None, dc_dst);
        SelectObject(dc_src, bmp_prev);
        DeleteDC(dc_src);
        DeleteObject(handle);
        
    }
    Ok(())
}

fn main() -> Result<()> {
    let bmp = get_tile_image()?;
    display_bitmap(bmp)

}