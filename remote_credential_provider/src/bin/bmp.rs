use std::time::SystemTime;

use windows::Win32::{
    Graphics::Gdi::{
        HBITMAP,
        GetDC,
        ReleaseDC,
        CreateCompatibleDC,
        SelectObject,
        SRCCOPY,
        BitBlt,
        DeleteDC,
        DeleteObject
    },
    Foundation::E_INVALIDARG
};
use windows::core::Result;
use helpers::get_tile_image;

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