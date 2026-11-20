//! Reading setup QR codes from a picture (a screenshot, a saved image).

/// The text of every QR code found in a greyscale picture, one byte per
/// pixel, `width * height` of them, row by row.
pub fn decode_grey(width: usize, height: usize, grey: &[u8]) -> Vec<String> {
    if width == 0 || height == 0 || grey.len() < width * height {
        return Vec::new();
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| grey[y * width + x]);
    img.detect_grids().into_iter().filter_map(|g| g.decode().ok().map(|(_, text)| text)).collect()
}

/// Greyscale from 8-bit B, G, R, A pixels (alpha premultiplied, as GDK hands
/// them out). Transparent counts as white, the way it's usually shown.
pub fn grey_from_bgra_premultiplied(bgra: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(width * height);
    for y in 0..height {
        let row = &bgra[y * stride..y * stride + width * 4];
        for p in row.chunks_exact(4) {
            let (b, g, r, a) = (p[0] as u32, p[1] as u32, p[2] as u32, p[3] as u32);
            let l = (299 * r + 587 * g + 114 * b) / 1000 + (255 - a);
            out.push(l.min(255) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_setup_code() {
        let uri = "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
        let (n, scale, quiet) = (code.width(), 4, 4);
        let side = (n + 2 * quiet) * scale;
        let colors = code.to_colors();
        let mut bgra = vec![255u8; side * side * 4];
        for y in 0..side {
            for x in 0..side {
                let (mx, my) = ((x / scale).wrapping_sub(quiet), (y / scale).wrapping_sub(quiet));
                if mx < n && my < n && colors[my * n + mx] == qrcode::Color::Dark {
                    bgra[(y * side + x) * 4..][..3].fill(0);
                }
            }
        }
        let grey = grey_from_bgra_premultiplied(&bgra, side, side, side * 4);
        assert_eq!(decode_grey(side, side, &grey), vec![uri.to_string()]);
        assert!(decode_grey(side, side, &vec![255; side * side]).is_empty());
    }
}
