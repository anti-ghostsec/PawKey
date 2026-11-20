//! Keyfiles: files whose contents are needed, as well as the password, to
//! open the vault. The same scheme as Enclave's and PurrDroid's: a keyfile is
//! hashed with SHA-512 (all of it) and the hash goes into Argon2id as its
//! secret input, so the password alone opens nothing and neither does the
//! keyfile.
//!
//! Several can be given, in any order. A folder counts as every file
//! directly in it. With exactly one keyfile the secret is that file's
//! SHA-512; with more, it's the SHA-512 of their hashes, sorted.
//!
//! Any file will do, as long as it never changes by a single byte.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// What the keyfiles add to the password: Argon2id's secret input.
pub type Secret = Zeroizing<[u8; 64]>;

fn hash_file(path: &Path) -> io::Result<[u8; 64]> {
    let mut f = File::open(path).map_err(|e| io::Error::new(e.kind(), format!("keyfile {}: {e}", path.display())))?;
    let mut h = Sha512::new();
    let mut buf = Zeroizing::new(vec![0u8; 1 << 16]);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// The files `paths` stand for: files as they are, folders as the files
/// directly in them.
pub fn expand(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        let meta = fs::metadata(p).map_err(|e| io::Error::new(e.kind(), format!("keyfile {}: {e}", p.display())))?;
        if meta.is_dir() {
            let mut inside: Vec<PathBuf> = fs::read_dir(p)?.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_file()).collect();
            inside.sort();
            if inside.is_empty() {
                return Err(io::Error::other(format!("the keyfile folder {} has no files in it", p.display())));
            }
            out.extend(inside);
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}

/// The secret for these keyfiles, or `None` when there are none.
pub fn secret(paths: &[PathBuf]) -> io::Result<Option<Secret>> {
    let files = expand(paths)?;
    let mut hashes = Vec::with_capacity(files.len());
    for f in &files {
        hashes.push(Zeroizing::new(hash_file(f)?));
    }
    Ok(match hashes.len() {
        0 => None,
        1 => Some(Zeroizing::new(*hashes[0])),
        _ => {
            hashes.sort_by(|a, b| a[..].cmp(&b[..]));
            let mut h = Sha512::new();
            h.update(b"pawkey keyfiles v1");
            for x in &hashes {
                h.update(&x[..]);
            }
            Some(Zeroizing::new(h.finalize().into()))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_many_folders_and_order() {
        let dir = std::env::temp_dir().join(format!("pawkey-keyfiles-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("folder")).unwrap();
        let (a, b) = (dir.join("a"), dir.join("folder/b"));
        fs::write(&a, b"first keyfile").unwrap();
        fs::write(&b, b"second keyfile").unwrap();

        assert!(secret(&[]).unwrap().is_none());
        let one = secret(&[a.clone()]).unwrap().unwrap();
        assert_eq!(&one[..], &Sha512::digest(b"first keyfile")[..]);
        let ab = secret(&[a.clone(), b.clone()]).unwrap().unwrap();
        let ba = secret(&[dir.join("folder"), a.clone()]).unwrap().unwrap();
        assert_eq!(&ab[..], &ba[..]);
        assert_ne!(&ab[..], &one[..]);
        fs::write(&a, b"first keyfilE").unwrap();
        assert_ne!(&secret(&[a.clone()]).unwrap().unwrap()[..], &one[..]);
        assert!(secret(&[dir.join("missing")]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
