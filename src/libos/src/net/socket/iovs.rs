//! I/O vectors

use super::*;
use crate::untrusted::SliceAsPtrAndLen;
use std::iter::Iterator;

/// A memory safe, immutable version of C iovec array
pub struct Iovs<'a> {
    iovs: Vec<&'a [u8]>,
}

impl<'a> Iovs<'a> {
    pub fn new(slices: Vec<&'a [u8]>) -> Iovs {
        Self { iovs: slices }
    }

    pub fn as_slices(&self) -> &[&[u8]] {
        &self.iovs[..]
    }

    pub fn total_bytes(&self) -> usize {
        self.iovs.iter().map(|s| s.len()).sum()
    }
}

/// A memory safe, mutable version of C iovec array
pub struct IovsMut<'a> {
    iovs: Vec<&'a mut [u8]>,
}

impl<'a> IovsMut<'a> {
    pub fn new(slices: Vec<&'a mut [u8]>) -> Self {
        Self { iovs: slices }
    }

    pub fn as_slices<'b>(&'b self) -> &'b [&'a [u8]] {
        let slices_mut: &'b [&'a mut [u8]] = &self.iovs[..];
        // We are "downgrading" _mutable_ slices to _immutable_ ones. It should be
        // safe to do this transmute
        unsafe { std::mem::transmute(slices_mut) }
    }

    pub fn as_slices_mut<'b>(&'b mut self) -> &'b mut [&'a mut [u8]] {
        &mut self.iovs[..]
    }

    pub fn total_bytes(&self) -> usize {
        self.iovs.iter().map(|s| s.len()).sum()
    }

    /// Copy as many bytes from an u8 iterator as possible
    pub fn copy_from_iter<'b, T>(&mut self, src_iter: &mut T) -> usize
    where
        T: Iterator<Item = &'b u8>,
    {
        let mut bytes_copied = 0;
        let mut dst_iter = self
            .as_slices_mut()
            .iter_mut()
            .flat_map(|mut slice| slice.iter_mut());
        while let (Some(mut d), Some(s)) = (dst_iter.next(), src_iter.next()) {
            *d = *s;
            bytes_copied += 1;
        }
        bytes_copied
    }
}

/// An extention trait that converts slice to libc::iovec
pub trait SliceAsLibcIovec {
    fn as_libc_iovec(&self) -> libc::iovec;
}

impl SliceAsLibcIovec for &[u8] {
    fn as_libc_iovec(&self) -> libc::iovec {
        let (iov_base, iov_len) = self.as_ptr_and_len();
        let iov_base = iov_base as *mut u8 as *mut c_void;
        libc::iovec { iov_base, iov_len }
    }
}

impl SliceAsLibcIovec for &mut [u8] {
    fn as_libc_iovec(&self) -> libc::iovec {
        let (iov_base, iov_len) = self.as_ptr_and_len();
        let iov_base = iov_base as *mut u8 as *mut c_void;
        libc::iovec { iov_base, iov_len }
    }
}

mod tests {
    use super::*;

    #[occlum_test]
    fn test_iov() {
        let matrix: Vec<Vec<u8>> = vec![vec![0, 1, 2], vec![1, 2, 3], vec![2, 3, 4]];
        let slices: Vec<&[u8]> = matrix.iter().map(|s| &s[..]).collect();
        let iovs = Iovs::new(slices);
        assert_eq!(iovs.total_bytes(), 9);
        assert_eq!(
            iovs.as_slices()
                .iter()
                .map(|s| s.to_vec())
                .flatten()
                .collect::<Vec<u8>>(),
            &[0, 1, 2, 1, 2, 3, 2, 3, 4]
        );
    }
}
