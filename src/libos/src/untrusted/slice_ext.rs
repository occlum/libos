/// Extension traits for slices
use super::*;
use std::ptr;

/// An extension trait for slice to get its _const_ pointer and length.
///
/// If the length is zero, then the pointer is null. This trait is handy when
/// it comes to converting slices to pointers and lengths for OCalls.
pub trait SliceAsPtrAndLen<T> {
    fn as_ptr_and_len(&self) -> (*const T, usize);
}

impl<T> SliceAsPtrAndLen<T> for Option<&[T]> {
    fn as_ptr_and_len(&self) -> (*const T, usize) {
        match self {
            Some(self_slice) => self_slice.as_ptr_and_len(),
            None => (std::ptr::null(), 0),
        }
    }
}

impl<T> SliceAsPtrAndLen<T> for Option<&mut [T]> {
    fn as_ptr_and_len(&self) -> (*const T, usize) {
        match self {
            Some(self_slice) => self_slice.as_ptr_and_len(),
            None => (std::ptr::null(), 0),
        }
    }
}

impl<T> SliceAsPtrAndLen<T> for &[T] {
    fn as_ptr_and_len(&self) -> (*const T, usize) {
        if self.len() > 0 {
            (self.as_ptr(), self.len())
        } else {
            (ptr::null(), 0)
        }
    }
}

impl<T> SliceAsPtrAndLen<T> for &mut [T] {
    fn as_ptr_and_len(&self) -> (*const T, usize) {
        if self.len() > 0 {
            (self.as_ptr(), self.len())
        } else {
            (ptr::null(), 0)
        }
    }
}

/// An extension trait for slice to get its _mutable_ pointer and length.
///
/// If the length is zero, then the pointer is null. This trait is handy when
/// it comes to converting slices to pointers and lengths for OCalls.
pub trait SliceAsMutPtrAndLen<T> {
    fn as_mut_ptr_and_len(&mut self) -> (*mut T, usize);
}

impl<T> SliceAsMutPtrAndLen<T> for Option<&mut [T]> {
    fn as_mut_ptr_and_len(&mut self) -> (*mut T, usize) {
        match self {
            Some(self_slice) => self_slice.as_mut_ptr_and_len(),
            None => (std::ptr::null_mut(), 0),
        }
    }
}

impl<T> SliceAsMutPtrAndLen<T> for &mut [T] {
    fn as_mut_ptr_and_len(&mut self) -> (*mut T, usize) {
        if self.len() > 0 {
            (self.as_mut_ptr(), self.len())
        } else {
            (ptr::null_mut(), 0)
        }
    }
}

mod tests {
    use super::*;

    #[occlum_test]
    fn test_empty_slice_ext() {
        let empty_vec: Vec<u32> = Vec::new();
        let empty_slice: &[u32] = &empty_vec;
        assert_eq!(empty_slice.as_ptr_and_len(), (std::ptr::null(), 0));
        assert_eq!(Some(empty_slice).as_ptr_and_len(), (std::ptr::null(), 0));
    }

    #[occlum_test]
    fn test_none_slice_ext() {
        assert_eq!(
            Option::<&[u8]>::None.as_ptr_and_len(),
            (std::ptr::null(), 0)
        );
    }
}
