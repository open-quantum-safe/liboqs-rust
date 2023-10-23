//! Defines macros to implement buffers for public/private keys

/// Implements a buffer for cryptographic objects
#[macro_export]
macro_rules! newtype_buffer {
    ($name: ident, $name_ref: ident) => {
        /// New owned buffer
        ///
        /// Construct the reference version of this type through the algorithm API functions.
        ///
        /// Optional support for `serde` if that feature is enabled.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        pub struct $name {
            bytes: Vec<u8>,
        }

        impl $name {
            /// Obtain the contained vector
            pub fn into_vec(self) -> Vec<u8> {
                self.bytes
            }
        }

        /// Reference version of this type.
        ///
        /// Allows for copy-less usage
        /// Construct it through the algorithm API functions
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name_ref<'a> {
            bytes: &'a [u8],
        }

        impl<'a> $name_ref<'a> {
            /// Construct a new container around this reference version
            fn new(bytes: &'a [u8]) -> $name_ref<'a> {
                $name_ref { bytes }
            }

            /// Clone this into the owned variant
            pub fn to_owned(self) -> $name {
                $name {
                    bytes: self.bytes.to_vec(),
                }
            }
        }

        impl<'a> From<&'a $name> for $name_ref<'a> {
            fn from(buf: &'a $name) -> $name_ref<'a> {
                $name_ref::new(&buf.bytes)
            }
        }

        impl<'a> From<&'a $name_ref<'a>> for $name_ref<'a> {
            fn from(buf: &'a $name_ref) -> $name_ref<'a> {
                *buf
            }
        }

        impl<'a> core::ops::Deref for $name_ref<'a> {
            type Target = [u8];
            fn deref(&self) -> &Self::Target {
                &self.bytes
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.bytes.as_ref()
            }
        }

        impl $name {
            /// Length in bytes
            #[allow(clippy::len_without_is_empty)]
            pub fn len(&self) -> usize {
                self.bytes.len()
            }
        }
    };
}

#[cfg(test)]
mod test {
    use alloc::vec;
    use alloc::vec::Vec;

    // necessary for newtype_buffer call
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    newtype_buffer!(TestBuf, TestBufRef);

    #[test]
    fn test_get_reference() {
        let buf = TestBuf {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(buf.bytes.as_ref() as &[u8], buf.as_ref());
    }

    #[test]
    fn test_len() {
        let buf = TestBuf {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(buf.len(), buf.bytes.len());
    }

    #[test]
    fn test_into_vec() {
        let buf = TestBuf {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(buf.into_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn test_to_owned() {
        let bytes = vec![1, 2, 3];
        let refbuf = TestBufRef::new(bytes.as_ref());
        let buf = TestBuf {
            bytes: bytes.clone(),
        };
        assert_eq!(refbuf.to_owned(), buf)
    }
}
