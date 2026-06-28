/*
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
This module provides a Rust wrapper for wolfCrypt SM2 functionality.
*/

#![cfg(sm2)]

use crate::ecc::ECC;
#[cfg(random)]
use crate::random::RNG;
use crate::sys;

/// An SM2 key backed by a wolfCrypt ECC key.
pub struct SM2 {
    key: ECC,
}

impl SM2 {
    /// SM2 key size in bytes.
    pub const KEY_SIZE: usize = sys::SM2_KEY_SIZE as usize;

    /// Default SM2 certificate signature identity.
    pub const CERT_SIG_ID: &'static [u8] = b"1234567812345678";

    /// wolfCrypt hash type identifier for SM3.
    #[cfg(sm3)]
    pub const HASH_TYPE_SM3: u32 = sys::wc_HashType_WC_HASH_TYPE_SM3;

    /// No ECC operation flags.
    pub const FLAG_NONE: i32 = ECC::FLAG_NONE;

    /// Enable the ECC cofactor flag.
    pub const FLAG_COFACTOR: i32 = ECC::FLAG_COFACTOR;

    /// Enable the ECC decrypt/sign flag.
    pub const FLAG_DEC_SIGN: i32 = ECC::FLAG_DEC_SIGN;

    /// Bind an owned random number generator to this key for ECC operations
    /// that require blinding.
    ///
    /// # Parameters
    ///
    /// * `rng`: The `RNG` struct instance to associate with this `SM2`
    ///   instance.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    #[cfg(random)]
    pub fn set_rng(&mut self, rng: RNG) -> Result<(), i32> {
        self.key.set_rng(rng)
    }

    /// Bind a shared random number generator to this key for ECC operations
    /// that require blinding. Available when the `alloc` feature is enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: The reference-counted `RNG` struct instance to associate with
    ///   this `SM2` instance.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    #[cfg(all(random, feature = "alloc"))]
    pub fn set_shared_rng(&mut self, rng: alloc::rc::Rc<RNG>) -> Result<(), i32> {
        self.key.set_shared_rng(rng)
    }

    /// Generate a new SM2 key using the supplied random number generator.
    ///
    /// # Parameters
    ///
    /// * `rng`: Reference to an `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `flags`: Flags for making the key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 key or Err(e) containing
    /// the wolfSSL library error code value.
    #[cfg(random)]
    pub fn generate(rng: &RNG, flags: i32) -> Result<Self, i32> {
        let key = ECC::new()?;
        let rc = unsafe { sys::wc_ecc_sm2_make_key(rng.wc_rng, key.wc_ecc_key, flags) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self { key })
    }

    /// Import public and private SM2 key pair from DER input buffer.
    ///
    /// The decoded key must use the SM2P256V1 curve. Keys using any other
    /// ECC curve are rejected with `ECC_CURVE_OID_E`.
    ///
    /// # Parameters
    ///
    /// * `der`: DER buffer containing the ECC public and private key pair.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate std;
    /// #[cfg(ecc_curve_sm2p256v1)]
    /// {
    /// use wolfssl_wolfcrypt::sm2::SM2;
    /// use std::fs;
    ///
    /// let key_path = "../../../certs/sm2/client-sm2-priv.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut sm2 = SM2::import_der(&der, None, None).expect("Error with import_der()");
    /// }
    /// ```
    #[cfg(ecc_curve_sm2p256v1)]
    pub fn import_der(
        der: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_der(der, heap, dev_id)?;
        if key.curve_id()? != ECC::SM2P256V1 {
            return Err(sys::wolfCrypt_ErrorCodes_ECC_CURVE_OID_E);
        }
        Ok(Self { key })
    }

    /// Import public SM2 key from DER input buffer.
    ///
    /// The decoded key must use the SM2P256V1 curve. Keys using any other
    /// ECC curve are rejected with `ECC_CURVE_OID_E`.
    ///
    /// # Parameters
    ///
    /// * `der`: DER buffer containing the SM2 public key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate std;
    /// #[cfg(ecc_curve_sm2p256v1)]
    /// {
    /// use wolfssl_wolfcrypt::sm2::SM2;
    /// use std::fs;
    ///
    /// let key_path = "../../../certs/sm2/client-sm2-key.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut sm2 = SM2::import_public_der(&der, None, None).expect("Error with import_public_der()");
    /// }
    /// ```
    #[cfg(ecc_curve_sm2p256v1)]
    pub fn import_public_der(
        der: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_public_der(der, heap, dev_id)?;
        if key.curve_id()? != ECC::SM2P256V1 {
            return Err(sys::wolfCrypt_ErrorCodes_ECC_CURVE_OID_E);
        }
        Ok(Self { key })
    }

    /// Import a public/private SM2 key pair from a buffer containing the raw
    /// private key and a second buffer containing the ANSI X9.63 formatted
    /// public key. This function handles both compressed and uncompressed
    /// keys as long as wolfSSL is built with the HAVE_COMP_KEY build option
    /// enabled.
    ///
    /// The key is imported using the SM2P256V1 curve.
    ///
    /// # Parameters
    ///
    /// * `priv_buf`: Buffer containing the raw private key.
    /// * `pub_buf`: Buffer containing the ANSI X9.63 formatted public key.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_import, ecc_curve_sm2p256v1))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let hash = [0x42u8; 32];
    /// let mut signature = [0u8; 128];
    /// let signature_length = sm2.sign_hash(&hash, &mut signature, &rng).expect("Error with sign_hash()");
    /// let signature = &signature[..signature_length];
    /// let mut d = [0u8; 32];
    /// let d_size = sm2.export_private(&mut d).expect("Error with export_private()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = sm2.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[..x963_size];
    /// let mut key2 = SM2::import_private_key(&d, x963, None, None).expect("Error with import_private_key()");
    /// let valid = key2.verify_hash(&signature, &hash).expect("Error with verify_hash()");
    /// assert_eq!(valid, true);
    /// }
    /// ```
    #[cfg(all(ecc_import, ecc_curve_sm2p256v1))]
    pub fn import_private_key(
        priv_buf: &[u8],
        pub_buf: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_private_key_ex(priv_buf, pub_buf, ECC::SM2P256V1, heap, dev_id)?;
        Ok(Self { key })
    }

    /// Import raw SM2 key from components in hexadecimal ASCII string format.
    ///
    /// The key is imported using the SM2P256V1 curve.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key as null terminated ASCII hex string.
    /// * `qy`: Y component of public key as null terminated ASCII hex string.
    /// * `d`: Private key as null terminated ASCII hex string.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(ecc_import, ecc_curve_sm2p256v1))]
    /// {
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// // ECC key
    /// let qx = b"7a4e287890a1a47ad3457e52f2f76a83ce46cbc947616d0cbaa82323818a793d\0";
    /// let qy = b"eec4084f5b29ebf29c44cce3b3059610922f8b30ea6e8811742ac7238fe87308\0";
    /// let d  = b"8c14b793cb19137e323a6d2e2a870bca2e7a493ec1153b3a95feb8a4873f8d08\0";
    /// let mut key = SM2::import_raw(qx, qy, d, None, None).expect("Error with import_raw()");
    /// assert!(key.check().is_err());
    ///
    /// // SM2 key from `certs/sm2/client-sm2-priv.pem`.
    /// let qx = b"3a1de8cb4bd32e3f4b073fb021fec59ed9ca3a939395761d30d90bf556ed1960\0";
    /// let qy = b"ed014cf6671df1aca8740db277c84938e4ff4cef8d6d87f64ec7f839747070b5\0";
    /// let d  = b"d0a2df497a2ddf02c9ceb7f237020dddfc08b8de14937a532649d5fe02d9f371\0";
    /// let mut key = SM2::import_raw(qx, qy, d, None, None).expect("Error with import_raw()");
    /// assert!(key.check().is_ok());
    /// }
    /// ```
    #[cfg(all(ecc_import, ecc_curve_sm2p256v1))]
    pub fn import_raw(
        qx: &[u8],
        qy: &[u8],
        d: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_raw_ex(qx, qy, d, ECC::SM2P256V1, heap, dev_id)?;
        Ok(Self { key })
    }

    /// Import raw SM2 key from components in binary unsigned integer format.
    ///
    /// The key is imported using the SM2P256V1 curve.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key in binary unsigned integer format.
    /// * `qy`: Y component of public key in binary unsigned integer format.
    /// * `d`: Private key in binary unsigned integer format.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_import, ecc_curve_sm2p256v1))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// sm2.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");
    /// let mut key2 = SM2::import_unsigned(&qx, &qy, &d, None, None).expect("Error with import_unsigned()");
    /// }
    /// ```
    #[cfg(all(ecc_import, ecc_curve_sm2p256v1))]
    pub fn import_unsigned(
        qx: &[u8],
        qy: &[u8],
        d: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_unsigned(qx, qy, d, ECC::SM2P256V1, heap, dev_id)?;
        Ok(Self { key })
    }

    /// Import a public SM2 key from the given buffer containing the key stored
    /// in ANSI X9.63 format. This function handles both compressed and
    /// uncompressed keys, as long as compressed keys are enabled at compile
    /// time with the HAVE_COMP_KEY build option.
    ///
    /// The key is imported using the SM2P256V1 curve.
    ///
    /// # Parameters
    ///
    /// * `din`: Buffer containing the SM2 key encoded in ANSI X9.63 format.
    /// * `heap`: Optional heap hint.
    /// * `dev_id`: Optional device ID to use with crypto callbacks or async hardware.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_import, ecc_curve_sm2p256v1))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let x963_size = sm2.export_x963(&mut x963).expect("Error with export_x963()");
    /// let x963 = &x963[..x963_size];
    /// let _key2 = SM2::import_x963(x963, None, None).expect("Error with import_x963()");
    /// }
    /// ```
    #[cfg(all(ecc_import, ecc_curve_sm2p256v1))]
    pub fn import_x963(
        din: &[u8],
        heap: Option<*mut core::ffi::c_void>,
        dev_id: Option<i32>,
    ) -> Result<Self, i32> {
        let key = ECC::import_x963_ex(din, ECC::SM2P256V1, heap, dev_id)?;
        Ok(Self { key })
    }

    /// Perform basic sanity checks on the SM2 key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(SM2) containing the SM2 struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate std;
    /// #[cfg(random)]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// sm2.check().expect("Error with check()");
    /// }
    /// ```
    pub fn check(&mut self) -> Result<(), i32> {
        self.key.check()
    }

    /// Export SM2 key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_import))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// sm2.export(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len).expect("Error with export()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    pub fn export(
        &mut self,
        qx: &mut [u8],
        qx_len: &mut u32,
        qy: &mut [u8],
        qy_len: &mut u32,
        d: &mut [u8],
        d_len: &mut u32,
    ) -> Result<(), i32> {
        self.key.export(qx, qx_len, qy, qy_len, d, d_len)
    }

    /// Export SM2 key components as either ASCII hexadecimal strings or
    /// in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    /// * `hex`: true to output in ASCII hexadecimal string, false to output
    ///   as binary data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_import))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// let mut d = [0u8; 32];
    /// let mut d_len = 0u32;
    /// sm2.export_ex(&mut qx, &mut qx_len, &mut qy, &mut qy_len, &mut d, &mut d_len, false).expect("Error with export_ex()");
    /// }
    /// ```
    #[cfg(ecc_import)]
    #[allow(clippy::too_many_arguments)]
    pub fn export_ex(
        &mut self,
        qx: &mut [u8],
        qx_len: &mut u32,
        qy: &mut [u8],
        qy_len: &mut u32,
        d: &mut [u8],
        d_len: &mut u32,
        hex: bool,
    ) -> Result<(), i32> {
        self.key.export_ex(qx, qx_len, qy, qy_len, d, d_len, hex)
    }

    /// Export private component from SM2 key in binary unsigned integer form.
    ///
    /// # Parameters
    ///
    /// * `d`: Buffer in which to store private component.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `d`
    /// or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_export))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut d = [0u8; 32];
    /// let d_size = sm2.export_private(&mut d).expect("Error with export_private()");
    /// assert_eq!(d_size, 32);
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_private(&mut self, d: &mut [u8]) -> Result<usize, i32> {
        self.key.export_private(d)
    }

    /// Export public SM2 key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_export))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut qx = [0u8; 32];
    /// let mut qx_len = 0u32;
    /// let mut qy = [0u8; 32];
    /// let mut qy_len = 0u32;
    /// sm2.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len).expect("Error with export_public()");
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_public(
        &mut self,
        qx: &mut [u8],
        qx_len: &mut u32,
        qy: &mut [u8],
        qy_len: &mut u32,
    ) -> Result<(), i32> {
        self.key.export_public(qx, qx_len, qy, qy_len)
    }

    /// Export public key in ANSI X9.63 format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_export))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let _x963_size = sm2.export_x963(&mut x963).expect("Error with export_x963()");
    /// }
    /// ```
    #[cfg(ecc_export)]
    pub fn export_x963(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        self.key.export_x963(dout)
    }

    /// Export public key in ANSI X9.63 compressed format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// #[cfg(all(random, ecc_export, ecc_comp_key))]
    /// {
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE).expect("Error with generate()");
    /// let mut x963 = [0u8; 128];
    /// let _x963_size = sm2.export_x963_compressed(&mut x963).expect("Error with export_x963_compressed()");
    /// }
    /// ```
    #[cfg(all(ecc_export, ecc_comp_key))]
    pub fn export_x963_compressed(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        self.key.export_x963_compressed(dout)
    }

    /// Compute the public component from this key private component.
    ///
    /// # Parameters
    ///
    /// * `rng`: RNG struct used to blind the private key value used in the
    ///   computation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate std;
    /// #[cfg(random)]
    /// {
    /// use std::fs;
    /// use wolfssl_wolfcrypt::random::RNG;
    /// use wolfssl_wolfcrypt::sm2::SM2;
    ///
    /// let rng = RNG::new().expect("Failed to create RNG");
    /// let key_path = "../../../certs/sm2/client-sm2-priv.der";
    /// let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    /// let mut sm2 = SM2::import_der(&der, None, None).expect("Error with import_der()");
    /// sm2.make_pub(Some(&rng)).expect("Error with make_pub()");
    /// }
    /// ```
    #[cfg(random)]
    pub fn make_pub(&mut self, rng: Option<&RNG>) -> Result<(), i32> {
        self.key.make_pub(rng)
    }

    /// Derive a shared secret into the caller-supplied output buffer.
    ///
    /// # Parameters
    ///
    /// * `peer`: Peer `SM2` key containing the public component.
    /// * `out`: Buffer in which to store the computed secret value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `out` or Err(e) containing the wolfSSL library error code value.
    #[cfg(sm2_dh)]
    pub fn shared_secret(&mut self, peer: &mut SM2, out: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = crate::buffer_len_to_u32(out.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_shared_secret(
                self.key.wc_ecc_key,
                peer.key.wc_ecc_key,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Create an SM2 digest for an identity and message.
    ///
    /// # Parameters
    ///
    /// * `id`: Identity associated with the signer.
    /// * `message`: Message to digest.
    /// * `hash_type`: wolfCrypt hash type identifier.
    /// * `out`: Buffer in which to store the digest.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    #[cfg(sm2_digest)]
    pub fn create_digest(
        &mut self,
        id: &[u8],
        message: &[u8],
        hash_type: u32,
        out: &mut [u8],
    ) -> Result<(), i32> {
        let id_len = u16::try_from(id.len()).map_err(|_| sys::wolfCrypt_ErrorCodes_BUFFER_E)?;
        let message_len = crate::buffer_len_to_i32(message.len())?;
        let out_len = crate::buffer_len_to_i32(out.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_create_digest(
                id.as_ptr(),
                id_len,
                message.as_ptr(),
                message_len,
                hash_type as sys::wc_HashType,
                out.as_mut_ptr(),
                out_len,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign a hash with this SM2 key and return the DER signature length.
    ///
    /// # Parameters
    ///
    /// * `hash`: Message digest to sign.
    /// * `signature`: Buffer in which to store the DER-encoded signature.
    /// * `rng`: Random number generator used while signing.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `signature` or Err(e) containing the wolfSSL library error code value.
    #[cfg(all(sm2_sign, random))]
    pub fn sign_hash(
        &mut self,
        hash: &[u8],
        signature: &mut [u8],
        rng: &RNG,
    ) -> Result<usize, i32> {
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut signature_len = crate::buffer_len_to_u32(signature.len())?;
        let rc = unsafe {
            sys::wc_ecc_sm2_sign_hash(
                hash.as_ptr(),
                hash_len,
                signature.as_mut_ptr(),
                &mut signature_len,
                rng.wc_rng,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_len as usize)
    }

    /// Verify a DER-encoded SM2 signature against a hash.
    ///
    /// # Parameters
    ///
    /// * `signature`: DER-encoded SM2 signature to verify.
    /// * `hash`: Message digest associated with the signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(true) for a valid signature, Ok(false) for an invalid
    /// signature, or Err(e) containing the wolfSSL library error code value.
    #[cfg(sm2_verify)]
    pub fn verify_hash(&mut self, signature: &[u8], hash: &[u8]) -> Result<bool, i32> {
        let signature_len = crate::buffer_len_to_u32(signature.len())?;
        let hash_len = crate::buffer_len_to_u32(hash.len())?;
        let mut valid = 0;
        let rc = unsafe {
            sys::wc_ecc_sm2_verify_hash(
                signature.as_ptr(),
                signature_len,
                hash.as_ptr(),
                hash_len,
                &mut valid,
                self.key.wc_ecc_key,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(valid != 0)
    }
}
