// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::{Digest, SensitiveData},
    tss2_esys::{Esys_GetRandom, Esys_StirRandom},
    Context, Error, Result, WrapperErrorKind as ErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Get a number of random bytes from the TPM and return them.
    ///
    /// # Errors
    /// * if converting `num_bytes` to `u16` fails, a `WrongParamSize` will be returned
    pub fn get_random(&mut self, num_bytes: usize) -> Result<Digest> {
        let mut random_bytes_ptr = null_mut();
        let ret = unsafe {
            Esys_GetRandom(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                num_bytes
                    .try_into()
                    .map_err(|_| Error::local_error(ErrorKind::WrongParamSize))?,
                &mut random_bytes_ptr,
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Digest::try_from(Context::ffi_data_to_owned(random_bytes_ptr))
        } else {
            error!("Error in getting random bytes: {}", ret);
            Err(ret)
        }
    }

    /// Add additional information into the TPM RNG state
    pub fn stir_random(&mut self, in_data: SensitiveData) -> Result<()> {
        let ret = unsafe {
            Esys_StirRandom(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &in_data.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error stirring random: {}", ret);
            Err(ret)
        }
    }
}
