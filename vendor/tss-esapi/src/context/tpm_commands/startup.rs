// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::StartupType,
    tss2_esys::{Esys_Shutdown, Esys_Startup},
    Context, Error, Result,
};
use log::error;

impl Context {
    /// Send a TPM2_STARTUP command to the TPM
    pub fn startup(&mut self, startup_type: StartupType) -> Result<()> {
        let ret = unsafe { Esys_Startup(self.mut_context(), startup_type.into()) };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error while starting up TPM: {}", ret);
            Err(ret)
        }
    }

    /// Send a TPM2_SHUTDOWN command to the TPM
    pub fn shutdown(&mut self, shutdown_type: StartupType) -> Result<()> {
        let ret = unsafe {
            Esys_Shutdown(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                shutdown_type.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error while shutting down TPM: {}", ret);
            Err(ret)
        }
    }
}
