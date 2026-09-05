// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Module that contains the different types of handles
//! that the ESAPI and the TPM uses in order to provide
//! access to objects that was or has been created.

// ///////////////////////////////////////////////////////
// ESYS Handles
// ///////////////////////////////////////////////////////
pub use handle::auth::AuthHandle;
pub use handle::key::KeyHandle;
pub use handle::nv_index::NvIndexHandle;
pub use handle::object::ObjectHandle;
pub use handle::pcr::PcrHandle;
pub use handle::session::SessionHandle;
pub(crate) mod handle_conversion {
    pub(crate) use super::handle::conversions::*;
}
mod handle;
// ///////////////////////////////////////////////////////
// TPM Handles
// ///////////////////////////////////////////////////////
pub use tpm::attached_component::AttachedComponentTpmHandle;
pub use tpm::hmac_session::HmacSessionTpmHandle;
pub use tpm::loaded_session::LoadedSessionTpmHandle;
pub use tpm::nv_index::NvIndexTpmHandle;
pub use tpm::pcr::PcrTpmHandle;
pub use tpm::permanent::PermanentTpmHandle;
pub use tpm::persistent::PersistentTpmHandle;
pub use tpm::policy_session::PolicySessionTpmHandle;
pub use tpm::saved_session::SavedSessionTpmHandle;
pub use tpm::transient::TransientTpmHandle;
pub use tpm::TpmHandle;
mod tpm;
