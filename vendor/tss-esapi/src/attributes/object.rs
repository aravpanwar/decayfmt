use crate::{tss2_esys::TPMA_OBJECT, Result};
use bitfield::bitfield;

bitfield! {
    /// Bitfield representing the object attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct ObjectAttributes(TPMA_OBJECT);
    impl Debug;
    // Object attribute flags
    pub fixed_tpm, _: 1;
    _, set_fixed_tpm: 1;
    pub st_clear, _: 2;
    _, set_st_clear: 2;
    pub fixed_parent, _: 4;
    _, set_fixed_parent: 4;
    pub sensitive_data_origin, _: 5;
    _, set_sensitive_data_origin: 5;
    pub user_with_auth, _: 6;
    _, set_user_with_auth: 6;
    pub admin_with_policy, _: 7;
    _, set_admin_with_policy: 7;
    pub no_da, _: 10;
    _, set_no_da: 10;
    pub encrypted_duplication, _: 11;
    _, set_encrypted_duplication: 11;
    pub restricted, _: 16;
    _, set_restricted: 16;
    pub decrypt, _: 17;
    _, set_decrypt: 17;
    pub sign_encrypt, _: 18;
    _, set_sign_encrypt: 18;
    pub x509_sign, _: 19;
    _, set_x509_sign: 19;
}

impl ObjectAttributes {
    /// Function for creating attributes for a
    /// fixed parent key object.
    pub fn new_fixed_parent_key() -> Self {
        let mut attrs = ObjectAttributes(0);
        attrs.set_fixed_tpm(true);
        attrs.set_fixed_parent(true);
        attrs.set_sensitive_data_origin(true);
        attrs.set_user_with_auth(true);
        attrs.set_decrypt(true);
        attrs.set_restricted(true);
        attrs
    }

    /// Function for creating attributes for
    /// a fixed signing key object.
    pub fn new_fixed_signing_key() -> Self {
        let mut attrs = ObjectAttributes(0);
        attrs.set_fixed_tpm(true);
        attrs.set_fixed_parent(true);
        attrs.set_sensitive_data_origin(true);
        attrs.set_user_with_auth(true);
        attrs.set_sign_encrypt(true);
        attrs
    }

    /// Get a builder for the structure
    pub const fn builder() -> ObjectAttributesBuilder {
        ObjectAttributesBuilder::new()
    }
}

impl From<ObjectAttributes> for TPMA_OBJECT {
    fn from(object_attributes: ObjectAttributes) -> Self {
        object_attributes.0
    }
}

impl From<TPMA_OBJECT> for ObjectAttributes {
    fn from(tpma_object: TPMA_OBJECT) -> Self {
        ObjectAttributes(tpma_object)
    }
}

/// A builder for [ObjectAttributes]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ObjectAttributesBuilder {
    object_attributes: ObjectAttributes,
}

impl ObjectAttributesBuilder {
    /// Creates an new [ObjectAttributes] builder.
    pub const fn new() -> Self {
        ObjectAttributesBuilder {
            object_attributes: ObjectAttributes(0),
        }
    }

    /// Controls the `fixed tpm` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_fixed_tpm(mut self, set: bool) -> Self {
        self.object_attributes.set_fixed_tpm(set);
        self
    }

    /// Controls the `st clear` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_st_clear(mut self, set: bool) -> Self {
        self.object_attributes.set_st_clear(set);
        self
    }

    /// Controls the `fixed parent` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_fixed_parent(mut self, set: bool) -> Self {
        self.object_attributes.set_fixed_parent(set);
        self
    }

    /// Controls the `sensitive data origin` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_sensitive_data_origin(mut self, set: bool) -> Self {
        self.object_attributes.set_sensitive_data_origin(set);
        self
    }

    /// Controls the `user with auth` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_user_with_auth(mut self, set: bool) -> Self {
        self.object_attributes.set_user_with_auth(set);
        self
    }

    /// Controls the `admin with policy` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_admin_with_policy(mut self, set: bool) -> Self {
        self.object_attributes.set_admin_with_policy(set);
        self
    }

    /// Controls the `no da` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_no_da(mut self, set: bool) -> Self {
        self.object_attributes.set_no_da(set);
        self
    }

    /// Controls the `encrypted duplication` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_encrypted_duplication(mut self, set: bool) -> Self {
        self.object_attributes.set_encrypted_duplication(set);
        self
    }

    /// Controls the `restricted` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_restricted(mut self, set: bool) -> Self {
        self.object_attributes.set_restricted(set);
        self
    }

    /// Controls the `decrypt` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_decrypt(mut self, set: bool) -> Self {
        self.object_attributes.set_decrypt(set);
        self
    }

    /// Controls the `sign/encrypt` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_sign_encrypt(mut self, set: bool) -> Self {
        self.object_attributes.set_sign_encrypt(set);
        self
    }

    /// Controls the `X509 sign` attribute
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the attribute should have the value SET.
    ///   `false`indicates that the attribute should have the value CLEAR.
    pub fn with_x509_sign(mut self, set: bool) -> Self {
        self.object_attributes.set_x509_sign(set);
        self
    }

    /// Builds the nv index attributes.
    ///
    /// # Errors
    /// Returns an error if some attributes are missing
    /// or are in conflict with each other.
    pub fn build(self) -> Result<ObjectAttributes> {
        Ok(self.object_attributes)
    }
}

impl Default for ObjectAttributesBuilder {
    fn default() -> Self {
        ObjectAttributesBuilder::new()
    }
}
