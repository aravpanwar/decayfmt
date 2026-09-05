use crate::tss2_esys::TPMA_SESSION;
use bitfield::bitfield;

// SESSION ATTRIBUTES

bitfield! {
    /// Bitfield representing the session attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct SessionAttributes(TPMA_SESSION);
    impl Debug;

    _, set_continue_session: 0;
    pub continue_session, _: 0;
    _, set_audit_exclusive: 1;
    pub audit_exclusive, _: 1;
    _, set_audit_reset: 2;
    pub audit_reset, _: 2;
    // Reserved 3,4 (Shall be clear)
    _, set_decrypt: 5;
    pub decrypt, _: 5;
    _, set_encrypt: 6;
    pub encrypt, _: 6;
    _, set_audit: 7;
    pub audit, _: 7;
}

impl SessionAttributes {
    /// Get a builder for the structure
    pub const fn builder() -> SessionAttributesBuilder {
        SessionAttributesBuilder::new()
    }
}

impl From<TPMA_SESSION> for SessionAttributes {
    fn from(tss_session_attributes: TPMA_SESSION) -> SessionAttributes {
        SessionAttributes(tss_session_attributes)
    }
}

impl From<SessionAttributes> for TPMA_SESSION {
    fn from(session_attributes: SessionAttributes) -> TPMA_SESSION {
        session_attributes.0
    }
}

// SESSION ATTRIBUTES MASK

bitfield! {
    /// Bitfield representing the session attributes mask.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct SessionAttributesMask(TPMA_SESSION);
    impl Debug;

    _, use_continue_session: 0;
    _, use_audit_exclusive: 1;
    _, use_audit_reset: 2;
    // Reserved 3,4 (Shall be clear)
    _, use_decrypt: 5;
    _, use_encrypt: 6;
    _, use_audit: 7;
}

impl SessionAttributesMask {
    /// Get a builder for the structure
    pub const fn builder() -> SessionAttributesBuilder {
        SessionAttributesBuilder::new()
    }
}

impl From<TPMA_SESSION> for SessionAttributesMask {
    fn from(tss_session_attributes: TPMA_SESSION) -> SessionAttributesMask {
        SessionAttributesMask(tss_session_attributes)
    }
}

impl From<SessionAttributesMask> for TPMA_SESSION {
    fn from(session_attributes_mask: SessionAttributesMask) -> TPMA_SESSION {
        session_attributes_mask.0
    }
}

// SESSION ATTRIBUTES ITEMS BUILDER

/// A builder that is used to create
/// SessionAttributes and a corresponding
/// SessionAttributesMask.
#[derive(Debug, Copy, Clone)]
pub struct SessionAttributesBuilder {
    attributes: SessionAttributes,
    mask: SessionAttributesMask,
}

impl SessionAttributesBuilder {
    pub const fn new() -> SessionAttributesBuilder {
        SessionAttributesBuilder {
            attributes: SessionAttributes(0),
            mask: SessionAttributesMask(0),
        }
    }

    pub fn with_continue_session(mut self, set: bool) -> Self {
        self.attributes.set_continue_session(set);
        self.mask.use_continue_session(true);
        self
    }

    pub fn with_audit_exclusive(mut self, set: bool) -> Self {
        self.attributes.set_audit_exclusive(set);
        self.mask.use_audit_exclusive(true);
        self
    }

    pub fn with_audit_reset(mut self, set: bool) -> Self {
        self.attributes.set_audit_reset(set);
        self.mask.use_audit_reset(true);
        self
    }

    pub fn with_decrypt(mut self, set: bool) -> Self {
        self.attributes.set_decrypt(set);
        self.mask.use_decrypt(true);
        self
    }

    pub fn with_encrypt(mut self, set: bool) -> Self {
        self.attributes.set_encrypt(set);
        self.mask.use_encrypt(true);
        self
    }

    pub fn with_audit(mut self, set: bool) -> Self {
        self.attributes.set_audit(set);
        self.mask.use_audit(true);
        self
    }

    pub fn build(self) -> (SessionAttributes, SessionAttributesMask) {
        (self.attributes, self.mask)
    }
}

impl Default for SessionAttributesBuilder {
    fn default() -> Self {
        Self::new()
    }
}
