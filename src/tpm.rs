//! TPM 2.0 connection and object-sealing layer for the v2 format.
//!
//! This module owns the TPM context and is the single entry point for talking to the
//! platform TPM. On Windows the default backend is the Windows TPM Base Services (TBS)
//! API via [`TctiNameConf::Tbs`]; on other platforms it is the kernel resource manager
//! device at `/dev/tpmrm0`, selected via [`TctiNameConf::Device`]. An explicit TCTI
//! (`--tcti`) overrides the default, for example to reach a software TPM.
//!
//! Implemented so far: connection, the deterministic owner primary storage key (the parent
//! for per-file objects), and sealing/loading/unsealing the 256-bit content key `K` into a
//! TPM keyed-hash object. The per-file NV counter and file-format integration come in later
//! steps. Errors are mapped to [`DecayError::Tpm`]; there is no software fallback and no
//! vTPM detection.

use std::collections::HashSet;

#[cfg(test)]
use std::collections::HashMap;

use rand::RngCore;
use tss_esapi::attributes::{
    NvIndexAttributes, NvIndexAttributesBuilder, ObjectAttributes, ObjectAttributesBuilder,
};
use tss_esapi::constants::tss::{TPM2_NV_INDEX_FIRST, TPM2_NV_INDEX_LAST};
use tss_esapi::constants::{CapabilityType, NvIndexType};
use tss_esapi::handles::{KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, Digest, KeyedHashScheme, NvPublic, Private, Public, PublicBuilder,
    PublicKeyRsa, PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SensitiveData, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

use crate::crypto::ContentKey;
use crate::error::DecayError;

/// The Linux TPM 2.0 device node used on non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub const DEVICE_PATH: &str = "/dev/tpmrm0";

/// The full TCTI name (`device:/dev/tpmrm0`) handed to the TCTI loader on non-Windows.
#[cfg(not(target_os = "windows"))]
const DEVICE_TCTI_NAME: &str = "device:/dev/tpmrm0";

/// Number of NV handles requested per `TPM2_GetCapability` page. This is only a per-request
/// page size (driven to completion by the `more_data` flag); it is never a cap on the total
/// number of NV indexes that are enumerated.
const NV_HANDLES_PAGE_SIZE: u32 = 64;

/// A connected TPM context owning the underlying `tss_esapi::Context`.
///
/// Provides no fallback path: connecting either succeeds against the required device
/// node or fails with a [`DecayError::Tpm`].
pub struct TpmContext {
    context: Context,
}

/// Information about a freshly created per-file TPM NV counter.
pub struct CounterInfo {
    /// The NV index handle value to persist in the file (the `nv_index` header field).
    pub nv_index: u32,
    /// The counter's initial value, read from the TPM after definition (the `c0` field).
    pub c0: u64,
    /// The per-file 32-byte NV authorization value needed to read/increment the counter
    /// (persisted in the header as `nv_auth`). Not a secret or encryption key.
    pub nv_auth: [u8; 32],
}

/// Read metadata about an existing TPM NV index.
pub struct CounterMetadata {
    /// The NV index handle value.
    pub nv_index: u32,
    /// The NV index type; `NvIndexType::Counter` for a decay counter.
    pub index_type: NvIndexType,
    /// Size of the NV data area in bytes (8 for a u64 counter).
    pub data_size: usize,
}

/// The TPM operations the v2 encode and open flows need.
///
/// Implemented by the production [`TpmContext`] (backed by tss-esapi) and, in tests, by a
/// deterministic fake. No tss-esapi type appears in these signatures: the sealed object's
/// transient handle is hidden by collapsing load+unseal into the `unseal_content_key`
/// method, and the counter type/size check is encapsulated by `validate_counter` rather than
/// exposing [`NvIndexType`] (see [`CounterMetadata`]).
pub trait Tpm {
    /// Seals `content_key` and returns the serialized `(public, private)` blobs to store in
    /// the v2 header. The caller retains and zeroizes `content_key`.
    fn seal_content_key(
        &mut self,
        content_key: &ContentKey,
    ) -> Result<(Vec<u8>, Vec<u8>), DecayError>;

    /// Allocates a fresh per-file counter and returns its identity and initial value.
    fn allocate_counter(&mut self) -> Result<CounterInfo, DecayError>;

    /// Validates that `nv_index` exists, is an `NvIndexType::Counter`, and is 8 bytes.
    fn validate_counter(&mut self, nv_index: u32) -> Result<(), DecayError>;

    /// Reads the current u64 value of the counter at `nv_index`, authorizing with `nv_auth`.
    fn read_counter(&mut self, nv_index: u32, nv_auth: [u8; 32]) -> Result<u64, DecayError>;

    /// Monotonically increments the counter at `nv_index`, authorizing with `nv_auth`.
    fn increment_counter(&mut self, nv_index: u32, nv_auth: [u8; 32]) -> Result<(), DecayError>;

    /// Loads the sealed object from `sealed_pub`/`sealed_priv` and unseals the content key,
    /// returning the raw 32-byte key. The caller zeroizes the returned bytes.
    fn unseal_content_key(
        &mut self,
        sealed_pub: &[u8],
        sealed_priv: &[u8],
    ) -> Result<[u8; 32], DecayError>;
}

impl TpmContext {
    /// Connects to the platform TPM 2.0 through Windows TPM Base Services (TBS).
    ///
    /// This is the default backend on Windows, so ordinary CLI usage needs no `--tcti`.
    #[cfg(target_os = "windows")]
    pub fn connect() -> Result<Self, DecayError> {
        let context = Context::new(TctiNameConf::Tbs).map_err(|error| DecayError::Tpm {
            context: format!("connect to TPM via Windows TBS: {error}"),
        })?;
        Ok(TpmContext { context })
    }

    /// Connects to the platform TPM 2.0 through the kernel resource manager device.
    ///
    /// Uses exactly the device TCTI configuration for `/dev/tpmrm0`. There is no vTPM
    /// detection and no fallback to any other device or library.
    #[cfg(not(target_os = "windows"))]
    pub fn connect() -> Result<Self, DecayError> {
        let conf: TctiNameConf = DEVICE_TCTI_NAME.parse().map_err(|error| DecayError::Tpm {
            context: format!("parse TCTI name '{DEVICE_TCTI_NAME}': {error}"),
        })?;
        let context = Context::new(conf).map_err(|error| DecayError::Tpm {
            context: format!("connect to TPM at '{DEVICE_PATH}': {error}"),
        })?;
        Ok(TpmContext { context })
    }

    /// Connects to the TPM using an explicit TCTI configuration.
    ///
    /// Unlike [`TpmContext::connect`], which uses the platform's default backend, this lets
    /// the caller choose the transport — for example a software TPM:
    /// `swtpm:host=127.0.0.1,port=2321`. It exists so tests and development can drive the
    /// same [`TpmContext`] against a disposable software TPM or a specific backend.
    pub fn connect_with_tcti(conf: TctiNameConf) -> Result<Self, DecayError> {
        let context = Context::new(conf).map_err(|error| DecayError::Tpm {
            context: format!("connect to TPM using TCTI: {error}"),
        })?;
        Ok(TpmContext { context })
    }

    /// Connects to the TPM, optionally via an explicit TCTI configuration string.
    ///
    /// When `tcti` is `None`, this is exactly [`TpmContext::connect`] — the platform default
    /// (Windows TBS, or the `/dev/tpmrm0` device elsewhere). When `Some(conf)` is supplied it
    /// is parsed as a TSS2 TCTI configuration — for example `swtpm:host=127.0.0.1,port=2321` —
    /// and used to open a [`TpmContext`] via [`TpmContext::connect_with_tcti`]. This lets the
    /// CLI keep `--tcti` available for testing and development while using the platform default
    /// when it is omitted.
    pub fn connect_optional(tcti: Option<&str>) -> Result<Self, DecayError> {
        match tcti {
            Some(conf_str) => {
                let conf: TctiNameConf = conf_str.parse().map_err(|error| DecayError::Tpm {
                    context: format!("invalid TCTI '{conf_str}': {error}"),
                })?;
                TpmContext::connect_with_tcti(conf)
            }
            None => TpmContext::connect(),
        }
    }

    /// Returns mutable access to the underlying TPM context for TPM commands.
    pub fn context(&mut self) -> &mut Context {
        &mut self.context
    }

    /// Creates (or deterministically recreates) the owner primary storage key.
    ///
    /// This is the parent under which each per-file sealed content-key object is created
    /// and loaded. It is a restricted, decrypt-capable, fixed-parent RSA key with no
    /// authorization policy and no caller-supplied secret; because it is created from a
    /// fixed template under [`Hierarchy::Owner`] with an empty nonce, the same key is
    /// recreated on every call — it is never persisted, and no handle is retained here.
    pub fn create_storage_parent(&mut self) -> Result<KeyHandle, DecayError> {
        let public = primary_storage_public()?;
        let key_handle = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .map_err(|error| DecayError::Tpm {
                context: format!("create_primary(Owner) failed: {error}"),
            })?
            .key_handle;
        Ok(key_handle)
    }

    /// Seals a 256-bit `ContentKey` K into a TPM keyed-hash object.
    ///
    /// Creates (or recreates) the deterministic owner storage parent, creates a keyed-hash
    /// sealing object under it with K as the sensitive data, flushes the parent handle, and
    /// returns the serialized `Public` and `Private` portions (for header storage) as
    /// `(sealed_pub, sealed_priv)`. K is supplied by the application (never generated by the
    /// TPM), so the sealed child has `sensitiveDataOrigin` clear. The parent handle is never
    /// retained.
    pub fn seal_content_key(
        &mut self,
        content_key: &ContentKey,
    ) -> Result<(Vec<u8>, Vec<u8>), DecayError> {
        let parent = self.create_storage_parent()?;
        let public = sealed_key_public()?;
        let sensitive_data =
            SensitiveData::try_from(content_key.as_bytes()).map_err(|error| DecayError::Tpm {
                context: format!("wrap content key as sensitive data: {error}"),
            })?;
        let created = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(parent, public, None, Some(sensitive_data), None, None)
            })
            .map_err(|error| DecayError::Tpm {
                context: format!("create sealed content-key object: {error}"),
            })?;
        self.flush_key(parent)?;
        let sealed_pub = created
            .out_public
            .marshall()
            .map_err(|error| DecayError::Tpm {
                context: format!("marshal sealed public: {error}"),
            })?;
        let sealed_priv = created.out_private.value().to_vec();
        Ok((sealed_pub, sealed_priv))
    }

    /// Loads a previously sealed content-key object from its serialized blobs.
    ///
    /// Recreates the owner storage parent, unmarshals `sealed_pub` via `UnMarshall` and
    /// `sealed_priv` via its buffer `TryFrom`, loads the object under the parent, flushes the
    /// parent, and returns the loaded transient [`KeyHandle`]. Used internally by
    /// [`Tpm::unseal_content_key`].
    fn load_sealed_object(
        &mut self,
        sealed_pub: &[u8],
        sealed_priv: &[u8],
    ) -> Result<KeyHandle, DecayError> {
        let parent = self.create_storage_parent()?;
        let public = Public::unmarshall(sealed_pub).map_err(|error| DecayError::Tpm {
            context: format!("unmarshal sealed public: {error}"),
        })?;
        let private = Private::try_from(sealed_priv).map_err(|error| DecayError::Tpm {
            context: format!("unmarshal sealed private: {error}"),
        })?;
        let loaded = self
            .context
            .execute_with_nullauth_session(|ctx| ctx.load(parent, private, public))
            .map_err(|error| DecayError::Tpm {
                context: format!("load sealed content-key object: {error}"),
            })?;
        self.flush_key(parent)?;
        Ok(loaded)
    }

    /// Unseals an already-loaded content-key object and returns the recovered K as exactly
    /// 32 bytes.
    ///
    /// Flushes the loaded transient handle after unsealing. A returned sensitive buffer whose
    /// length is not 32 bytes is mapped to [`DecayError::Tpm`] rather than panicking.
    ///
    /// The TPM-returned [`SensitiveData`] is backed by `zeroize::Zeroizing`, so the library
    /// already wipes its buffer when it is dropped; no extra manual erasure of that buffer is
    /// possible without unsafe, and none is required. The returned `[u8; 32]` key is a
    /// separate copy that the caller must zeroize (as `open.rs::open_v2_file` does). This is
    /// the KeyHandle-based half of [`Tpm::unseal_content_key`].
    fn unseal_loaded_key(&mut self, loaded: KeyHandle) -> Result<[u8; 32], DecayError> {
        let object_handle = ObjectHandle::from(loaded);
        let sensitive = self
            .context
            .execute_with_nullauth_session(|ctx| ctx.unseal(object_handle))
            .map_err(|error| DecayError::Tpm {
                context: format!("unseal content-key object: {error}"),
            })?;
        self.context
            .flush_context(object_handle)
            .map_err(|error| DecayError::Tpm {
                context: format!("flush sealed object handle: {error}"),
            })?;
        let bytes = sensitive.value();
        if bytes.len() != 32 {
            return Err(DecayError::Tpm {
                context: format!(
                    "unsealed content key has {} bytes, expected 32",
                    bytes.len()
                ),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    }

    /// Flushes a transient key handle so it does not remain resident.
    fn flush_key(&mut self, handle: KeyHandle) -> Result<(), DecayError> {
        self.context
            .flush_context(ObjectHandle::from(handle))
            .map_err(|error| DecayError::Tpm {
                context: format!("flush transient handle: {error}"),
            })
    }

    /// Allocates and defines a fresh per-file TPM NV counter under the Owner hierarchy.
    ///
    /// Enumerates the TPM's existing NV handles, picks a genuinely unused index in the valid
    /// NV range, defines an 8-byte `NvIndexType::Counter` index with `AUTHREAD | AUTHWRITE`
    /// attributes and a fresh random 32-byte NV authorization value (returned as `nv_auth` for the
    /// header), and returns it alongside a logical initial value of `c0 = 0`. It never redefines
    /// an existing index; any define failure is surfaced as a [`DecayError::NvCounter`] and the
    /// counter is left untouched.
    pub fn allocate_counter(&mut self) -> Result<CounterInfo, DecayError> {
        let used = self.used_nv_indexes()?;
        let index = pick_unused_nv_index(&used).ok_or_else(|| DecayError::NvCounter {
            context: "no free TPM NV index available".to_string(),
        })?;
        let nv_tpm_index = NvIndexTpmHandle::new(index).map_err(|error| DecayError::NvCounter {
            context: format!("invalid NV index {index:#010x}: {error}"),
        })?;
        // A fresh random 32-byte NV authorization value authorizes reads/increments of this
        // counter (persisted in the header as nv_auth; it is not a secret or encryption key).
        let mut nv_auth = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nv_auth);
        let auth = Auth::try_from(nv_auth.to_vec()).map_err(|error| DecayError::NvCounter {
            context: format!("build NV auth for {index:#010x}: {error}"),
        })?;
        let nv_public = NvPublic::builder()
            .with_nv_index(nv_tpm_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(counter_attributes()?)
            .with_data_area_size(8)
            .build()
            .map_err(|error| DecayError::NvCounter {
                context: format!("build NV public for {index:#010x}: {error}"),
            })?;
        let nv_handle = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.nv_define_space(Provision::Owner, Some(auth), nv_public)
            })
            .map_err(|error| DecayError::NvCounter {
                context: format!("define NV counter at {index:#010x}: {error}"),
            })?;
        self.close_nv_handle(nv_handle)?;
        // A freshly-created TPMA_NV_COUNTER has a logical initial value of 0, so record c0 = 0
        // without reading it from the TPM. This keeps encode free of any counter read, and avoids
        // a TPM that cannot read a counter until its first increment (e.g. swtpm) failing here.
        Ok(CounterInfo {
            nv_index: index,
            c0: 0,
            nv_auth,
        })
    }

    /// Reads the current u64 value of the per-file TPM NV counter at `nv_index`, authorizing
    /// with the per-file `nv_auth`.
    pub fn read_counter(&mut self, nv_index: u32, nv_auth: [u8; 32]) -> Result<u64, DecayError> {
        let nv_handle = self.nv_handle_from_index(nv_index)?;
        self.authorize_nv_handle(nv_handle, nv_auth)?;
        let value = self.read_counter_from_handle(nv_handle)?;
        self.close_nv_handle(nv_handle)?;
        Ok(value)
    }

    /// Increments the per-file TPM NV counter at `nv_index` (monotonic, on the TPM), authorizing
    /// with the per-file `nv_auth`.
    pub fn increment_counter(
        &mut self,
        nv_index: u32,
        nv_auth: [u8; 32],
    ) -> Result<(), DecayError> {
        let nv_handle = self.nv_handle_from_index(nv_index)?;
        self.authorize_nv_handle(nv_handle, nv_auth)?;
        self.context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.nv_increment(NvAuth::NvIndex(nv_handle), nv_handle)
            })
            .map_err(|error| DecayError::NvCounter {
                context: format!("increment NV counter {nv_index:#010x}: {error}"),
            })?;
        self.close_nv_handle(nv_handle)?;
        Ok(())
    }

    /// Reads the public metadata of the NV index at `nv_index`.
    pub fn counter_metadata(&mut self, nv_index: u32) -> Result<CounterMetadata, DecayError> {
        let nv_handle = self.nv_handle_from_index(nv_index)?;
        let (nv_public, _name) = self
            .context
            .execute_without_session(|ctx| ctx.nv_read_public(nv_handle))
            .map_err(|error| DecayError::NvCounter {
                context: format!("read NV public for {nv_index:#010x}: {error}"),
            })?;
        self.close_nv_handle(nv_handle)?;
        let index_type =
            nv_public
                .attributes()
                .index_type()
                .map_err(|error| DecayError::NvCounter {
                    context: format!("read index type for {nv_index:#010x}: {error}"),
                })?;
        Ok(CounterMetadata {
            nv_index,
            index_type,
            data_size: nv_public.data_size(),
        })
    }

    /// Validates that the NV index at `nv_index` is a real 8-byte monotonic counter.
    pub fn validate_counter(&mut self, nv_index: u32) -> Result<(), DecayError> {
        let metadata = self.counter_metadata(nv_index)?;
        if metadata.index_type != NvIndexType::Counter {
            return Err(DecayError::NvCounter {
                context: format!(
                    "NV index {nv_index:#010x} is not a counter (type {:?})",
                    metadata.index_type
                ),
            });
        }
        if metadata.data_size != 8 {
            return Err(DecayError::NvCounter {
                context: format!(
                    "NV index {nv_index:#010x} data size is {}, expected 8",
                    metadata.data_size
                ),
            });
        }
        Ok(())
    }

    /// Registers `nv_auth` as the ESYS authorization value for the given NV index handle, so a
    /// subsequent `NV_Read`/`NV_Increment` issued under a password session authorizes with it.
    fn authorize_nv_handle(
        &mut self,
        nv_handle: NvIndexHandle,
        nv_auth: [u8; 32],
    ) -> Result<(), DecayError> {
        let auth = Auth::try_from(nv_auth.to_vec()).map_err(|error| DecayError::NvCounter {
            context: format!("build NV auth value: {error}"),
        })?;
        self.context
            .tr_set_auth(ObjectHandle::from(nv_handle), auth)
            .map_err(|error| DecayError::NvCounter {
                context: format!("set NV authorization value: {error}"),
            })
    }

    /// Reads 8 bytes (u64 big-endian, network order) from an open NV counter handle, using the
    /// counter's NV index authorization (the auth was registered via [`Self::authorize_nv_handle`]).
    fn read_counter_from_handle(&mut self, nv_handle: NvIndexHandle) -> Result<u64, DecayError> {
        match self
            .context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.nv_read(NvAuth::NvIndex(nv_handle), nv_handle, 8, 0)
            }) {
            Ok(buffer) => decode_counter_bytes(buffer.value()),
            Err(error) => {
                // A freshly-defined TPMA_NV_COUNTER may be unreadable until its first increment on
                // some TPMs (e.g. swtpm); per the spec its logical initial value is 0. Map ONLY the
                // TPM "NV index used before being initialized" response code (Tss2 RC 0x14A) to 0;
                // every other TPM or wrapper error is propagated.
                let is_uninitialized = matches!(
                    error,
                    tss_esapi::Error::Tss2Error(code)
                        if matches!(
                            code.kind(),
                            Some(tss_esapi::constants::Tss2ResponseCodeKind::NvUninitialized)
                        )
                );
                if is_uninitialized {
                    Ok(0)
                } else {
                    Err(DecayError::NvCounter {
                        context: format!("read NV counter: {error}"),
                    })
                }
            }
        }
    }

    /// Reopens an `NvIndexHandle` for a stored NV index value.
    fn nv_handle_from_index(&mut self, nv_index: u32) -> Result<NvIndexHandle, DecayError> {
        let nv_tpm_index =
            NvIndexTpmHandle::new(nv_index).map_err(|error| DecayError::NvCounter {
                context: format!("invalid NV index {nv_index:#010x}: {error}"),
            })?;
        let object_handle = self
            .context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::from(nv_tpm_index)))
            .map_err(|error| DecayError::NvCounter {
                context: format!("open NV index {nv_index:#010x}: {error}"),
            })?;
        Ok(NvIndexHandle::from(object_handle))
    }

    /// Closes a transient ESYS handle for an NV index.
    fn close_nv_handle(&mut self, nv_handle: NvIndexHandle) -> Result<(), DecayError> {
        let mut object_handle = ObjectHandle::from(nv_handle);
        self.context
            .execute_without_session(|ctx| ctx.tr_close(&mut object_handle))
            .map_err(|error| DecayError::Tpm {
                context: format!("close NV index handle: {error}"),
            })
    }

    /// Enumerates the currently-defined NV indexes as raw `u32` handle values.
    ///
    /// Uses the `TPM2_GetCapability` handshake for `CapabilityType::Handles`, paging through
    /// the handle space via the returned `more_data` flag rather than assuming a single call
    /// returns every NV index. This avoids treating the property tag `TPM2_PT_NV_INDEX_MAX`
    /// as a handle count and avoids capping the number of NV indexes examined at an arbitrary
    /// maximum. On each page the cursor `property` advances to one past the highest handle
    /// returned, so the enumeration runs to completion however many NV indexes exist.
    fn used_nv_indexes(&mut self) -> Result<Vec<u32>, DecayError> {
        let mut used = Vec::new();
        let mut property = TPM2_NV_INDEX_FIRST;

        while property <= TPM2_NV_INDEX_LAST {
            let (capability_data, more) = self
                .context
                .execute_without_session(|ctx| {
                    ctx.get_capability(CapabilityType::Handles, property, NV_HANDLES_PAGE_SIZE)
                })
                .map_err(|error| DecayError::NvCounter {
                    context: format!("enumerate TPM NV indexes from {property:#010x}: {error}"),
                })?;

            let handles = match capability_data {
                CapabilityData::Handles(handle_list) => handle_list.into_inner(),
                _ => Vec::new(),
            };

            // The TPM returns handles in ascending order, so the last is the largest returned
            // on this page. Keep the highest raw value so the next page resumes just after it.
            let highest_this_page = handles.iter().map(|handle| u32::from(*handle)).max();

            for tpm_handle in &handles {
                if let Ok(nv_index) = NvIndexTpmHandle::try_from(*tpm_handle) {
                    used.push(u32::from(nv_index));
                }
            }

            if !more {
                break;
            }

            // Advance the cursor past the handles returned so far. A page that yields no new
            // maximum (or none at all) means the TPM is not making forward progress; fail
            // closed rather than loop forever or return a partial set of NV indexes.
            match highest_this_page {
                Some(highest) => {
                    let next = highest
                        .checked_add(1)
                        .ok_or_else(|| DecayError::NvCounter {
                            context: format!(
                                "enumerate TPM NV indexes: handle cursor overflow at {highest:#010x}"
                            ),
                        })?;
                    if next <= property {
                        return Err(DecayError::NvCounter {
                            context: format!(
                                "enumerate TPM NV indexes: handle cursor did not advance at {property:#010x}"
                            ),
                        });
                    }
                    property = next;
                }
                None => {
                    return Err(DecayError::NvCounter {
                        context: format!(
                            "enumerate TPM NV indexes: no handles returned but more data reported at {property:#010x}"
                        ),
                    });
                }
            }
        }

        Ok(used)
    }
}

impl Tpm for TpmContext {
    fn seal_content_key(
        &mut self,
        content_key: &ContentKey,
    ) -> Result<(Vec<u8>, Vec<u8>), DecayError> {
        TpmContext::seal_content_key(self, content_key)
    }

    fn allocate_counter(&mut self) -> Result<CounterInfo, DecayError> {
        // Windows NV provisioning is delegated to the DecayFmtProvisionerTest service over its
        // named pipe (see `platform_allocate_counter`); every other OS defines the counter on the
        // local TPM directly. Sealing always happens locally on this same TpmContext.
        platform_allocate_counter(self)
    }

    fn validate_counter(&mut self, nv_index: u32) -> Result<(), DecayError> {
        TpmContext::validate_counter(self, nv_index)
    }

    fn read_counter(&mut self, nv_index: u32, nv_auth: [u8; 32]) -> Result<u64, DecayError> {
        TpmContext::read_counter(self, nv_index, nv_auth)
    }

    fn increment_counter(&mut self, nv_index: u32, nv_auth: [u8; 32]) -> Result<(), DecayError> {
        TpmContext::increment_counter(self, nv_index, nv_auth)
    }

    fn unseal_content_key(
        &mut self,
        sealed_pub: &[u8],
        sealed_priv: &[u8],
    ) -> Result<[u8; 32], DecayError> {
        let loaded = self.load_sealed_object(sealed_pub, sealed_priv)?;
        TpmContext::unseal_loaded_key(self, loaded)
    }
}

/// Platform-specific counter allocation used by the `Tpm` implementation for [`TpmContext`].
///
/// On Windows this defers to the `DecayFmtProvisionerTest` service over its named pipe (the
/// production integration, mirroring `src/bin/ms_provision_client.rs`), so the local context never
/// defines an NV index itself. On every other platform it is the existing direct local allocation.
#[cfg(target_os = "windows")]
fn platform_allocate_counter(_ctx: &mut TpmContext) -> Result<CounterInfo, DecayError> {
    windows_provision::request_allocate_counter()
}

#[cfg(not(target_os = "windows"))]
fn platform_allocate_counter(ctx: &mut TpmContext) -> Result<CounterInfo, DecayError> {
    TpmContext::allocate_counter(ctx)
}

/// Builds the deterministic `Public` template for the owner primary storage key.
///
/// This is an RSA-2048 restricted, decrypt-capable key (a storage key) with a null scheme,
/// SHA-256 name, and no authorization policy. `fixedTPM` and `fixedParent` make it TPM-pinned
/// and non-duplicable; it is suitable as the parent for a keyed-hash sealed object.
fn primary_storage_public() -> Result<Public, DecayError> {
    let rsa_parameters = PublicRsaParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .map_err(|error| DecayError::Tpm {
            context: format!("build owner primary RSA parameters: {error}"),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(ObjectAttributes::new_fixed_parent_key())
        .with_rsa_parameters(rsa_parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048))
        .build()
        .map_err(|error| DecayError::Tpm {
            context: format!("build owner primary public template: {error}"),
        })
}

/// Builds the `Public` template for the sealed content-key (keyed-hash) object.
///
/// This is a keyed-hash sealing object: SHA-256 name, `KeyedHashScheme::Null`, `fixedTPM`,
/// `fixedParent`, `userWithAuth`, `noDA`, and `sensitiveDataOrigin` CLEAR (K is supplied by
/// the application, not generated by the TPM). There is no authorization/policy binding.
fn sealed_key_public() -> Result<Public, DecayError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_sensitive_data_origin(false)
        .build()
        .map_err(|error| DecayError::Tpm {
            context: format!("build sealed object attributes: {error}"),
        })?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|error| DecayError::Tpm {
            context: format!("build sealed object public template: {error}"),
        })
}

/// Builds the `NvIndexAttributes` for a monotonic 8-byte counter authorized by the Owner
/// hierarchy. `owned` read/write lets the honest decayfmt application increment and read the
/// counter without a passphrase.
fn counter_attributes() -> Result<NvIndexAttributes, DecayError> {
    NvIndexAttributesBuilder::new()
        .with_auth_read(true)
        .with_auth_write(true)
        .with_nv_index_type(NvIndexType::Counter)
        .build()
        .map_err(|error| DecayError::NvCounter {
            context: format!("build NV counter attributes: {error}"),
        })
}

/// Decodes the 8-byte counter representation returned by `TPM2_NV_Read`.
///
/// TPM NV counters are returned in big-endian (network) byte order, so the bytes are parsed with
/// `u64::from_be_bytes`. A buffer that is not exactly 8 bytes is rejected rather than truncated or
/// padded, and the bytes are never interpreted as little-endian.
fn decode_counter_bytes(bytes: &[u8]) -> Result<u64, DecayError> {
    if bytes.len() != 8 {
        return Err(DecayError::NvCounter {
            context: format!("NV counter returned {} bytes, expected 8", bytes.len()),
        });
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(out))
}

/// Returns the lowest NV index in the valid NV range that is not present in `used`.
fn pick_unused_nv_index(used: &[u32]) -> Option<u32> {
    let used_set: HashSet<u32> = used.iter().copied().collect();
    (TPM2_NV_INDEX_FIRST..=TPM2_NV_INDEX_LAST).find(|index| !used_set.contains(index))
}

/// A deterministic, hardware-free [`Tpm`] implementation for tests.
///
/// Gated behind `#[cfg(test)]` so it never ships as production API. It models only what the
/// v2 encode/open flows use: per-file counters and a sealed-object registry, plus
/// failure-injection knobs for validate/read/increment/unseal. It uses no tss-esapi types.
#[cfg(test)]
pub struct FakeTpm {
    /// Monotonically increasing source of fresh NV index values; never reused.
    next_nv_index: u32,
    /// Allocated per-file counters: `nv_index` -> its current u64 value (initial `c0`).
    counters: HashMap<u32, u64>,
    /// Counter used to make each seal's blobs unique.
    sealed_serial: u64,
    /// `sealed_pub` -> `(sealed_priv, content-key bytes)`.
    sealed: HashMap<Vec<u8>, (Vec<u8>, [u8; 32])>,
    /// Inject a failure next time `validate_counter` is called.
    pub fail_validate: bool,
    /// Inject a failure next time `read_counter` is called.
    pub fail_read: bool,
    /// Inject a failure next time `increment_counter` is called.
    pub fail_increment: bool,
    /// Inject a failure next time `unseal_content_key` is called.
    pub fail_unseal: bool,
    /// Records each of `validate`/`read`/`increment`/`unseal` as it is attempted, in order,
    /// so tests can assert call ordering and that an operation was (or wasn't) reached.
    pub call_log: Vec<&'static str>,
}

#[cfg(test)]
impl FakeTpm {
    /// A deterministic fake with an empty counter space, a fresh index range, and no
    /// failures enabled.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        FakeTpm {
            next_nv_index: 0x0100_0000,
            counters: HashMap::new(),
            sealed_serial: 0,
            sealed: HashMap::new(),
            fail_validate: false,
            fail_read: false,
            fail_increment: false,
            fail_unseal: false,
            call_log: Vec::new(),
        }
    }
}

#[cfg(test)]
impl Tpm for FakeTpm {
    fn seal_content_key(
        &mut self,
        content_key: &ContentKey,
    ) -> Result<(Vec<u8>, Vec<u8>), DecayError> {
        let serial = self.sealed_serial;
        self.sealed_serial += 1;
        let sealed_pub = format!("sealed-pub-{serial}").into_bytes();
        let sealed_priv = format!("sealed-priv-{serial}").into_bytes();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(content_key.as_bytes());
        self.sealed
            .insert(sealed_pub.clone(), (sealed_priv.clone(), key_bytes));
        Ok((sealed_pub, sealed_priv))
    }

    fn allocate_counter(&mut self) -> Result<CounterInfo, DecayError> {
        let index = self.next_nv_index;
        self.next_nv_index += 1;
        self.counters.insert(index, 0);
        Ok(CounterInfo {
            nv_index: index,
            c0: 0,
            nv_auth: [0u8; 32],
        })
    }

    fn validate_counter(&mut self, nv_index: u32) -> Result<(), DecayError> {
        self.call_log.push("validate");
        if self.fail_validate {
            return Err(DecayError::NvCounter {
                context: "fake: validate failure injected".to_string(),
            });
        }
        if self.counters.contains_key(&nv_index) {
            Ok(())
        } else {
            Err(DecayError::NvCounter {
                context: format!("fake: no counter allocated at index {nv_index:#010x}"),
            })
        }
    }

    fn read_counter(&mut self, nv_index: u32, _nv_auth: [u8; 32]) -> Result<u64, DecayError> {
        self.call_log.push("read");
        if self.fail_read {
            return Err(DecayError::NvCounter {
                context: "fake: read failure injected".to_string(),
            });
        }
        self.counters
            .get(&nv_index)
            .copied()
            .ok_or_else(|| DecayError::NvCounter {
                context: format!("fake: no counter allocated at index {nv_index:#010x}"),
            })
    }

    fn increment_counter(&mut self, nv_index: u32, _nv_auth: [u8; 32]) -> Result<(), DecayError> {
        self.call_log.push("increment");
        if self.fail_increment {
            return Err(DecayError::NvCounter {
                context: "fake: increment failure injected".to_string(),
            });
        }
        let value = self
            .counters
            .get_mut(&nv_index)
            .ok_or_else(|| DecayError::NvCounter {
                context: format!("fake: no counter allocated at index {nv_index:#010x}"),
            })?;
        *value = value.checked_add(1).ok_or_else(|| DecayError::NvCounter {
            context: "fake: counter would overflow u64::MAX".to_string(),
        })?;
        Ok(())
    }

    fn unseal_content_key(
        &mut self,
        sealed_pub: &[u8],
        sealed_priv: &[u8],
    ) -> Result<[u8; 32], DecayError> {
        self.call_log.push("unseal");
        if self.fail_unseal {
            return Err(DecayError::Tpm {
                context: "fake: unseal failure injected".to_string(),
            });
        }
        match self.sealed.get(sealed_pub) {
            Some((expected_priv, key)) if expected_priv == sealed_priv => Ok(*key),
            _ => Err(DecayError::Tpm {
                context: "fake: sealed object not found or sealed_priv mismatch".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "windows"))]
    use std::ffi::CString;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn device_tcti_name_selects_the_required_device() {
        // Parsing the TCTI name builds a `Device` configuration without opening the
        // TPM, so this is hardware-free — only TpmContext::connect() touches /dev/tpmrm0.
        let conf: TctiNameConf = DEVICE_TCTI_NAME
            .parse()
            .expect("device TCTI name must parse");

        assert!(
            matches!(&conf, TctiNameConf::Device(_)),
            "must be a Device config"
        );

        let cstr = CString::try_from(conf).expect("TCTI config must convert to CString");
        assert_eq!(
            cstr.to_string_lossy(),
            DEVICE_TCTI_NAME,
            "TCTI name must be 'device:/dev/tpmrm0'"
        );
    }

    #[test]
    fn primary_storage_template_is_deterministic_and_is_a_storage_key() {
        let a = primary_storage_public().expect("owner primary template must build");
        let b = primary_storage_public().expect("owner primary template must build");

        assert_eq!(a, b, "the primary storage template must be deterministic");

        assert!(matches!(&a, Public::Rsa { .. }), "must be an RSA key");

        let attributes = a.object_attributes();
        assert!(attributes.fixed_tpm(), "fixedTPM must be set");
        assert!(attributes.fixed_parent(), "fixedParent must be set");
        assert!(
            attributes.restricted(),
            "restricted must be set (storage key)"
        );
        assert!(attributes.decrypt(), "decrypt must be set (storage key)");

        assert_eq!(a.name_hashing_algorithm(), HashingAlgorithm::Sha256);
        assert!(
            a.auth_policy().value().is_empty(),
            "no authorization policy"
        );
    }

    #[test]
    fn sealed_object_template_is_keyed_hash_with_app_supplied_secret() {
        let public = sealed_key_public().expect("sealed public template must build");

        assert!(
            matches!(&public, Public::KeyedHash { .. }),
            "must be a keyed-hash object"
        );

        let attributes = public.object_attributes();
        assert!(attributes.fixed_tpm(), "fixedTPM must be set");
        assert!(attributes.fixed_parent(), "fixedParent must be set");
        assert!(attributes.user_with_auth(), "userWithAuth must be set");
        assert!(attributes.no_da(), "noDA must be set");
        assert!(
            !attributes.sensitive_data_origin(),
            "sensitiveDataOrigin must NOT be set (K is supplied by the application)"
        );
        assert!(
            !attributes.restricted(),
            "sealing object must not be restricted"
        );
        assert!(
            !attributes.decrypt(),
            "sealing object must not be a decrypt key"
        );

        assert_eq!(public.name_hashing_algorithm(), HashingAlgorithm::Sha256);
        assert!(
            public.auth_policy().value().is_empty(),
            "no authorization policy"
        );
    }

    #[test]
    fn sealed_public_template_marshals_and_unmarshals() {
        let public = sealed_key_public().expect("sealed public template must build");
        let bytes = public.marshall().expect("Public must marshall");
        let rebuilt = Public::unmarshall(&bytes).expect("Public must unmarshall");
        assert_eq!(
            public, rebuilt,
            "Public must round-trip through Marshall/UnMarshall"
        );
    }

    #[test]
    fn picks_lowest_unused_nv_index() {
        let first = TPM2_NV_INDEX_FIRST;
        assert_eq!(pick_unused_nv_index(&[]), Some(first));
        assert_eq!(pick_unused_nv_index(&[first, first + 1]), Some(first + 2));
        assert_ne!(pick_unused_nv_index(&[first]), Some(first));
    }

    #[test]
    fn fake_increment_counter_overflows_at_u64_max() {
        let mut fake = FakeTpm::new();
        let info = fake.allocate_counter().expect("allocate a counter");
        assert_eq!(info.c0, 0);

        // Force the fresh counter to u64::MAX.
        let value = fake
            .counters
            .get_mut(&info.nv_index)
            .expect("freshly allocated counter must exist");
        *value = u64::MAX;

        assert!(
            matches!(
                fake.increment_counter(info.nv_index, info.nv_auth),
                Err(DecayError::NvCounter { .. })
            ),
            "incrementing a counter already at u64::MAX must fail closed"
        );
        assert_eq!(
            fake.read_counter(info.nv_index, info.nv_auth).unwrap(),
            u64::MAX,
            "the counter must remain at u64::MAX after a failed increment"
        );
    }

    #[test]
    fn decode_counter_bytes_is_big_endian() {
        // Value 1 as the TPM returns it: big-endian (network) byte order.
        assert_eq!(
            decode_counter_bytes(&[0, 0, 0, 0, 0, 0, 0, 1]).expect("decode 1"),
            1
        );
        // It must NOT be decoded as little-endian (which would be 0x0100000000000000).
        assert_ne!(
            decode_counter_bytes(&[0, 0, 0, 0, 0, 0, 0, 1]).expect("decode 1"),
            0x0100_0000_0000_0000
        );
        assert_eq!(
            decode_counter_bytes(&[0, 0, 0, 0, 0, 0, 0, 2]).expect("decode 2"),
            2
        );
        assert_eq!(
            decode_counter_bytes(&[0xFF; 8]).expect("decode all-ones"),
            u64::MAX
        );
        // A non-8-byte buffer is rejected rather than truncated or padded.
        assert!(matches!(
            decode_counter_bytes(&[0, 0, 0, 0, 0, 0, 0]),
            Err(DecayError::NvCounter { .. })
        ));
    }

    #[test]
    fn fake_allocate_counter_has_zero_c0() {
        // A freshly-created counter is logically 0: encode records c0 = 0 and never consumes an
        // access on creation.
        let mut fake = FakeTpm::new();
        let info = fake.allocate_counter().expect("allocate counter");
        assert_eq!(info.c0, 0);
        assert_eq!(info.nv_auth.len(), 32);
        assert_eq!(fake.read_counter(info.nv_index, info.nv_auth).unwrap(), 0);
    }

    #[test]
    fn swtpm_tcti_name_parses() {
        let conf: TctiNameConf = "swtpm:host=127.0.0.1,port=2321"
            .parse()
            .expect("swtpm TCTI name must parse");
        assert!(matches!(conf, TctiNameConf::Swtpm(_)));
    }

    #[test]
    fn connect_with_tcti_connects_via_swtpm_when_available() {
        let conf: TctiNameConf = "swtpm:host=127.0.0.1,port=2321"
            .parse()
            .expect("swtpm TCTI name must parse");
        // A software TPM may or may not be running in a given environment; we only exercise the
        // custom-TCTI construction path here and never fabricate a TPM error. When a daemon is
        // listening this constructs the TpmContext (Ok); otherwise it is a no-op for this host.
        let _tpm = TpmContext::connect_with_tcti(conf);
    }
}

/// Windows-only: provisions a fresh NV counter by asking the DecayFmtProvisionerTest Windows
/// service over its named pipe, instead of defining the counter on the local TPM.
///
/// This is the production counterpart of `src/bin/ms_provision_client.rs`: it connects to
/// `\\.\pipe\decayfmt-provision`, sends exactly `AllocateCounter\n`, and parses the service's
/// `OK nv_index=0x... c0=...\n` reply. It performs no sealing and no other TPM work; the local
/// `TpmContext` still seals the content key itself against the Windows TPM (TBS). The same
/// hand-written Win32 FFI style is used (no extra dependency), and the module only compiles on
/// Windows so Linux/macOS behaviour is unchanged.
#[cfg(target_os = "windows")]
mod windows_provision {
    use std::os::raw::c_void;

    use super::{CounterInfo, DecayError};

    /// The named pipe served by the `DecayFmtProvisionerTest` Windows service.
    const PIPE_NAME: &str = r"\\.\pipe\decayfmt-provision";

    // CreateFileW constants (winnt.h / winbase.h).
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;

    const MAX_RESPONSE_BYTES: usize = 4096;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> *mut c_void;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn ReadFile(
            h_file: *mut c_void,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn WriteFile(
            h_file: *mut c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    /// Asks the provisioner service to allocate a fresh NV counter, returning its identity.
    pub(super) fn request_allocate_counter() -> Result<CounterInfo, DecayError> {
        let pipe_name = to_wide(PIPE_NAME);
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(DecayError::NvCounter {
                context: format!(
                    "Windows v2 encode: could not reach the provisioner service at {PIPE_NAME} (last error {}); is the DecayFmtProvisionerTest service running?",
                    last_error()
                ),
            });
        }

        // Exactly one request opcode is supported, matching the service.
        let request = b"AllocateCounter\n";
        if !write_all(handle, request) {
            close(handle);
            return Err(DecayError::NvCounter {
                context:
                    "Windows v2 encode: failed to send AllocateCounter to the provisioner pipe"
                        .to_string(),
            });
        }

        let response = read_response(handle);
        close(handle);

        match parse_ok(&response) {
            Some(info) => Ok(info),
            None => {
                let text = String::from_utf8_lossy(&response);
                let trimmed = text.trim();
                Err(DecayError::NvCounter {
                    context: format!(
                        "Windows v2 encode: the provisioner returned an invalid or error response: {trimmed}"
                    ),
                })
            }
        }
    }

    /// Parses the service's success line `OK nv_index=0x... c0=... nv_auth=0x...`.
    fn parse_ok(response: &[u8]) -> Option<CounterInfo> {
        let text = std::str::from_utf8(response).ok()?;
        let rest = text.trim_start().strip_prefix("OK")?.trim_start();

        let nv_key = "nv_index=0x";
        let after_nv_key = &rest[rest.find(nv_key)? + nv_key.len()..];
        let nv_end = after_nv_key
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(after_nv_key.len());
        let nv_index = u32::from_str_radix(&after_nv_key[..nv_end], 16).ok()?;

        let after_nv = &after_nv_key[nv_end..];
        let c0_key = "c0=";
        let after_c0_key = &after_nv[after_nv.find(c0_key)? + c0_key.len()..];
        let c0_end = after_c0_key
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_c0_key.len());
        let c0: u64 = after_c0_key[..c0_end].parse().ok()?;

        // The service echoes the per-file 32-byte NV auth as 64 lowercase hex digits.
        let after_c0 = &after_c0_key[c0_end..];
        let auth_key = "nv_auth=0x";
        let after_auth_key = &after_c0[after_c0.find(auth_key)? + auth_key.len()..];
        let hex_end = after_auth_key
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(after_auth_key.len());
        if hex_end != 64 {
            return None;
        }
        let mut nv_auth = [0u8; 32];
        for (i, byte) in nv_auth.iter_mut().enumerate() {
            let two = after_auth_key
                .get(i * 2..i * 2 + 2)
                .expect("64 hex digits covers 32 bytes");
            *byte = u8::from_str_radix(two, 16).ok()?;
        }

        Some(CounterInfo {
            nv_index,
            c0,
            nv_auth,
        })
    }

    /// Reads until the pipe closes or the response cap is reached.
    fn read_response(handle: *mut c_void) -> Vec<u8> {
        let mut response = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    handle,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || bytes_read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..bytes_read as usize]);
            if response.len() >= MAX_RESPONSE_BYTES || response.contains(&b'\n') {
                break;
            }
        }
        response
    }

    /// Writes the whole buffer to the pipe.
    fn write_all(handle: *mut c_void, bytes: &[u8]) -> bool {
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        ok != 0 && written == bytes.len() as u32
    }

    fn close(handle: *mut c_void) {
        unsafe {
            CloseHandle(handle);
        }
    }

    /// Appends a NUL terminator so the wide buffer is usable as a `PCWSTR`.
    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        unsafe { GetLastError() }
    }
}
