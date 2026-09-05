// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Wrapper around the TCTI Loader Library interface.
//! See section 3.5 of the TCG TSS 2.0 TPM Command Transmission Interface(TCTI) API
//! Specification.

use crate::{Error, Result, WrapperErrorKind};
use log::error;
use regex::Regex;
use std::convert::TryFrom;
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::str::FromStr;

const DEVICE: &str = "device";
const MSSIM: &str = "mssim";
const SWTPM: &str = "swtpm";
const TABRMD: &str = "tabrmd";
const TBS: &str = "tbs";

/// TCTI Context created via a TCTI Loader Library.
/// Wrapper around the TSS2_TCTI_CONTEXT structure.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct TctiContext {
    tcti_context: *mut tss_esapi_sys::TSS2_TCTI_CONTEXT,
}

impl TctiContext {
    /// Allocate and initialize a new TctiContext structure.
    pub fn initialize(name_conf: TctiNameConf) -> Result<Self> {
        let mut tcti_context = null_mut();

        let tcti_name_conf = CString::try_from(name_conf)?;

        unsafe {
            let ret =
                tss_esapi_sys::Tss2_TctiLdr_Initialize(tcti_name_conf.as_ptr(), &mut tcti_context);
            let ret = Error::from_tss_rc(ret);
            if !ret.is_success() {
                error!("Error when creating a TCTI context: {}", ret);
                return Err(ret);
            }
        }
        Ok(TctiContext { tcti_context })
    }

    /// Get access to the inner C pointer
    pub(crate) fn tcti_context_ptr(&mut self) -> *mut tss_esapi_sys::TSS2_TCTI_CONTEXT {
        self.tcti_context
    }
}

impl Drop for TctiContext {
    fn drop(&mut self) {
        unsafe {
            tss_esapi_sys::Tss2_TctiLdr_Finalize(&mut self.tcti_context);
        }
    }
}

// `Send` and `Sync` are implemented to allow `TctiContext` to be thread-safe.
// This is necessary because `*mut TSS2_TCTI_CONTEXT` is not thread-safe by
// default. We can confirm the safety as the pointer can only be accessed
// in a thread-safe way (i.e. in methods that require a `&mut self`).
unsafe impl Send for TctiContext {}
unsafe impl Sync for TctiContext {}

/// Wrapper around the TSS2_TCTI_INFO structure.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct TctiInfo {
    tcti_info: *mut tss_esapi_sys::TSS2_TCTI_INFO,
}

impl TctiInfo {
    /// Query the TCTI loading mechanism
    pub fn get_info(name_conf: TctiNameConf) -> Result<Self> {
        let mut tcti_info = null_mut();

        let tcti_name_conf = CString::try_from(name_conf)?;

        unsafe {
            let ret = tss_esapi_sys::Tss2_TctiLdr_GetInfo(tcti_name_conf.as_ptr(), &mut tcti_info);
            let ret = Error::from_tss_rc(ret);
            if !ret.is_success() {
                error!("Error when getting the TCTI_INFO structure: {}", ret);
                return Err(ret);
            }
        }
        Ok(TctiInfo { tcti_info })
    }

    /// Get the version field
    pub fn version(&self) -> u32 {
        unsafe { (*(self.tcti_info)).version }
    }

    /// Get the name field
    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).name) }
    }

    /// Get the description field
    pub fn description(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).description) }
    }

    /// Get the config_help field
    pub fn config_help(&self) -> &CStr {
        unsafe { CStr::from_ptr((*(self.tcti_info)).config_help) }
    }
}

impl Drop for TctiInfo {
    fn drop(&mut self) {
        unsafe {
            tss_esapi_sys::Tss2_TctiLdr_FreeInfo(&mut self.tcti_info);
        }
    }
}

/// Placeholder TCTI types that can be used when initialising a `Context` to determine which
/// interface will be used to communicate with the TPM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TctiNameConf {
    /// Connect to a TPM available as a device node on the system
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Device_Init)
    Device(DeviceConfig),
    /// Connect to a TPM (simulator) available as a network device via the MSSIM protocol
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Mssim_Init)
    Mssim(NetworkTPMConfig),
    /// Connect to a TPM (simulator) available as a network device via the SWTPM protocol
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Mssim_Init)
    Swtpm(NetworkTPMConfig),
    /// Connect to a TPM through an Access Broker/Resource Manager daemon
    ///
    /// For more information about configuration, see [this page](https://www.mankier.com/3/Tss2_Tcti_Tabrmd_Init)
    Tabrmd(TabrmdConfig),
    /// Connect to the platform TPM through the Windows TPM Base Services (TBS) API.
    Tbs,
}

impl TctiNameConf {
    /// Gets a TCTI from the following environment variables, in order:
    /// - TPM2TOOLS_TCTI
    /// - TCTI
    /// - TEST_TCTI
    ///
    /// # Examples
    /// ```
    /// # use tss_esapi::tcti_ldr::TctiNameConf;
    /// // Create context
    /// let tcti_name_conf = TctiNameConf::from_environment_variable().expect("Failed to get TCTI");
    pub fn from_environment_variable() -> Result<Self> {
        env::var("TPM2TOOLS_TCTI")
            .or_else(|_| env::var("TCTI"))
            .or_else(|_| env::var("TEST_TCTI"))
            .map_err(|_| Error::WrapperError(WrapperErrorKind::ParamsMissing))
            .and_then(|val| TctiNameConf::from_str(&val))
    }
}

impl TryFrom<TctiNameConf> for CString {
    type Error = Error;

    fn try_from(tcti: TctiNameConf) -> Result<Self> {
        let tcti_name = match tcti {
            TctiNameConf::Device(..) => DEVICE,
            TctiNameConf::Mssim(..) => MSSIM,
            TctiNameConf::Swtpm(..) => SWTPM,
            TctiNameConf::Tabrmd(..) => TABRMD,
            TctiNameConf::Tbs => TBS,
        };

        let tcti_conf = match tcti {
            TctiNameConf::Mssim(config) => {
                if let ServerAddress::Hostname(name) = &config.host {
                    if !hostname_validator::is_valid(name) {
                        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                    }
                }
                format!("host={},port={}", config.host, config.port)
            }
            TctiNameConf::Swtpm(config) => {
                if let ServerAddress::Hostname(name) = &config.host {
                    if !hostname_validator::is_valid(name) {
                        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                    }
                }
                format!("host={},port={}", config.host, config.port)
            }
            TctiNameConf::Device(DeviceConfig { path }) => path
                .to_str()
                .ok_or(Error::WrapperError(WrapperErrorKind::InvalidParam))?
                .to_owned(),
            TctiNameConf::Tabrmd(config) => {
                format!("bus_name={},bus_type={}", config.bus_name, config.bus_type)
            }
            // TBS has no configuration string; the loader string is exactly "tbs".
            TctiNameConf::Tbs => String::new(),
        };

        if tcti_conf.is_empty() {
            CString::new(tcti_name).or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        } else {
            CString::new(format!("{}:{}", tcti_name, tcti_conf))
                .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
        }
    }
}

impl FromStr for TctiNameConf {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        let device_pattern = Regex::new(r"^device(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = device_pattern.captures(config_str) {
            return Ok(TctiNameConf::Device(DeviceConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let mssim_pattern = Regex::new(r"^mssim(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = mssim_pattern.captures(config_str) {
            return Ok(TctiNameConf::Mssim(NetworkTPMConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let swtpm_pattern = Regex::new(r"^swtpm(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = swtpm_pattern.captures(config_str) {
            return Ok(TctiNameConf::Swtpm(NetworkTPMConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let tabrmd_pattern = Regex::new(r"^tabrmd(:(.*))?$").unwrap(); //should not fail
        if let Some(captures) = tabrmd_pattern.captures(config_str) {
            return Ok(TctiNameConf::Tabrmd(TabrmdConfig::from_str(
                captures.get(2).map_or("", |m| m.as_str()),
            )?));
        }

        let tbs_pattern = Regex::new(r"^tbs$").unwrap(); //should not fail
        if tbs_pattern.is_match(config_str) {
            return Ok(TctiNameConf::Tbs);
        }

        Err(Error::WrapperError(WrapperErrorKind::InvalidParam))
    }
}

#[test]
fn validate_from_str_tcti() {
    let tcti = TctiNameConf::from_str("mssim:port=1234,host=168.0.0.1").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Mssim(NetworkTPMConfig {
            port: 1234,
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(168, 0, 0, 1)))
        })
    );

    let tcti = TctiNameConf::from_str("mssim").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Mssim(NetworkTPMConfig {
            port: DEFAULT_SERVER_PORT,
            host: Default::default()
        })
    );

    let tcti = TctiNameConf::from_str("swtpm:port=1234,host=168.0.0.1").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Swtpm(NetworkTPMConfig {
            port: 1234,
            host: ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(168, 0, 0, 1)))
        })
    );

    let tcti = TctiNameConf::from_str("swtpm").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Swtpm(NetworkTPMConfig {
            port: DEFAULT_SERVER_PORT,
            host: Default::default()
        })
    );

    let tcti = TctiNameConf::from_str("device:/try/this/path").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Device(DeviceConfig {
            path: PathBuf::from("/try/this/path"),
        })
    );

    let tcti = TctiNameConf::from_str("device").unwrap();
    assert_eq!(tcti, TctiNameConf::Device(Default::default()));

    let tcti = TctiNameConf::from_str("tabrmd:bus_name=some.bus.Name2,bus_type=session").unwrap();
    assert_eq!(
        tcti,
        TctiNameConf::Tabrmd(TabrmdConfig {
            bus_name: String::from("some.bus.Name2"),
            bus_type: BusType::Session
        })
    );

    let tcti = TctiNameConf::from_str("tabrmd").unwrap();
    assert_eq!(tcti, TctiNameConf::Tabrmd(Default::default()));

    let tcti = TctiNameConf::from_str("tbs").unwrap();
    assert_eq!(tcti, TctiNameConf::Tbs);

    assert!(matches!(
        TctiNameConf::from_str("tbs:foo"),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam))
    ));
}

#[test]
fn validate_tbs_to_cstring() {
    let cstr = CString::try_from(TctiNameConf::Tbs).expect("Tbs must convert to CString");
    assert_eq!(
        cstr.to_str().expect("Tbs CString must be valid UTF-8"),
        "tbs",
        "Tbs must produce exactly the 'tbs' loader string with no :config suffix"
    );
}

/// Configuration for a Device TCTI context
///
/// The default configuration uses the library default of
/// `/dev/tpm0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Path to the device node to connect to
    ///
    /// If set to `None`, the default location is used
    path: PathBuf,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            path: PathBuf::from("/dev/tpm0"),
        }
    }
}

impl FromStr for DeviceConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }

        Ok(DeviceConfig {
            path: PathBuf::from(config_str),
        })
    }
}

#[test]
fn validate_from_str_device_config() {
    let config = DeviceConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = DeviceConfig::from_str("/dev/tpm0").unwrap();
    assert_eq!(config.path, PathBuf::from("/dev/tpm0"));
}

/// Configuration for an Mssim TCTI context
///
/// The default configuration will point to `localhost:2321`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTPMConfig {
    /// Address of the server to connect to
    ///
    /// Defaults to `localhost`
    host: ServerAddress,
    /// Port used by the server at the address given in `host`
    ///
    /// Defaults to `2321`
    port: u16,
}

const DEFAULT_SERVER_PORT: u16 = 2321;

impl Default for NetworkTPMConfig {
    fn default() -> Self {
        NetworkTPMConfig {
            host: Default::default(),
            port: DEFAULT_SERVER_PORT,
        }
    }
}

impl FromStr for NetworkTPMConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }
        let host_pattern = Regex::new(r"(,|^)host=(.*?)(,|$)").unwrap(); // should not fail
        let host = host_pattern
            .captures(config_str)
            .map_or(Ok(Default::default()), |captures| {
                ServerAddress::from_str(captures.get(2).map_or("", |m| m.as_str()))
            })?;

        let port_pattern = Regex::new(r"(,|^)port=(.*?)(,|$)").unwrap(); // should not fail
        let port =
            port_pattern
                .captures(config_str)
                .map_or(Ok(DEFAULT_SERVER_PORT), |captures| {
                    u16::from_str(captures.get(2).map_or("", |m| m.as_str()))
                        .or(Err(Error::WrapperError(WrapperErrorKind::InvalidParam)))
                })?;
        Ok(NetworkTPMConfig { host, port })
    }
}

#[test]
fn validate_from_str_networktpm_config() {
    let config = NetworkTPMConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = NetworkTPMConfig::from_str("fjshd89943r=joishdf894u9r,sio0983=9u98jj").unwrap();
    assert_eq!(config, Default::default());

    let config = NetworkTPMConfig::from_str("host=127.0.0.1,random=value").unwrap();
    assert_eq!(
        config.host,
        ServerAddress::Ip(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
    );
    assert_eq!(config.port, DEFAULT_SERVER_PORT);

    let config = NetworkTPMConfig::from_str("port=1234,random=value").unwrap();
    assert_eq!(config.host, Default::default());
    assert_eq!(config.port, 1234);

    let config = NetworkTPMConfig::from_str("host=localhost,port=1234").unwrap();
    assert_eq!(
        config.host,
        ServerAddress::Hostname(String::from("localhost"))
    );
    assert_eq!(config.port, 1234);

    let config = NetworkTPMConfig::from_str("port=1234,host=localhost").unwrap();
    assert_eq!(config.host, "localhost".parse::<ServerAddress>().unwrap());
    assert_eq!(config.port, 1234);

    let config = NetworkTPMConfig::from_str("port=1234,host=localhost,random=value").unwrap();
    assert_eq!(config.host, "localhost".parse::<ServerAddress>().unwrap());
    assert_eq!(config.port, 1234);

    let config = NetworkTPMConfig::from_str("host=1234.1234.1234.1234.12445.111").unwrap();
    assert_eq!(
        config.host,
        ServerAddress::Hostname(String::from("1234.1234.1234.1234.12445.111"))
    );

    let _ = NetworkTPMConfig::from_str("port=abdef").unwrap_err();
    let _ = NetworkTPMConfig::from_str("host=-timey-wimey").unwrap_err();
    let _ = NetworkTPMConfig::from_str("host=abc@def").unwrap_err();
    let _ = NetworkTPMConfig::from_str("host=").unwrap_err();
    let _ = NetworkTPMConfig::from_str("port=").unwrap_err();
    let _ = NetworkTPMConfig::from_str("port=,host=,yas").unwrap_err();
}

/// Address of a TPM server
///
/// The default value is `localhost`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerAddress {
    /// IPv4 or IPv6 address
    Ip(IpAddr),
    /// Hostname
    ///
    /// The string is checked for compatibility with DNS hostnames
    /// before the context is created
    Hostname(String),
}

impl FromStr for ServerAddress {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if let Ok(addr) = IpAddr::from_str(config_str) {
            return Ok(ServerAddress::Ip(addr));
        }

        if !hostname_validator::is_valid(config_str) {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }

        Ok(ServerAddress::Hostname(config_str.to_owned()))
    }
}

impl std::fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerAddress::Ip(addr) => addr.fmt(f),
            ServerAddress::Hostname(name) => name.fmt(f),
        }
    }
}

impl Default for ServerAddress {
    fn default() -> Self {
        ServerAddress::Hostname(String::from("localhost"))
    }
}

/// Configuration for a TABRMD TCTI context
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabrmdConfig {
    /// Bus name to be used by TABRMD
    ///
    /// Defaults tp `com.intel.tss2.Tabrmd`
    // TODO: this could be changed to use the `dbus` crate, which has some
    // more dependencies, though
    bus_name: String,
    /// Bus type to be used by TABRMD
    ///
    /// Defaults to `System`
    bus_type: BusType,
}

const DEFAULT_BUS_NAME: &str = "com.intel.tss2.Tabrmd";

impl Default for TabrmdConfig {
    fn default() -> Self {
        TabrmdConfig {
            bus_name: String::from(DEFAULT_BUS_NAME),
            bus_type: Default::default(),
        }
    }
}

impl FromStr for TabrmdConfig {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        if config_str.is_empty() {
            return Ok(Default::default());
        }
        let bus_name_pattern = Regex::new(r"(,|^)bus_name=(.*?)(,|$)").unwrap(); // should not fail
        let bus_name = bus_name_pattern.captures(config_str).map_or(
            Ok(DEFAULT_BUS_NAME.to_owned()),
            |captures| {
                let valid_bus_name_pattern =
                    Regex::new(r"^[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+$").unwrap(); //should not fail
                if !valid_bus_name_pattern.is_match(captures.get(2).map_or("", |m| m.as_str())) {
                    return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
                }
                Ok(captures.get(2).map_or("", |m| m.as_str()).to_owned())
            },
        )?;

        let bus_type_pattern = Regex::new(r"(,|^)bus_type=(.*?)(,|$)").unwrap(); // should not fail
        let bus_type = bus_type_pattern
            .captures(config_str)
            .map_or(Ok(Default::default()), |captures| {
                BusType::from_str(captures.get(2).map_or("", |m| m.as_str()))
            })?;

        Ok(TabrmdConfig { bus_name, bus_type })
    }
}

/// DBus type for usage with TABRMD
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum BusType {
    #[default]
    System,
    Session,
}

impl FromStr for BusType {
    type Err = Error;

    fn from_str(config_str: &str) -> Result<Self> {
        match config_str {
            "session" => Ok(BusType::Session),
            "system" => Ok(BusType::System),
            _ => Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl std::fmt::Display for BusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BusType::Session => write!(f, "session"),
            BusType::System => write!(f, "system"),
        }
    }
}

#[test]
fn validate_from_str_tabrmd_config() {
    let config = TabrmdConfig::from_str("").unwrap();
    assert_eq!(config, Default::default());

    let config = TabrmdConfig::from_str("fjshd89943r=joishdf894u9r,sio0983=9u98jj").unwrap();
    assert_eq!(config, Default::default());

    let config = TabrmdConfig::from_str("bus_name=one.true.bus.Name,random=value").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, Default::default());

    let config = TabrmdConfig::from_str("bus_type=session,random=value").unwrap();
    assert_eq!(&config.bus_name, DEFAULT_BUS_NAME);
    assert_eq!(config.bus_type, BusType::Session);

    let config = TabrmdConfig::from_str("bus_name=one.true.bus.Name,bus_type=system").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let config = TabrmdConfig::from_str("bus_type=system,bus_name=one.true.bus.Name").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let config =
        TabrmdConfig::from_str("bus_type=system,bus_name=one.true.bus.Name,random=value").unwrap();
    assert_eq!(&config.bus_name, "one.true.bus.Name");
    assert_eq!(config.bus_type, BusType::System);

    let _ = TabrmdConfig::from_str("bus_name=abc&.bcd").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_name=adfsdgdfg4gf4").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_name=,bus_type=,bla?").unwrap_err();
    let _ = TabrmdConfig::from_str("bus_type=randooom").unwrap_err();
}
