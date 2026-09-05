//! TEMPORARY experiment / Windows-only prototype: a native Windows service that provisions TPM
//! NV decay counters over a local named pipe.
//!
//! The service exposes a single, well-defined operation, `AllocateCounter`, over the named pipe
//! `\\.\pipe\decayfmt-provision-test`. It does NOT expose arbitrary TPM commands: the only TPM
//! work it does is call the existing production `TpmContext::allocate_counter()` implementation
//! (the same one the v2 encoder uses) and return the resulting NV index and initial counter value
//! `c0`. Requests are handled sequentially on a single pipe instance.
//!
//! Lifecycle / usage:
//!   * `--install`   register a Windows SCM service (auto start) using the current exe path.
//!   * `--uninstall` stop (if running) and delete that service.
//!   * `--console`   run the provisioner in the foreground (original prototype behavior).
//!   * (no mode)     run under the SCM via `StartServiceCtrlDispatcherW`.
//!
//! Windows-only by construction. On non-Windows hosts this binary is a harmless no-op so the
//! cross-platform CI matrix (`cargo clippy --all-targets` / `cargo test`) keeps building it.
//! Production source is untouched; this is a standalone `src/bin` target. The Win32 named-pipe,
//! security-descriptor, and SCM surface is hand-rolled FFI so that no `windows`/`winapi` crate
//! dependency has to be added to `Cargo.toml`.

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        return provisioner::run();
    }

    #[cfg(not(windows))]
    {
        eprintln!("ms_provisioner is a Windows-only prototype; nothing to do here.");
    }

    ExitCode::SUCCESS
}

#[cfg(windows)]
mod provisioner {
    use std::mem::size_of;
    use std::os::raw::c_void;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use decayfmt::tpm::TpmContext;

    // Named-pipe constants (winnt.h / winbase.h).
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const N_MAX_INSTANCES: u32 = 1;
    const PIPE_BUFFER_SIZE: u32 = 4096;
    const ERROR_PIPE_CONNECTED: u32 = 535;

    /// The local named pipe this service serves.
    const PIPE_NAME: &str = r"\\.\pipe\decayfmt-provision-test";

    /// SDDL DACL for the pipe: deny NETWORK logons (S-1-5-2) first, then allow AUTHENTICATED
    /// USERS (S-1-5-11). A remote client connects under a network logon whose token carries the
    /// NETWORK SID, so the deny ACE fires before the allow ACE; a locally-authenticated caller
    /// does not carry the NETWORK SID and is admitted by the allow ACE. This admits local
    /// authenticated users while rejecting remote clients. (`D:P` = protected DACL with no
    /// inherited ACEs.)
    const PIPE_SECURITY_DESCRIPTOR_SDDL: &str = "D:P(D;;GA;;;S-1-5-2)(A;;GA;;;S-1-5-11)";

    const MAX_REQUEST_BYTES: usize = 1024;

    /// The Windows SCM service name (and display name) registered by `--install`.
    const SERVICE_NAME: &str = "DecayFmtProvisionerTest";

    // Service control manager / service type constants (winsvc.h).
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
    const SERVICE_AUTO_START: u32 = 0x0000_0002;
    const SERVICE_ERROR_NORMAL: u32 = 0x0000_0001;
    const SERVICE_STOPPED: u32 = 0x0000_0001;
    const SERVICE_START_PENDING: u32 = 0x0000_0002;
    const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
    const SERVICE_RUNNING: u32 = 0x0000_0004;
    const SERVICE_ACCEPT_STOP: u32 = 0x0000_0001;
    const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
    const NO_ERROR: u32 = 0;

    // Access flags.
    const SC_MANAGER_ALL_ACCESS: u32 = 0x000F_003F;
    const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;

    // Win32 error codes referenced by this prototype.
    const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
    const ERROR_SERVICE_EXISTS: u32 = 1073;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    /// `SERVICE_STATUS` as returned by / passed to the SCM.
    #[repr(C)]
    struct ServiceStatus {
        dw_service_type: u32,
        dw_current_state: u32,
        dw_controls_accepted: u32,
        dw_win32_exit_code: u32,
        dw_service_specific_exit_code: u32,
        dw_check_point: u32,
        dw_wait_hint: u32,
    }

    /// `SERVICE_TABLE_ENTRYW` for `StartServiceCtrlDispatcherW`.
    #[repr(C)]
    struct ServiceTableEntry {
        service_name: *const u16,
        service_proc: Option<ServiceMainFn>,
    }

    type ServiceMainFn =
        unsafe extern "system" fn(dw_num_service_args: u32, lp_service_arg_vectors: *mut *mut u16);
    type ControlHandlerFn = unsafe extern "system" fn(
        dw_control: u32,
        dw_event_type: u32,
        lp_event_data: *mut c_void,
        lp_context: *mut c_void,
    ) -> u32;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            lp_name: *const u16,
            dw_open_mode: u32,
            dw_pipe_mode: u32,
            n_max_instances: u32,
            n_out_buffer_size: u32,
            n_in_buffer_size: u32,
            n_default_timeout: u32,
            lp_security_attributes: *const SecurityAttributes,
        ) -> *mut c_void;
        fn ConnectNamedPipe(h_named_pipe: *mut c_void, lp_overlapped: *mut c_void) -> i32;
        fn DisconnectNamedPipe(h_named_pipe: *mut c_void) -> i32;
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
        fn GetModuleFileNameW(lp_module: *mut c_void, lp_filename: *mut u16, n_size: u32) -> u32;
        fn GetLastError() -> u32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn OpenSCManagerW(
            lp_machine_name: *const u16,
            lp_database_name: *const u16,
            dw_desired_access: u32,
        ) -> *mut c_void;
        fn CreateServiceW(
            h_sc_manager: *mut c_void,
            lp_service_name: *const u16,
            lp_display_name: *const u16,
            dw_desired_access: u32,
            dw_service_type: u32,
            dw_start_type: u32,
            dw_error_control: u32,
            lp_binary_path_name: *const u16,
            lp_load_order_group: *const u16,
            lpdw_tag_id: *mut u32,
            lp_dependencies: *const u16,
            lp_service_start_name: *const u16,
            lp_password: *const u16,
        ) -> *mut c_void;
        fn OpenServiceW(
            h_sc_manager: *mut c_void,
            lp_service_name: *const u16,
            dw_desired_access: u32,
        ) -> *mut c_void;
        fn DeleteService(h_service: *mut c_void) -> i32;
        fn CloseServiceHandle(h_sc_object: *mut c_void) -> i32;
        fn QueryServiceStatus(h_service: *mut c_void, lp_service_status: *mut ServiceStatus)
            -> i32;
        fn ControlService(
            h_service: *mut c_void,
            dw_control: u32,
            lp_service_status: *mut ServiceStatus,
        ) -> i32;
        fn StartServiceCtrlDispatcherW(lp_service_start_table: *mut ServiceTableEntry) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            lp_service_name: *const u16,
            lp_handler_proc: Option<ControlHandlerFn>,
            lp_context: *mut c_void,
        ) -> *mut c_void;
        fn SetServiceStatus(
            h_service_status: *mut c_void,
            lp_service_status: *const ServiceStatus,
        ) -> i32;
    }

    /// Set when the SCM asks the service to stop; read by the provisioner loop on the service
    /// thread. Never set in `--console` mode.
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    /// The live named-pipe handle (as a usize). The value is swapped to 0 exactly once, by either
    /// the service control handler (to abort a pending blocking connect) or the service thread
    /// (during cleanup), so the underlying handle is closed at most once.
    static PIPE_HANDLE: AtomicUsize = AtomicUsize::new(0);
    /// The `SERVICE_STATUS_HANDLE` returned by `RegisterServiceCtrlHandlerExW`.
    static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

    /// Entry point used by `main()` on Windows. Dispatches on the command-line mode.
    pub(crate) fn run() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();

        if args.iter().any(|a| a == "--install") {
            return do_install();
        }
        if args.iter().any(|a| a == "--uninstall") {
            return do_uninstall();
        }
        if args.iter().any(|a| a == "--console") {
            let tcti = tcti_from_args(&args);
            println!(
                "[info] console mode; connecting with tcti = {:?}",
                tcti.as_deref()
            );
            return run_console(tcti.as_deref());
        }

        // No mode flag: assume the SCM launched us and act as a service.
        dispatch_service()
    }

    /// Extracts the TCTI from `--tcti <name>` or a bare positional argument, mirroring the
    /// original prototype's argument handling. Mode flags are skipped.
    fn tcti_from_args(args: &[String]) -> Option<String> {
        let mut index = 0;
        while index < args.len() {
            if args[index] == "--tcti" {
                return args.get(index + 1).cloned();
            }
            if !args[index].starts_with("--") {
                return Some(args[index].clone());
            }
            index += 1;
        }
        None
    }

    /// Returns the fully-qualified path of the current executable.
    fn current_exe_path() -> Option<String> {
        let mut buffer = [0u16; 32768];
        let len = unsafe {
            GetModuleFileNameW(
                std::ptr::null_mut(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        if len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..len as usize]))
    }

    /// Appends a NUL terminator so the wide buffer is usable as a `PCWSTR`.
    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    /// `--install`: register the SCM service. Opens the SCM, calls `CreateServiceW` for
    /// `SERVICE_NAME` as a `SERVICE_WIN32_OWN_PROCESS` with `SERVICE_AUTO_START`, then closes the
    /// handles. The service is NOT started.
    fn do_install() -> ExitCode {
        let sc_manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) };
        if sc_manager.is_null() {
            eprintln!(
                "[error] OpenSCManagerW failed (last error {}); administrator rights may be required",
                last_error()
            );
            return ExitCode::FAILURE;
        }

        let Some(exe_path) = current_exe_path() else {
            eprintln!("[error] could not determine the current executable path");
            unsafe {
                CloseServiceHandle(sc_manager);
            }
            return ExitCode::FAILURE;
        };

        // The service must talk to the Windows TPM through the TBS TCTI, so the image path carries
        // the same `--tcti tbs` argument the console mode uses.
        let command_line = format!("\"{exe_path}\" --tcti tbs");
        let service_name_wide = to_wide(SERVICE_NAME);
        let command_wide = to_wide(&command_line);

        let service = unsafe {
            CreateServiceW(
                sc_manager,
                service_name_wide.as_ptr(),
                service_name_wide.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                command_wide.as_ptr(),
                std::ptr::null(),     // load order group
                std::ptr::null_mut(), // tag id
                std::ptr::null(),     // dependencies
                std::ptr::null(),     // service start name (LocalSystem)
                std::ptr::null(),     // password
            )
        };
        if service.is_null() {
            let error = last_error();
            eprintln!("[error] CreateServiceW failed (last error {error})");
            if error == ERROR_SERVICE_EXISTS {
                eprintln!("[error] {SERVICE_NAME} is already installed; run --uninstall first");
            }
            unsafe {
                CloseServiceHandle(sc_manager);
            }
            return ExitCode::FAILURE;
        }

        println!(
            "[info] installed service '{SERVICE_NAME}' (auto start, own process) with command line: {command_line}"
        );

        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
        }
        ExitCode::SUCCESS
    }

    /// `--uninstall`: open the service, stop it if running, delete it, then close the handles.
    fn do_uninstall() -> ExitCode {
        let sc_manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) };
        if sc_manager.is_null() {
            eprintln!(
                "[error] OpenSCManagerW failed (last error {}); administrator rights may be required",
                last_error()
            );
            return ExitCode::FAILURE;
        }

        let service_name_wide = to_wide(SERVICE_NAME);
        let service =
            unsafe { OpenServiceW(sc_manager, service_name_wide.as_ptr(), SERVICE_ALL_ACCESS) };
        if service.is_null() {
            let error = last_error();
            eprintln!("[error] OpenServiceW failed (last error {error})");
            if error == ERROR_SERVICE_DOES_NOT_EXIST {
                eprintln!("[error] {SERVICE_NAME} is not installed");
            }
            unsafe {
                CloseServiceHandle(sc_manager);
            }
            return ExitCode::FAILURE;
        }

        // Stop the service first if it is currently running.
        let mut status = zero_service_status();
        let querying = unsafe { QueryServiceStatus(service, &mut status) };
        if querying != 0 && status.dw_current_state == SERVICE_RUNNING {
            println!("[info] stopping running service '{SERVICE_NAME}'");
            let mut stopped = zero_service_status();
            unsafe {
                ControlService(service, SERVICE_CONTROL_STOP, &mut stopped);
            }
            // Poll until the service reports stopped (bounded wait).
            for _ in 0..60 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let mut current = zero_service_status();
                let ok = unsafe { QueryServiceStatus(service, &mut current) };
                if ok != 0 && current.dw_current_state == SERVICE_STOPPED {
                    break;
                }
            }
        }

        let deleted = unsafe { DeleteService(service) };
        if deleted == 0 {
            eprintln!("[error] DeleteService failed (last error {})", last_error());
            unsafe {
                CloseServiceHandle(service);
                CloseServiceHandle(sc_manager);
            }
            return ExitCode::FAILURE;
        }

        println!("[info] deleted service '{SERVICE_NAME}'");
        unsafe {
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
        }
        ExitCode::SUCCESS
    }

    /// No-mode path: register a service table and hand control to the SCM dispatcher. This
    /// blocks until the service stops and `ServiceMain` returns.
    fn dispatch_service() -> ExitCode {
        let service_name_wide = to_wide(SERVICE_NAME);
        let mut service_table = [
            ServiceTableEntry {
                service_name: service_name_wide.as_ptr(),
                service_proc: Some(service_main),
            },
            ServiceTableEntry {
                service_name: std::ptr::null(),
                service_proc: None,
            },
        ];

        let dispatched = unsafe { StartServiceCtrlDispatcherW(service_table.as_mut_ptr()) };
        if dispatched == 0 {
            let error = last_error();
            eprintln!("[error] StartServiceCtrlDispatcherW failed (last error {error})");
            if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                eprintln!("[error] not started by the service control manager; run with --console instead");
            }
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    }

    /// `ServiceMain`: register the control handler, report `START_PENDING`, initialize the TPM
    /// and named-pipe provisioner, report `RUNNING` (accepting `STOP`), run the request loop, and
    /// finally clean up and report `STOPPED`.
    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let service_name_wide = to_wide(SERVICE_NAME);
        let status_handle = RegisterServiceCtrlHandlerExW(
            service_name_wide.as_ptr(),
            Some(service_control_handler),
            std::ptr::null_mut(),
        );
        if status_handle.is_null() {
            eprintln!(
                "[error] RegisterServiceCtrlHandlerExW failed (last error {})",
                last_error()
            );
            return;
        }
        STATUS_HANDLE.store(status_handle as usize, Ordering::SeqCst);

        // Report that the service is starting.
        set_service_status(SERVICE_START_PENDING, 0, 1, 8000, 0);

        // Resolve the TCTI from the process command line (present when installed with
        // `--tcti tbs`); SCM launches carry no arguments, so this is None then.
        let args: Vec<String> = std::env::args().skip(1).collect();
        let tcti = tcti_from_args(&args);
        println!(
            "[info] service connecting with tcti = {:?}",
            tcti.as_deref()
        );

        match provisioner_start(tcti.as_deref()) {
            Err(message) => {
                eprintln!("[error] service initialization failed: {message}");
                set_service_status(SERVICE_STOPPED, 0, 0, 0, 1);
            }
            Ok(mut provisioner) => {
                // Ready: accept stop control requests and run the request loop.
                set_service_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0, 0);

                let result = provisioner_serve(&mut provisioner);
                if let Err(message) = result {
                    eprintln!("[error] provisioner loop stopped with an error: {message}");
                }

                // Clean up the pipe handle (owned via the global swap) and let `TpmContext` drop.
                provisioner_close();
                set_service_status(SERVICE_STOPPED, 0, 0, 0, 0);
            }
        }
    }

    /// Control handler registered via `RegisterServiceCtrlHandlerExW`. It runs on an SCM thread.
    /// On `SERVICE_CONTROL_STOP` it signals the service thread and closes the pipe handle so a
    /// pending blocking `ConnectNamedPipe` returns, then reports `STOP_PENDING`. The service
    /// thread reports the final `STOPPED`.
    unsafe extern "system" fn service_control_handler(
        dw_control: u32,
        _dw_event_type: u32,
        _lp_event_data: *mut c_void,
        _lp_context: *mut c_void,
    ) -> u32 {
        match dw_control {
            SERVICE_CONTROL_STOP => {
                STOP_REQUESTED.store(true, Ordering::SeqCst);

                // Abort a pending blocking ConnectNamedPipe by taking and closing the pipe. The
                // swap makes this the sole closer of that handle value.
                let pipe = PIPE_HANDLE.swap(0, Ordering::SeqCst) as *mut c_void;
                if !pipe.is_null() {
                    DisconnectNamedPipe(pipe);
                    CloseHandle(pipe);
                }

                set_service_status(SERVICE_STOP_PENDING, 0, 1, 5000, 0);
                NO_ERROR
            }
            _ => NO_ERROR,
        }
    }

    /// Reports the current service status through the cached `SERVICE_STATUS_HANDLE`.
    fn set_service_status(
        state: u32,
        controls_accepted: u32,
        checkpoint: u32,
        wait_hint: u32,
        win32_exit_code: u32,
    ) {
        let status_handle = STATUS_HANDLE.load(Ordering::SeqCst) as *mut c_void;
        if status_handle.is_null() {
            return;
        }
        let status = ServiceStatus {
            dw_service_type: SERVICE_WIN32_OWN_PROCESS,
            dw_current_state: state,
            dw_controls_accepted: controls_accepted,
            dw_win32_exit_code: win32_exit_code,
            dw_service_specific_exit_code: 0,
            dw_check_point: checkpoint,
            dw_wait_hint: wait_hint,
        };
        unsafe {
            SetServiceStatus(status_handle, &status);
        }
    }

    fn zero_service_status() -> ServiceStatus {
        ServiceStatus {
            dw_service_type: 0,
            dw_current_state: 0,
            dw_controls_accepted: 0,
            dw_win32_exit_code: 0,
            dw_service_specific_exit_code: 0,
            dw_check_point: 0,
            dw_wait_hint: 0,
        }
    }

    /// A running provisioner: a connected TPM context plus the live named-pipe instance.
    struct Provisioner {
        tpm: TpmContext,
        pipe: *mut c_void,
    }

    /// `--console`: run the original foreground provisioner exactly (blocking loop, no SCM).
    fn run_console(tcti: Option<&str>) -> ExitCode {
        match provisioner_start(tcti) {
            Err(message) => {
                eprintln!("[error] {message}");
                ExitCode::FAILURE
            }
            Ok(mut provisioner) => {
                println!("[info] serving request loop on {PIPE_NAME}");
                match provisioner_serve(&mut provisioner) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(message) => {
                        eprintln!("[error] {message}");
                        provisioner_close();
                        ExitCode::FAILURE
                    }
                }
            }
        }
    }

    /// Connects to the TPM (via `TpmContext`) and creates the named-pipe instance. Registers the
    /// pipe handle globally so the service control handler can abort a pending connect on stop.
    fn provisioner_start(tcti: Option<&str>) -> Result<Provisioner, String> {
        let tpm = TpmContext::connect_optional(tcti).map_err(|e| format!("connect failed: {e}"))?;

        let security_descriptor = build_security_descriptor()
            .ok_or_else(|| "failed to build the pipe security descriptor".to_string())?;
        let pipe = create_pipe(security_descriptor)
            .ok_or_else(|| format!("failed to create named pipe {PIPE_NAME}"))?;

        PIPE_HANDLE.store(pipe as usize, Ordering::SeqCst);
        Ok(Provisioner { tpm, pipe })
    }

    /// Runs the request loop until the SCM requests a stop (service mode) or a fatal pipe error
    /// occurs. In `--console` mode `STOP_REQUESTED` is never set, so this blocks like the original
    /// prototype.
    fn provisioner_serve(provisioner: &mut Provisioner) -> Result<(), String> {
        let pipe = provisioner.pipe;
        loop {
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                return Ok(());
            }

            // Blocking wait for the next client connection.
            let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
            if connected == 0 && last_error() != ERROR_PIPE_CONNECTED {
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    return Ok(());
                }
                return Err(format!(
                    "ConnectNamedPipe failed (last error {})",
                    last_error()
                ));
            }

            // A stop could have arrived while we were waiting for a connection; bail if so.
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                return Ok(());
            }

            // A client is connected: read exactly one request, service it, reply, then disconnect
            // and go back to waiting for the next client.
            let request = read_request(pipe);
            let response = handle_request(&request, &mut provisioner.tpm);
            write_response(pipe, response.as_bytes());

            unsafe {
                DisconnectNamedPipe(pipe);
            }
        }
    }

    /// Closes the named-pipe instance. The handle is owned via the global swap so it is closed at
    /// most once (the control handler may already have taken and closed it to abort a connect).
    fn provisioner_close() {
        let pipe = PIPE_HANDLE.swap(0, Ordering::SeqCst) as *mut c_void;
        if !pipe.is_null() {
            unsafe {
                CloseHandle(pipe);
            }
        }
    }

    /// Builds the security descriptor from the SDDL string above, or logs and returns `None`.
    fn build_security_descriptor() -> Option<*mut c_void> {
        let sddl = to_wide(PIPE_SECURITY_DESCRIPTOR_SDDL);
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1, // SDDL_REVISION_1
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            eprintln!(
                "[error] ConvertStringSecurityDescriptorToSecurityDescriptorW failed (last error {})",
                last_error()
            );
            return None;
        }
        Some(descriptor)
    }

    /// Creates a single named-pipe instance guarded by `security_descriptor`. The descriptor is
    /// intentionally kept alive for the whole process (never freed): it is consulted for each
    /// access check on connect.
    fn create_pipe(security_descriptor: *mut c_void) -> Option<*mut c_void> {
        let pipe_name = to_wide(PIPE_NAME);
        let security_attributes = SecurityAttributes {
            n_length: size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: security_descriptor,
            b_inherit_handle: 0,
        };
        let pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                N_MAX_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                &security_attributes,
            )
        };
        if pipe as isize == -1 {
            eprintln!(
                "[error] CreateNamedPipeW failed (last error {}); is another server already running?",
                last_error()
            );
            return None;
        }
        Some(pipe)
    }

    /// Reads one request. Stops at a newline, at end-of-stream, or after a reasonable cap.
    fn read_request(pipe: *mut c_void) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    pipe,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || bytes_read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..bytes_read as usize]);
            if request.len() >= MAX_REQUEST_BYTES || request.contains(&b'\n') {
                break;
            }
        }
        request
    }

    /// Services a single request. The only supported opcode is `AllocateCounter`, which calls the
    /// production NV counter allocation. Everything else is answered with an error; no arbitrary
    /// TPM command is ever dispatched.
    fn handle_request(request: &[u8], tpm: &mut TpmContext) -> String {
        let text = String::from_utf8_lossy(request);
        let trimmed = text.trim();
        eprintln!("[info] request: {trimmed:?}");

        if trimmed != "AllocateCounter" {
            return "ERR unknown request (only AllocateCounter is supported)\n".to_string();
        }

        match tpm.allocate_counter() {
            Ok(info) => {
                let nv_auth_hex = hex_bytes(&info.nv_auth);
                println!(
                    "[info] allocated counter nv_index=0x{:08X} c0={} nv_auth=0x{nv_auth_hex}",
                    info.nv_index, info.c0
                );
                format!(
                    "OK nv_index=0x{:08X} c0={} nv_auth=0x{nv_auth_hex}\n",
                    info.nv_index, info.c0
                )
            }
            Err(e) => {
                eprintln!("[error] allocate_counter failed: {e}");
                format!("ERR allocate failed: {e}\n")
            }
        }
    }

    /// Lowercase hex encoding of a byte slice (used for the echoed `nv_auth`).
    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Writes `bytes` back to the connected client.
    fn write_response(pipe: *mut c_void, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut bytes_written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            eprintln!("[error] WriteFile failed (last error {})", last_error());
        }
    }
}
