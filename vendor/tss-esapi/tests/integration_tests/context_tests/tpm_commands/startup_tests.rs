// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_startup {
    use crate::common::create_ctx_without_session;
    use tss_esapi::constants::StartupType;

    #[test]
    fn test_startup() {
        let mut context = create_ctx_without_session();
        context.startup(StartupType::Clear).unwrap();
    }
}

mod test_shutdown {
    use crate::common::create_ctx_without_session;
    use tss_esapi::constants::StartupType;
    #[test]
    fn test_shutdown() {
        let mut context = create_ctx_without_session();
        context.shutdown(StartupType::Clear).unwrap();
        // Re-start the TPM so our tests won't fail
        context.startup(StartupType::Clear).unwrap();
    }
}
