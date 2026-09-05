// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_self_test {
    use crate::common::create_ctx_without_session;

    #[test]
    fn test_self_test() {
        let mut context = create_ctx_without_session();
        context.self_test(false).unwrap();
        context.self_test(true).unwrap();
    }
}

mod test_get_test_result {
    use crate::common::create_ctx_without_session;
    #[test]
    fn test_get_test_result() {
        let mut context = create_ctx_without_session();
        let (_, rc) = context.get_test_result().unwrap();
        rc.unwrap();
    }
}
