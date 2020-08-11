//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

macro_rules! error {
    ($($arg:tt)*) => (log!($crate::protobufs::kbupd::EnclaveLogLevel::Error, $($arg)*));
}
macro_rules! warn {
    ($($arg:tt)*) => (log!($crate::protobufs::kbupd::EnclaveLogLevel::Warn, $($arg)*));
}
macro_rules! info {
    ($($arg:tt)*) => (log!($crate::protobufs::kbupd::EnclaveLogLevel::Info, $($arg)*));
}
macro_rules! verbose {
    ($($arg:tt)*) => (
        if $crate::logging::verbose_logging_enabled() {
            log!($crate::protobufs::kbupd::EnclaveLogLevel::Info, $($arg)*)
        } else {
            #[cfg(feature = "debug")]
            log!($crate::protobufs::kbupd::EnclaveLogLevel::Info, $($arg)*)
        }
    );
}
macro_rules! debug {
    ($($arg:tt)*) => ({
        #[cfg(feature = "debug")]
        #[cfg(feature = "insecure")]
        log!($crate::protobufs::kbupd::EnclaveLogLevel::Debug, $($arg)*)
    });
}

macro_rules! log {
    ($level:expr, $msg:expr) => ({
        log!($level, "{}", $msg)
    });
    ($level:expr, $msg:expr,) => ({
        log!($level, $msg)
    });
    ($level:expr, $fmt:expr, $($arg:tt)*) => ({
        $crate::kbupd_send($crate::protobufs::kbupd::EnclaveMessage {
            inner: Some($crate::protobufs::kbupd::enclave_message::Inner::EnclaveLogSignal($crate::protobufs::kbupd::EnclaveLogSignal {
                message: ::alloc::format!($fmt, $($arg)*).into_bytes(),
                module:  module_path!().as_bytes().to_vec(),
                file:    file!().rsplit("/").next().unwrap_or_default().as_bytes().to_vec(),
                line:    line!(),
                level:   $level.into(),
            })),
        });
    });
}

macro_rules! assert_true {
    ($($arg:tt)*) => ({
        assert!($($arg)+);
        true
    });
}

macro_rules! assert_match {
    ($pat:pat = $expr:expr) => ({
        if let $pat = $expr {
            true
        } else {
            panic!("assertion failed: `$pat = $expr`")
        }
    });
    ($pat:pat = $expr:expr, $($arg:tt)*) => ({
        if let $pat = $expr {
            true
        } else {
            panic!("assertion failed: `$pat = $expr`: {}", format_args!($($arg)+))
        }
    });
}

macro_rules! static_unreachable {
    () => {{
        #[cfg(not(debug_assertions))]
        {
            extern "C" {
                pub fn __static_unreachable() -> !;
            }
            unsafe { __static_unreachable() };
        }
        #[cfg(debug_assertions)]
        unreachable!()
    }};
}
