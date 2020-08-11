//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use alloc::string::ToString;
use core::panic::PanicInfo;

use super::bindgen_wrapper::kbupd_enclave_ocall_panic;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let message = info.to_string();
    unsafe {
        kbupd_enclave_ocall_panic(message.as_ptr(), message.len());
        libc::abort()
    }
}
