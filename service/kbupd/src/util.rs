//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::path::{Path, PathBuf};

pub use kbupd_util::*;

pub fn join_if_relative(dir_path: &Path, file_path: &Path) -> PathBuf {
    if file_path.is_relative() {
        dir_path.join(file_path)
    } else {
        file_path.to_owned()
    }
}
