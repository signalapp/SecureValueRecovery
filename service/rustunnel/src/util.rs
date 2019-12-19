/*
 * Copyright (C) 2019 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::io;
use std::os::unix::prelude::*;

use nix::errno::{Errno};
use nix::fcntl;
use nix::fcntl::{OFlag};

pub fn convert_nix<T>(result: nix::Result<T>) -> io::Result<T> {
    match result {
        Ok(value)                             => Ok(value),
        Err(nix::Error::Sys(errno))           => Err(errno.into()),
        Err(nix::Error::InvalidPath)          => Err(Errno::EINVAL.into()),
        Err(nix::Error::InvalidUtf8)          => Err(Errno::EINVAL.into()),
        Err(nix::Error::UnsupportedOperation) => Err(io::Error::new(io::ErrorKind::Other, "unsupported")),
    }
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = OFlag::from_bits(convert_nix(fcntl::fcntl(fd, fcntl::F_GETFL))?).unwrap_or_else(OFlag::empty);
    assert_eq!(convert_nix(fcntl::fcntl(fd, fcntl::F_SETFL(flags | OFlag::O_NONBLOCK)))?, 0);
    Ok(())
}
