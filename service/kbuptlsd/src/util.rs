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

use std::net::{SocketAddr, ToSocketAddrs};
use std::io;
use std::os::unix::prelude::*;
use std::os::unix::process::{CommandExt as _};
use std::process::{Command};

use nix::fcntl;
use nix::fcntl::{FdFlag};

pub use rustunnel::util::*;

pub trait CommandExt {
    fn preserve_fd(&mut self, fd: &impl AsRawFd);
}

pub fn to_socket_addr(address: impl ToSocketAddrs) -> io::Result<SocketAddr> {
    address.to_socket_addrs()?
           .next()
           .ok_or(io::Error::new(io::ErrorKind::Other, "empty address"))
}

impl CommandExt for Command {
    fn preserve_fd(&mut self, fd: &impl AsRawFd) {
        let fd = fd.as_raw_fd();
        unsafe {
            self.pre_exec(move || {
                let fd_flag_bits = convert_nix(fcntl::fcntl(fd, fcntl::F_GETFD))?;
                let mut fd_flags = FdFlag::from_bits(fd_flag_bits).unwrap_or_else(FdFlag::empty);
                fd_flags.remove(FdFlag::FD_CLOEXEC);
                assert_eq!(convert_nix(fcntl::fcntl(fd, fcntl::F_SETFD(fd_flags)))?, 0);
                Ok(())
            });
        }
    }
}
