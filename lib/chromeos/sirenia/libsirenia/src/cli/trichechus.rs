// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Encapsulates functionality to support the command line interface with the
//! Trichechus and Dugong daemons.

use std::env::current_exe;

use getopts::{self, Matches, Options};
use sys_util::vsock::{SocketAddr as VSocketAddr, VsockCid};
use thiserror::Error as ThisError;

use crate::build_info::BUILD_TIMESTAMP;
use crate::cli::{self, HelpOption, TransportTypeOption};
use crate::transport::{TransportType, DEFAULT_SERVER_PORT};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to get transport type option: {0}")]
    FromMatches(#[source] cli::Error),
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The configuration options that can be configured by command line arguments,
/// flags, and options.
#[derive(Debug, PartialEq)]
pub struct CommonConfig {
    pub connection_type: TransportType,
}

pub fn get_name_and_version_string() -> String {
    let program_name = match current_exe() {
        Ok(exe_path) => exe_path
            .file_name()
            .map(|f| f.to_str().map(|f| f.to_string()))
            .flatten(),
        _ => None,
    };

    if let Some(program_name) = program_name {
        format!("{}: {}", program_name, BUILD_TIMESTAMP)
    } else {
        BUILD_TIMESTAMP.to_string()
    }
}

/// Sets up command line argument parsing and generates a CommonConfig based on
/// the command line entry.
pub fn initialize_common_arguments(
    mut opts: Options,
    args: &[String],
) -> Result<(CommonConfig, Matches)> {
    // Vsock is used as the default because it is the transport used in production.
    // IP is provided for testing and development.
    // Not sure yet what cid default makes sense or if a default makes sense at
    // all.
    let default_connection = TransportType::VsockConnection(VSocketAddr {
        cid: VsockCid::Any,
        port: DEFAULT_SERVER_PORT,
    });
    let mut config = CommonConfig {
        connection_type: default_connection,
    };

    let help_option = HelpOption::new(&mut opts);
    let url_option = TransportTypeOption::default(&mut opts);

    let matches = help_option.parse_and_check_self(&opts, args, get_name_and_version_string);

    if let Some(value) = url_option
        .from_matches(&matches)
        .map_err(Error::FromMatches)?
    {
        config.connection_type = value;
    };
    Ok((config, matches))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::transport::{get_test_ip_uri, get_test_vsock_uri};

    #[test]
    fn initialize_common_arguments_ip_valid() {
        let exp_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1234);
        let exp_result = CommonConfig {
            connection_type: TransportType::IpConnection(exp_socket),
        };
        let value: [String; 2] = ["-U".to_string(), get_test_ip_uri()];
        let (act_result, _) = initialize_common_arguments(Options::new(), &value).unwrap();
        assert_eq!(act_result, exp_result);
    }

    #[test]
    fn initialize_common_arguments_vsock_valid() {
        let vsock = TransportType::VsockConnection(VSocketAddr {
            cid: VsockCid::Local,
            port: 1,
        });
        let exp_result = CommonConfig {
            connection_type: vsock,
        };
        let value: [String; 2] = ["-U".to_string(), get_test_vsock_uri()];
        let (act_result, _) = initialize_common_arguments(Options::new(), &value).unwrap();
        assert_eq!(act_result, exp_result);
    }

    #[test]
    fn initialize_common_arguments_no_args() {
        let default_connection = TransportType::VsockConnection(VSocketAddr {
            cid: VsockCid::Any,
            port: DEFAULT_SERVER_PORT,
        });
        let exp_result = CommonConfig {
            connection_type: default_connection,
        };
        let value: [String; 0] = [];
        let (act_result, _) = initialize_common_arguments(Options::new(), &value).unwrap();
        assert_eq!(act_result, exp_result);
    }
}
