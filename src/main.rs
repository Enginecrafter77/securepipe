/*
securepipe - a fast and secure means of transferring data between networked machines
Copyright (C) 2025 Enginecrafter77

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::{
    env,
    fs::File,
    io::{self, Read, Write},
};

use getopts::Options;
use log::info;

use crate::connection::{
    SecurePipePeer,
    config::{SecurePipeConfig, SecurePipeMode},
};

mod buffer;
mod connection;
mod filter;
mod nonce;
mod pump;

const DEFAULT_PORT: u16 = 4096;

macro_rules! printerrln {
    ($($arg:tt)*) => {
        writeln!(io::stderr(), $($arg)*).expect("STDERR write failed");
    };
}

const DESCRIPTION: &str = include_str!("../helpstring.txt");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut opts = Options::new();

    opts.optflag("h", "help", "Displays this help message");
    opts.optflag("d", "decrypt", "Designated decrypting end");
    opts.optopt("i", "input", "Read input from", "source");
    opts.optopt("o", "output", "Write output to", "dest");
    opts.optopt("p", "port", "Use the given port (default: 4096)", "port");
    opts.optopt(
        "b",
        "block-size",
        "The size of plaintext blocks [DISABLED]",
        "block-size",
    );
    opts.optflag("z", "compress", "Use LZ4 compression for network transfer");
    opts.optflagmulti("v", "verbose", "Add 1 verbosity level");
    opts.optflag("q", "quiet", "Suppresses all logging output");

    let m = opts
        .parse(std::env::args())
        .expect("Parsing arguments failed");

    stderrlog::new()
        .module(module_path!())
        .quiet(m.opt_present("q"))
        .verbosity(m.opt_count("v"))
        .init()
        .expect("Logging framework init failed");

    if m.opt_present("h") {
        printerrln!(
            "{} [host]\n{}{}\nSecurepipe version: {}",
            opts.short_usage("securepipe"),
            opts.usage("A simple pipe for secure network transfers."),
            DESCRIPTION,
            PKG_VERSION
        );
        return;
    }

    let mode = {
        if m.opt_present("d") {
            SecurePipeMode::DECRYPTING
        } else {
            SecurePipeMode::ENCRYPTING
        }
    };

    let port = m
        .opt_str("p")
        .map(|x| x.parse::<u16>().expect("Parsing port number failed"))
        .unwrap_or(DEFAULT_PORT);

    let config = SecurePipeConfig::new(mode, m.opt_present("z"));
    let peer = match m.free.get(1).cloned() {
        Some(remote) => SecurePipePeer::client(config, remote, port),
        None => SecurePipePeer::server(config, port),
    };
    let mut connection = peer
        .connect()
        .expect("Unable to estabilish peer connection");

    let mut src: Box<dyn Read> = match m.opt_str("i") {
        None => Box::new(io::stdin()),
        Some(filename) => Box::new(File::open(filename).expect("Input file open failed")),
    };

    let mut dest: Box<dyn Write> = match m.opt_str("o") {
        None => Box::new(io::stdout()),
        Some(filename) => Box::new(File::create(filename).expect("Output file open failed")),
    };

    if mode == SecurePipeMode::DECRYPTING {
        info!("Decrypting socket stream to output...");
        connection.pump_out(dest.as_mut()).expect("IO error");
    } else {
        info!("Encrypting input to socket stream...");
        connection.pump_in(src.as_mut()).expect("IO error");
    }
}
