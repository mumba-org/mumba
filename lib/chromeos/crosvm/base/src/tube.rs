// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use remain::sorted;
use std::io;

use thiserror::Error as ThisError;

#[cfg_attr(windows, path = "windows/tube.rs")]
#[cfg_attr(not(windows), path = "unix/tube.rs")]
mod tube;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
pub use tube::*;

impl Tube {
    /// Creates a Send/Recv pair of Tubes.
    pub fn directional_pair() -> Result<(SendTube, RecvTube)> {
        let (t1, t2) = Self::pair()?;
        Ok((SendTube(t1), RecvTube(t2)))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
/// A Tube end which can only send messages. Cloneable.
pub struct SendTube(Tube);

#[allow(dead_code)]
impl SendTube {
    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_send_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }

    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        self.0.send(msg)
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(SendTube(
            #[allow(deprecated)]
            self.0.try_clone()?,
        ))
    }

    /// Never call this function, it is for use by cros_async to provide
    /// directional wrapper types only. Using it in any other context may
    /// violate concurrency assumptions. (Type splitting across crates has put
    /// us in a situation where we can't use Rust privacy to enforce this.)
    #[deprecated]
    pub fn into_tube(self) -> Tube {
        self.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
/// A Tube end which can only recv messages.
pub struct RecvTube(Tube);

#[allow(dead_code)]
impl RecvTube {
    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        self.0.recv()
    }

    /// TODO(b/145998747, b/184398671): this method should be removed.
    pub fn set_recv_timeout(&self, _timeout: Option<Duration>) -> Result<()> {
        unimplemented!("To be removed/refactored upstream.");
    }

    /// Never call this function, it is for use by cros_async to provide
    /// directional wrapper types only. Using it in any other context may
    /// violate concurrency assumptions. (Type splitting across crates has put
    /// us in a situation where we can't use Rust privacy to enforce this.)
    #[deprecated]
    pub fn into_tube(self) -> Tube {
        self.0
    }
}

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[cfg(windows)]
    #[error("attempt to duplicate descriptor via broker failed")]
    BrokerDupDescriptor,
    #[error("failed to clone transport: {0}")]
    Clone(io::Error),
    #[error("tube was disconnected")]
    Disconnected,
    #[error("failed to duplicate descriptor: {0}")]
    DupDescriptor(io::Error),
    #[cfg(windows)]
    #[error("failed to flush named pipe: {0}")]
    Flush(io::Error),
    #[error("failed to serialize/deserialize json from packet: {0}")]
    Json(serde_json::Error),
    #[error("cancelled a queued async operation")]
    OperationCancelled,
    #[error("failed to crate tube pair: {0}")]
    Pair(io::Error),
    #[error("failed to receive packet: {0}")]
    Recv(io::Error),
    #[error("Received a message with a zero sized body. This should not happen.")]
    RecvUnexpectedEmptyBody,
    #[error("failed to send packet: {0}")]
    Send(crate::platform::Error),
    #[error("failed to send packet: {0}")]
    SendIo(io::Error),
    #[error("failed to write packet to intermediate buffer: {0}")]
    SendIoBuf(io::Error),
    #[error("failed to set recv timeout: {0}")]
    SetRecvTimeout(io::Error),
    #[error("failed to set send timeout: {0}")]
    SetSendTimeout(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;

    use std::{collections::HashMap, time::Duration};

    use serde::{Deserialize, Serialize};
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    #[derive(Serialize, Deserialize)]
    struct DataStruct {
        x: u32,
    }

    // Magics to identify which producer sent a message (& detect corruption).
    const PRODUCER_ID_1: u32 = 801279273;
    const PRODUCER_ID_2: u32 = 345234861;

    #[track_caller]
    fn test_event_pair(send: Event, recv: Event) {
        send.write(1).unwrap();
        recv.read_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn send_recv_no_fd() {
        let (s1, s2) = Tube::pair().unwrap();

        let test_msg = "hello world";
        s1.send(&test_msg).unwrap();
        let recv_msg: String = s2.recv().unwrap();

        assert_eq!(test_msg, recv_msg);
    }

    #[test]
    fn send_recv_one_fd() {
        #[derive(Serialize, Deserialize)]
        struct EventStruct {
            x: u32,
            b: Event,
        }

        let (s1, s2) = Tube::pair().unwrap();

        let test_msg = EventStruct {
            x: 100,
            b: Event::new().unwrap(),
        };
        s1.send(&test_msg).unwrap();
        let recv_msg: EventStruct = s2.recv().unwrap();

        assert_eq!(test_msg.x, recv_msg.x);

        test_event_pair(test_msg.b, recv_msg.b);
    }

    /// Send messages to a Tube with the given identifier (see `consume_messages`; we use this to
    /// track different message producers).
    #[track_caller]
    fn produce_messages(tube: SendTube, data: u32, barrier: Arc<Barrier>) -> SendTube {
        let data = DataStruct { x: data };
        barrier.wait();
        for _ in 0..100 {
            tube.send(&data).unwrap();
        }
        tube
    }

    /// Consumes the given number of messages from a Tube, returning the number messages read with
    /// each producer ID.
    #[track_caller]
    fn consume_messages(
        tube: RecvTube,
        count: usize,
        barrier: Arc<Barrier>,
    ) -> (RecvTube, usize, usize) {
        barrier.wait();

        let mut id1_count = 0usize;
        let mut id2_count = 0usize;

        for _ in 0..count {
            let msg = tube.recv::<DataStruct>().unwrap();
            match msg.x {
                PRODUCER_ID_1 => id1_count += 1,
                PRODUCER_ID_2 => id2_count += 1,
                _ => panic!(
                    "want message with ID {} or {}; got message w/ ID {}.",
                    PRODUCER_ID_1, PRODUCER_ID_2, msg.x
                ),
            }
        }
        (tube, id1_count, id2_count)
    }

    #[test]
    fn send_recv_mpsc() {
        let (p1, consumer) = Tube::directional_pair().unwrap();
        let p2 = p1.try_clone().unwrap();
        let start_block_p1 = Arc::new(Barrier::new(3));
        let start_block_p2 = start_block_p1.clone();
        let start_block_consumer = start_block_p1.clone();

        let p1_thread = thread::spawn(move || produce_messages(p1, PRODUCER_ID_1, start_block_p1));
        let p2_thread = thread::spawn(move || produce_messages(p2, PRODUCER_ID_2, start_block_p2));

        let (_tube, id1_count, id2_count) = consume_messages(consumer, 200, start_block_consumer);
        assert_eq!(id1_count, 100);
        assert_eq!(id2_count, 100);

        p1_thread.join().unwrap();
        p2_thread.join().unwrap();
    }

    #[test]
    fn send_recv_hash_map() {
        let (s1, s2) = Tube::pair().unwrap();

        let mut test_msg = HashMap::new();
        test_msg.insert("Red".to_owned(), Event::new().unwrap());
        test_msg.insert("White".to_owned(), Event::new().unwrap());
        test_msg.insert("Blue".to_owned(), Event::new().unwrap());
        test_msg.insert("Orange".to_owned(), Event::new().unwrap());
        test_msg.insert("Green".to_owned(), Event::new().unwrap());
        s1.send(&test_msg).unwrap();
        let mut recv_msg: HashMap<String, Event> = s2.recv().unwrap();

        let mut test_msg_keys: Vec<_> = test_msg.keys().collect();
        test_msg_keys.sort();
        let mut recv_msg_keys: Vec<_> = recv_msg.keys().collect();
        recv_msg_keys.sort();
        assert_eq!(test_msg_keys, recv_msg_keys);

        for (key, test_event) in test_msg {
            let recv_event = recv_msg.remove(&key).unwrap();
            test_event_pair(test_event, recv_event);
        }
    }
}
