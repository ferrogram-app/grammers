// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::{Duration, Instant};

use mtg_mtproto::transport;
use mtg_session::updates::UpdatesLike;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::Rpc;
use crate::Sender;
use crate::errors::ReadError;

const UPDATES_DROPPED_LOG_COOLDOWN: Duration = Duration::from_secs(300);

/// Drives one connection: forwards its updates to `updates` and sends the queued requests.
pub(super) async fn run_sender(
    mut sender: Sender<Box<dyn transport::Transport + Send>, mtg_mtproto::mtp::Encrypted>,
    mut rpc_rx: mpsc::UnboundedReceiver<Rpc>,
    updates: mpsc::Sender<UpdatesLike>,
    home_sender: bool,
) -> Result<(), ReadError> {
    let mut dropped: usize = 0;
    let mut last_update_limit_warn = Instant::now();
    let mut updates_closed = false;

    loop {
        tokio::select! {
            step = sender.step() => match step {
                Ok(all_new_updates) => {
                    if updates_closed {
                        continue;
                    }
                    for new_updates in all_new_updates {
                        if let Err(e) = updates.try_send(new_updates) {
                            match e {
                                mpsc::error::TrySendError::Full(_) => {
                                    dropped += 1;
                                    if last_update_limit_warn.elapsed() >= UPDATES_DROPPED_LOG_COOLDOWN {
                                        warn!(
                                            capacity = updates.max_capacity(),
                                            dropped_count = dropped,
                                            last_time = ?last_update_limit_warn.elapsed(),
                                            "updates channel full",
                                        );
                                        dropped = 0;
                                        last_update_limit_warn = Instant::now();
                                    }
                                }
                                mpsc::error::TrySendError::Closed(_) => {
                                    debug!("updates channel closed, stopping update forwarding");
                                    updates_closed = true;
                                    break;
                                }
                            }
                        }
                    }
                },
                Err(err) => {
                    if home_sender {
                        let _ = updates.try_send(UpdatesLike::ConnectionClosed);
                    }
                    break Err(err)
                },
            },
            rpc = rpc_rx.recv() => match rpc {
                Some(rpc) => sender.enqueue_body(rpc.body, rpc.tx),
                None => break Ok(()),
            },
        }
    }
}
