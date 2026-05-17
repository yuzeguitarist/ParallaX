//! Injection / blocking subsystem of the GFW simulator.
//!
//! These types model the four blocking actions the GFW exposes:
//!
//!  * **TCP RST injection** - forge a TCP segment with `RST=1` so that the
//!    client (and ideally the server) tear down the connection. Implemented as
//!    a record of "what would have been sent" since the simulator does not
//!    actually emit raw IP/TCP frames.
//!  * **UDP drop** - silently swallow UDP datagrams matching a 3-tuple. Used
//!    for QUIC after the Initial SNI fires.
//!  * **Residual block** - after either of the above, retain the 3-tuple
//!    `(client_ip, server_ip, server_port)` for ~180 s and drop any new flow
//!    that matches.
//!  * **DNS response injection** - forge a fake A-record response. Handled
//!    inline by [`super::detection::dns_inject`], which constructs the
//!    forged response; this module just keeps a stats counter.

pub mod blocking;

pub use blocking::{
    BlockingPolicy, EgressAction, ResidualBlockTable, ResidualBlockTuple, TcpResetReason,
    UdpDropReason,
};

// `ActionLog` is exposed so callers can mirror what the simulator emits if they
// want their own log buffer; it is otherwise unused inside the simulator.
#[allow(unused_imports)]
pub use blocking::ActionLog;
