//! Runtime layer: the "middlebox" that wires every detection module into a
//! single pipeline and produces per-flow verdicts.

pub mod middlebox;
pub mod verdict;

pub use middlebox::{GfwSimulator, GfwSimulatorConfig};

#[allow(unused_imports)]
pub use middlebox::{ClientToServerEvent, FlowSummary, ServerToClientEvent};

#[allow(unused_imports)]
pub use verdict::{LayerVerdict, ScenarioReport, VerdictKind};
