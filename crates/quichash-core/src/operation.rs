//! Shared control and progress types for long-running operations.

use std::path::PathBuf;

/// Whether an operation stops on the first item-level failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum FailurePolicy {
    /// Return the first error without a partial report.
    #[default]
    FailFast,
    /// Continue processing and retain item-level failures in the report.
    Continue,
}

/// Current phase of a long-running operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProgressPhase {
    /// Filesystem entries are being enumerated.
    Discovering,
    /// File or stream contents are being hashed.
    Hashing,
    /// Results are being persisted.
    Writing,
    /// Stored digests are being checked.
    Verifying,
}

/// Structured progress suitable for a TUI, GUI, or CLI adapter.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProgressEvent {
    /// Kind of work currently underway.
    pub phase: ProgressPhase,
    /// Completed units; interpretation depends on [`ProgressEvent::phase`].
    pub completed: u64,
    /// Total units when known in advance.
    pub total: Option<u64>,
    /// Cumulative bytes processed by the operation when available.
    pub bytes_processed: u64,
    /// Current file when the event concerns a specific path.
    pub path: Option<PathBuf>,
}

/// Observer used for progress reporting and cooperative cancellation.
pub trait OperationObserver: Send + Sync {
    /// Receive a progress snapshot.
    ///
    /// Implementations should return quickly and must tolerate calls from
    /// multiple worker threads.
    fn on_progress(&self, _event: &ProgressEvent) {}

    /// Return `true` to request cooperative cancellation.
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// Observer that discards progress and never cancels.
pub struct NoopObserver;

impl OperationObserver for NoopObserver {}

/// Internal no-op adapter retained while legacy engines are exposed through
/// the structured observer API.
#[derive(Clone, Debug, Default)]
pub(crate) struct LegacyProgress;

#[allow(dead_code)]
impl LegacyProgress {
    pub(crate) fn new(_length: u64) -> Self {
        Self
    }
    pub(crate) fn set_style(&self, _style: LegacyProgressStyle) {}
    pub(crate) fn set_message(&self, _message: impl Into<String>) {}
    pub(crate) fn set_length(&self, _length: u64) {}
    pub(crate) fn inc(&self, _amount: u64) {}
    pub(crate) fn set_position(&self, _position: u64) {}
    pub(crate) fn finish_and_clear(&self) {}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LegacyProgressStyle;

impl LegacyProgressStyle {
    pub(crate) fn default_bar() -> Self {
        Self
    }
    pub(crate) fn template(self, _template: &str) -> Result<Self, std::convert::Infallible> {
        Ok(self)
    }
    pub(crate) fn progress_chars(self, _characters: &str) -> Self {
        self
    }
}
