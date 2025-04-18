//! Record type argument definitions for data operations

use clap::{ArgGroup, Args};
use nexum_keycard::PersistentRecord;

/// Arguments for specifying record type
#[derive(Args, Debug)]
#[command(group = ArgGroup::new("record_type").required(false))]
pub struct RecordTypeArgs {
    /// Public (default)
    #[arg(long, group = "record_type")]
    pub public: bool,

    /// NDEF
    #[arg(long, group = "record_type")]
    pub ndef: bool,

    /// Cashcard
    #[arg(long, group = "record_type")]
    pub cashcard: bool,
}

impl RecordTypeArgs {
    /// Convert the args to a PersistentRecord enum
    pub fn to_record_type(&self) -> PersistentRecord {
        if self.ndef {
            PersistentRecord::Ndef
        } else if self.cashcard {
            PersistentRecord::Cashcard
        } else {
            PersistentRecord::Public
        }
    }
}

impl Default for RecordTypeArgs {
    fn default() -> Self {
        Self {
            public: true,
            ndef: false,
            cashcard: false,
        }
    }
}
