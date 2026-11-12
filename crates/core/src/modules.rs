//! The single registry of Garrison modules, in menu order.
//!
//! A module is a unit of authorization and navigation. Profiles grant module IDs;
//! observations name the modules that may display them; the interface renders only
//! granted modules. Adding a module means adding one variant and one entry here,
//! and one frontend view.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A module identifier. The derived order is the menu order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    Dashboard,
    Services,
    Antivirus,
    Spam,
    Attacks,
    Deliveries,
    Sessions,
    Logs,
    Backups,
    Alerts,
    DnsTls,
    Actions,
}

#[derive(Debug)]
pub struct Module {
    pub id: ModuleId,
    pub label: &'static str,
    pub description: &'static str,
}

pub const MODULES: [Module; 12] = [
    Module {
        id: ModuleId::Dashboard,
        label: "Dashboard",
        description: "Health summary, mailbox storage and recorded metric history.",
    },
    Module {
        id: ModuleId::Services,
        label: "Services",
        description: "Process states, schedules, installed versions and newer releases.",
    },
    Module {
        id: ModuleId::Antivirus,
        label: "Antivirus",
        description: "Scanner configuration, signature files and test messages through the mail server.",
    },
    Module {
        id: ModuleId::Spam,
        label: "Spam filter",
        description: "Native spam filter, classifier, test messages and webmail plugin observations.",
    },
    Module {
        id: ModuleId::Attacks,
        label: "Attacks & bans",
        description: "Failed sign-ins, Stalwart's bans and TLS handshake errors by address, network and account; accounts that send unusually much.",
    },
    Module {
        id: ModuleId::Deliveries,
        label: "Deliveries",
        description: "Queue lifecycles correlated from recorded events.",
    },
    Module {
        id: ModuleId::Sessions,
        label: "Sessions",
        description: "Protocol sessions reconstructed from recorded events.",
    },
    Module {
        id: ModuleId::Logs,
        label: "Event history",
        description: "Recorded Stalwart events with privacy filtering.",
    },
    Module {
        id: ModuleId::Backups,
        label: "Backups",
        description: "Backup jobs with their last run, schedules, receipts and restore tests.",
    },
    Module {
        id: ModuleId::Alerts,
        label: "Alerts",
        description: "Notifications when a check fails or warns, and monitor receipts.",
    },
    Module {
        id: ModuleId::DnsTls,
        label: "DNS & TLS",
        description: "DNS records of each domain, blocklists and reverse names, resolver process and TLS certificate checks.",
    },
    Module {
        id: ModuleId::Actions,
        label: "Maintenance",
        description: "Reviewed maintenance operations with confirmation and audit.",
    },
];

impl ModuleId {
    /// Every module in menu order.
    pub fn all() -> impl Iterator<Item = ModuleId> {
        MODULES.iter().map(|module| module.id)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ModuleId::Dashboard => "dashboard",
            ModuleId::Services => "services",
            ModuleId::Antivirus => "antivirus",
            ModuleId::Spam => "spam",
            ModuleId::Attacks => "attacks",
            ModuleId::Deliveries => "deliveries",
            ModuleId::Sessions => "sessions",
            ModuleId::Logs => "logs",
            ModuleId::Backups => "backups",
            ModuleId::Alerts => "alerts",
            ModuleId::DnsTls => "dns_tls",
            ModuleId::Actions => "actions",
        }
    }

    pub fn module(self) -> &'static Module {
        // MODULES lists the variants in declaration order (tested below).
        &MODULES[self as usize]
    }
}

/// The registry as `frontend/api/modules.json` holds it: id, label and
/// description in menu order, pretty-printed with a final newline.
pub fn document() -> String {
    let list: Vec<serde_json::Value> = MODULES
        .iter()
        .map(|module| {
            serde_json::json!({
                "id": module.id.as_str(),
                "label": module.label,
                "description": module.description,
            })
        })
        .collect();
    let mut text = serde_json::to_string_pretty(&list).unwrap_or_default();
    text.push('\n');
    text
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown module {0:?}")]
pub struct UnknownModule(pub String);

impl FromStr for ModuleId {
    type Err = UnknownModule;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ModuleId::all()
            .find(|id| id.as_str() == value)
            .ok_or_else(|| UnknownModule(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_module_sits_at_its_variant_index() {
        for (index, module) in MODULES.iter().enumerate() {
            assert_eq!(module.id as usize, index, "{:?}", module.id);
            assert_eq!(module.id.module().id, module.id);
        }
        assert_eq!(MODULES.len(), ModuleId::Actions as usize + 1);
    }

    #[test]
    fn names_round_trip_through_text_and_json() {
        for id in ModuleId::all() {
            assert_eq!(id.as_str().parse::<ModuleId>(), Ok(id));
            let json = serde_json::to_string(&id).unwrap();
            assert_eq!(json, format!("\"{}\"", id.as_str()));
            assert_eq!(id.module().id, id);
        }
        assert!("Dashboard".parse::<ModuleId>().is_err());
        assert!("domains".parse::<ModuleId>().is_err());
    }
}
