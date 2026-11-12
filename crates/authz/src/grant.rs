//! The authorization result the broker returns and the web service enforces.

use std::collections::BTreeSet;

use garrison_core::modules::ModuleId;
use garrison_core::time;
use garrison_stalwart::oidc::is_subject;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Error;
use crate::policy::is_profile_name;

const MAX_EMAIL: usize = 254;

/// Modules serialize in menu order and actions sorted, as the broker sends them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub subject: String,
    pub email: String,
    pub modules: BTreeSet<ModuleId>,
    pub actions: BTreeSet<String>,
    pub profiles: Vec<String>,
    pub checked_at: String,
}

impl Grant {
    pub fn allows_module(&self, module: ModuleId) -> bool {
        self.modules.contains(&module)
    }

    pub fn allows_action(&self, action: &str) -> bool {
        self.modules.contains(&ModuleId::Actions) && self.actions.contains(action)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Validate a broker answer; anything ambiguous is treated as no access.
pub fn parse_grant(value: Value, action_ids: &BTreeSet<&str>) -> Result<Grant, Error> {
    let malformed = || Error::Denied("Malformed authorization answer".into());
    let grant: Grant = serde_json::from_value(value).map_err(|_| malformed())?;
    let valid = is_subject(&grant.subject)
        && grant.email.chars().count() <= MAX_EMAIL
        && !grant.modules.is_empty()
        && grant
            .actions
            .iter()
            .all(|action| action_ids.contains(action.as_str()))
        && grant.profiles.iter().all(|name| is_profile_name(name))
        && time::parse(&grant.checked_at).is_some();
    if valid { Ok(grant) } else { Err(malformed()) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn actions() -> BTreeSet<&'static str> {
        BTreeSet::from(["run_monitor", "run_backup"])
    }

    fn answer() -> Value {
        json!({
            "subject": "42",
            "email": "ann@example.test",
            "modules": ["dashboard", "actions"],
            "actions": ["run_monitor"],
            "profiles": ["administrator"],
            "checkedAt": "2026-10-29T10:00:00.123456+00:00",
        })
    }

    #[test]
    fn a_valid_answer_round_trips_in_menu_order() {
        let grant = parse_grant(answer(), &actions()).unwrap();
        assert!(grant.allows_module(ModuleId::Dashboard));
        assert!(!grant.allows_module(ModuleId::Backups));
        assert!(grant.allows_action("run_monitor") && !grant.allows_action("run_backup"));
        let mut expected = answer();
        expected["modules"] = json!(["dashboard", "actions"]);
        assert_eq!(grant.to_value(), expected);
        assert_eq!(
            serde_json::to_string(&grant.to_value()).unwrap(),
            r#"{"subject":"42","email":"ann@example.test","modules":["dashboard","actions"],"actions":["run_monitor"],"profiles":["administrator"],"checkedAt":"2026-10-29T10:00:00.123456+00:00"}"#
        );
    }

    #[test]
    fn actions_need_the_actions_module() {
        let mut value = answer();
        value["modules"] = json!(["dashboard"]);
        let grant = parse_grant(value, &actions()).unwrap();
        assert!(!grant.allows_action("run_monitor"));
    }

    #[test]
    fn anything_ambiguous_is_no_access() {
        let mutations: [(&str, Value); 11] = [
            ("subject", json!("a b")),
            ("email", json!("x".repeat(255))),
            ("modules", json!([])),
            ("modules", json!(["unknown"])),
            ("actions", json!(["format_disk"])),
            ("actions", json!("run_monitor")),
            ("profiles", json!(["Admin"])),
            ("checkedAt", json!("2026-10-29T10:00:00")),
            ("checkedAt", json!("soon")),
            ("extra", json!(true)),
            ("subject", Value::Null),
        ];
        for (key, replacement) in mutations {
            let mut value = answer();
            value[key] = replacement;
            assert_eq!(
                parse_grant(value.clone(), &actions()),
                Err(Error::Denied("Malformed authorization answer".into())),
                "{value}"
            );
        }
        let mut missing = answer();
        missing.as_object_mut().unwrap().remove("profiles");
        assert!(parse_grant(missing, &actions()).is_err());
        assert!(parse_grant(json!([]), &actions()).is_err());
    }
}
