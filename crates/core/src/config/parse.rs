//! Turn the TOML document into a [`Config`], section by section.

use std::collections::{BTreeSet, HashSet};

use toml::{Table, Value};

use super::notify::{milter, notifications};
use super::values::{
    Section, absolute_path, boolean, https_origin, https_url, integer, loopback_url, origin_of,
    secret_source, short_text,
};
use super::{
    Action, BrokerConfig, CollectorConfig, Config, ConfigError, Deployment, IngestConfig,
    Operation, WebConfig, is_action_id, is_confirmation, is_unit_name, is_user_name,
};
use crate::modules::ModuleId;

fn fail<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

pub fn parse(raw: &Table) -> Result<Config, ConfigError> {
    let allowed = [
        "schema",
        "credentials_directory",
        "deployment",
        "web",
        "ingest",
        "collector",
        "broker",
        "notifications",
        "milter",
        "actions",
        "providers",
        "modules",
    ];
    let top = Section::of(raw, "top level", &allowed)?;
    if top.get("schema").and_then(Value::as_integer) != Some(1) {
        return fail("schema must be 1");
    }
    Ok(Config {
        credentials_directory: absolute_path(
            top.get("credentials_directory"),
            "/etc/garrison/credentials",
            "credentials_directory",
        )?,
        deployment: deployment(top.get("deployment"))?,
        web: web(top.get("web"))?,
        ingest: ingest(top.get("ingest"))?,
        collector: collector(top.get("collector"), top.get("providers"))?,
        broker: broker(top.get("broker"), top.get("actions"))?,
        notifications: notifications(top.get("notifications"))?,
        milter: milter(top.get("milter"))?,
        modules: modules(top.get("modules"))?,
    })
}

/// The modules this installation offers; without the key, all of them. The
/// dashboard and the services page are always among them.
fn modules(value: Option<&Value>) -> Result<BTreeSet<ModuleId>, ConfigError> {
    let Some(value) = value else {
        return Ok(ModuleId::all().collect());
    };
    let Some(items) = value.as_array() else {
        return fail("modules must be a list of module IDs");
    };
    let mut modules = BTreeSet::from([ModuleId::Dashboard, ModuleId::Services]);
    for item in items {
        let Some(text) = item.as_str() else {
            return fail("modules must be a list of module IDs");
        };
        let Ok(id) = text.parse() else {
            return fail(format!("modules: \"{text}\" is not a module ID"));
        };
        modules.insert(id);
    }
    Ok(modules)
}

fn deployment(value: Option<&Value>) -> Result<Deployment, ConfigError> {
    let allowed = [
        "public_origin",
        "issuer",
        "stalwart_url",
        "admin_url",
        "links",
    ];
    let table = Section::take(value, "deployment", &allowed)?;
    let links = match table.get("links") {
        None => Vec::new(),
        Some(Value::Table(links)) if links.len() <= 16 => links
            .iter()
            .map(|(name, url)| {
                Ok((
                    name.clone(),
                    https_url(Some(url), &format!("deployment.links.{name}"))?,
                ))
            })
            .collect::<Result<_, ConfigError>>()?,
        Some(_) => return fail("[deployment] links must be a small table of names to URLs"),
    };
    let public_origin = https_origin(table.get("public_origin"), "deployment.public_origin")?;
    let issuer = https_origin(table.get("issuer"), "deployment.issuer")?;
    // Stalwart serves its own WebUI under its issuer unless configured otherwise.
    let default_admin = Value::String(format!("{issuer}/admin/"));
    let admin_url = https_url(
        Some(table.get("admin_url").unwrap_or(&default_admin)),
        "deployment.admin_url",
    )?;
    // A browser gives one origin one storage and one authority: a script of
    // either interface could act as the user signed in to the other, such as
    // the Stalwart administrator. So the two never share one.
    if [&issuer, &origin_of(&admin_url)].contains(&&public_origin) {
        return fail(
            "deployment.public_origin must be a host name of its own, not Stalwart's \
             (issuer or admin_url): a shared origin lets scripts of either interface act \
             in the other",
        );
    }
    Ok(Deployment {
        issuer,
        stalwart_url: loopback_url(table.get("stalwart_url"), "deployment.stalwart_url")?,
        admin_url,
        public_origin,
        links,
    })
}

fn web(value: Option<&Value>) -> Result<WebConfig, ConfigError> {
    let allowed = [
        "port",
        "state_directory",
        "session_minutes",
        "bind_client_ip",
    ];
    let table = Section::take(value, "web", &allowed)?;
    Ok(WebConfig {
        port: integer(table.get("port"), Some(8091), "web.port", 1024, 65535)?,
        state_directory: absolute_path(
            table.get("state_directory"),
            "/var/lib/garrison/web",
            "web.state_directory",
        )?,
        session_minutes: integer(
            table.get("session_minutes"),
            Some(30),
            "web.session_minutes",
            5,
            480,
        )?,
        bind_client_ip: boolean(table.get("bind_client_ip"), false, "web.bind_client_ip")?,
    })
}

fn ingest(value: Option<&Value>) -> Result<IngestConfig, ConfigError> {
    let allowed = [
        "port",
        "state_directory",
        "signature_key",
        "retention_days",
        "max_events",
        "max_database_mib",
    ];
    let table = Section::take(value, "ingest", &allowed)?;
    Ok(IngestConfig {
        port: integer(table.get("port"), Some(8094), "ingest.port", 1024, 65535)?,
        state_directory: absolute_path(
            table.get("state_directory"),
            "/var/lib/garrison/ingest",
            "ingest.state_directory",
        )?,
        signature_key: secret_source(
            table.get("signature_key"),
            "credential:webhook-signature-key",
            "ingest.signature_key",
        )?,
        retention_days: integer(
            table.get("retention_days"),
            Some(30),
            "ingest.retention_days",
            1,
            365,
        )?,
        max_events: integer(
            table.get("max_events"),
            Some(1_000_000),
            "ingest.max_events",
            1000,
            10_000_000,
        )?,
        max_database_mib: integer(
            table.get("max_database_mib"),
            Some(256),
            "ingest.max_database_mib",
            16,
            16384,
        )?,
    })
}

fn collector(
    value: Option<&Value>,
    providers: Option<&Value>,
) -> Result<CollectorConfig, ConfigError> {
    let allowed = [
        "state_directory",
        "native_key",
        "metrics_credential",
        "history_days",
    ];
    let table = Section::take(value, "collector", &allowed)?;
    let providers = match providers {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Table(provider) if provider.get("type").is_some_and(Value::is_str) => {
                    Ok(provider.clone())
                }
                _ => fail("providers must be a list of tables with a type"),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return fail("providers must be a list of tables with a type"),
    };
    // An empty string turns the metrics credential off.
    let metrics = match table.get("metrics_credential") {
        Some(Value::String(text)) if text.is_empty() => None,
        value => Some(secret_source(
            value,
            "credential:metrics-credential",
            "collector.metrics_credential",
        )?),
    };
    Ok(CollectorConfig {
        state_directory: absolute_path(
            table.get("state_directory"),
            "/var/lib/garrison/collector",
            "collector.state_directory",
        )?,
        native_key: secret_source(
            table.get("native_key"),
            "credential:collector-native-key",
            "collector.native_key",
        )?,
        metrics_credential: metrics,
        history_days: integer(
            table.get("history_days"),
            Some(90),
            "collector.history_days",
            1,
            730,
        )?,
        providers,
    })
}

fn broker(value: Option<&Value>, actions: Option<&Value>) -> Result<BrokerConfig, ConfigError> {
    let allowed = [
        "socket",
        "state_directory",
        "native_key",
        "policy",
        "allowed_peers",
    ];
    let table = Section::take(value, "broker", &allowed)?;
    let actions: Vec<Action> = match actions {
        None => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(action).collect::<Result<_, _>>()?,
        Some(_) => return fail("actions must be a list of tables"),
    };
    let mut seen = HashSet::new();
    if !actions.iter().all(|action| seen.insert(action.id.as_str())) {
        return fail("actions must have unique IDs");
    }
    let peers = match table.get("allowed_peers") {
        None => vec!["garrison".to_owned()],
        Some(Value::Array(names)) if !names.is_empty() => names
            .iter()
            .map(|name| match name.as_str() {
                Some(name) if is_user_name(name) => Ok(name.to_owned()),
                _ => fail("broker.allowed_peers must list system user names"),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return fail("broker.allowed_peers must list system user names"),
    };
    Ok(BrokerConfig {
        socket: absolute_path(
            table.get("socket"),
            "/run/garrison/broker.sock",
            "broker.socket",
        )?,
        state_directory: absolute_path(
            table.get("state_directory"),
            "/var/lib/garrison/broker",
            "broker.state_directory",
        )?,
        native_key: secret_source(
            table.get("native_key"),
            "credential:broker-native-key",
            "broker.native_key",
        )?,
        policy: absolute_path(
            table.get("policy"),
            "/etc/garrison/access-policy.json",
            "broker.policy",
        )?,
        allowed_peers: peers,
        actions,
    })
}

fn action(raw: &Value) -> Result<Action, ConfigError> {
    let allowed = [
        "id",
        "title",
        "description",
        "confirmation",
        "unit",
        "operation",
        "cooldown_seconds",
        "timeout_seconds",
        "operator",
    ];
    let table = Section::take(Some(raw), "actions", &allowed)?;
    let id = match table.get("id").and_then(Value::as_str) {
        Some(id) if is_action_id(id) => id.to_owned(),
        _ => return fail("actions.id must be a lowercase identifier"),
    };
    let name = format!("actions[{id}]");
    let text = |key: &str| table.get(key).and_then(Value::as_str);
    let confirmation = match text("confirmation") {
        Some(phrase) if is_confirmation(phrase) => phrase.to_owned(),
        _ => return fail(format!("{name}.confirmation must be an uppercase phrase")),
    };
    let unit = match text("unit") {
        Some(unit) if is_unit_name(unit) => unit.to_owned(),
        _ => return fail(format!("{name}.unit must be a systemd unit name")),
    };
    let operation = match text("operation") {
        Some("start") => Operation::Start,
        Some("restart") => Operation::Restart,
        _ => return fail(format!("{name}.operation must be start or restart")),
    };
    Ok(Action {
        title: short_text(table.get("title"), &format!("{name}.title"))?,
        description: short_text(table.get("description"), &format!("{name}.description"))?,
        confirmation,
        unit,
        operation,
        cooldown_seconds: integer(
            table.get("cooldown_seconds"),
            None,
            &format!("{name}.cooldown_seconds"),
            0,
            86400,
        )?,
        timeout_seconds: integer(
            table.get("timeout_seconds"),
            None,
            &format!("{name}.timeout_seconds"),
            5,
            7200,
        )?,
        operator: boolean(table.get("operator"), false, &format!("{name}.operator"))?,
        id,
    })
}
