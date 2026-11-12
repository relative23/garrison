//! Failed sign-ins, bans and TLS handshake errors from the event history.

use std::sync::Arc;

use axum::extract::State;
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use garrison_core::modules::ModuleId;
use garrison_core::time;
use garrison_ingest::attacks as found;
use serde::Deserialize;
use utoipa::ToSchema;

use super::events::{parsed, run};
use crate::app::App;
use crate::error::{ApiError, ApiResult, blocking};
use crate::models::{
    AttackNetwork, AttackSource, AttackTotals, AttackedAccount, Attacks, Ban, BanReason,
};
use crate::security::Visitor;

pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/attacks", get(attacks))
}

/// The stretch a summary covers, up to now.
#[derive(Clone, Copy, Debug, Default, Deserialize, ToSchema)]
pub enum Period {
    #[default]
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
}

impl Period {
    fn seconds(self) -> i64 {
        match self {
            Period::Day => 86_400,
            Period::Week => 7 * 86_400,
            Period::Month => 30 * 86_400,
        }
    }
}

/// The query of the summaries over a period.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct PeriodQuery {
    #[serde(default)]
    #[param(inline, default = "24h")]
    period: Period,
}

impl PeriodQuery {
    /// The stretch the query asks for: from the period's length ago to now.
    pub(super) fn stretch(uri: &Uri) -> ApiResult<(i64, i64)> {
        let query: PeriodQuery = parsed(uri)?;
        let until = time::now().as_second();
        Ok((until - query.period.seconds(), until))
    }
}

/// A count as the API states it; none here can pass the largest JSON integer.
fn count(number: u64) -> i64 {
    i64::try_from(number).unwrap_or(i64::MAX)
}

// Each conversion names every field: one the receiver adds or changes fails
// to compile until the API takes a decision about it.

impl From<found::Source> for AttackSource {
    fn from(source: found::Source) -> Self {
        let found::Source {
            address,
            network,
            failed_sign_ins,
            accounts,
            tls_errors,
            bans,
            first_seen,
            last_seen,
            listeners,
        } = source;
        AttackSource {
            address,
            network,
            failed_sign_ins: count(failed_sign_ins),
            accounts: count(accounts),
            tls_errors: count(tls_errors),
            bans: count(bans),
            first_seen,
            last_seen,
            listeners,
        }
    }
}

impl From<found::Network> for AttackNetwork {
    fn from(network: found::Network) -> Self {
        let found::Network {
            network,
            sources,
            failed_sign_ins,
            tls_errors,
            bans,
            last_seen,
        } = network;
        AttackNetwork {
            network,
            sources: count(sources),
            failed_sign_ins: count(failed_sign_ins),
            tls_errors: count(tls_errors),
            bans: count(bans),
            last_seen,
        }
    }
}

impl From<found::Account> for AttackedAccount {
    fn from(account: found::Account) -> Self {
        let found::Account {
            name,
            failed_sign_ins,
            sources,
            last_seen,
        } = account;
        AttackedAccount {
            name,
            failed_sign_ins: count(failed_sign_ins),
            sources: count(sources),
            last_seen,
        }
    }
}

impl From<found::Totals> for AttackTotals {
    fn from(totals: found::Totals) -> Self {
        let found::Totals {
            failed_sign_ins,
            unknown_accounts,
            tls_errors,
            bans,
            sources,
        } = totals;
        AttackTotals {
            failed_sign_ins: count(failed_sign_ins),
            unknown_accounts: count(unknown_accounts),
            tls_errors: count(tls_errors),
            bans: count(bans),
            sources: count(sources),
        }
    }
}

/// A ban as the API states it; a reason the API does not know is a fault of
/// this release, not of the request.
fn ban(ban: found::Ban) -> ApiResult<Ban> {
    let found::Ban {
        at,
        address,
        reason,
    } = ban;
    let reason = match reason.as_str() {
        "authentication" => BanReason::Authentication,
        "abuse" => BanReason::Abuse,
        "scan" => BanReason::Scan,
        "loiter" => BanReason::Loiter,
        _ => return Err(ApiError::internal(&"a ban without a known reason")),
    };
    Ok(Ban {
        at,
        address,
        reason,
    })
}

fn stated(summary: found::Attacks) -> ApiResult<Attacks> {
    let found::Attacks {
        since,
        until,
        truncated,
        totals,
        sources,
        networks,
        accounts,
        bans,
    } = summary;
    Ok(Attacks {
        since,
        until,
        truncated,
        totals: totals.into(),
        sources: sources.into_iter().map(AttackSource::from).collect(),
        networks: networks.into_iter().map(AttackNetwork::from).collect(),
        accounts: accounts.into_iter().map(AttackedAccount::from).collect(),
        bans: bans.into_iter().map(ban).collect::<ApiResult<Vec<Ban>>>()?,
    })
}

/// Failed sign-ins, Stalwart's bans and TLS handshake errors of the last day,
/// week or 30 days, by address, network and account.
#[utoipa::path(
    get,
    path = "/api/attacks",
    operation_id = "getAttacks",
    params(PeriodQuery),
    responses((status = 200, body = Attacks)),
)]
async fn attacks(
    State(app): State<Arc<App>>,
    visitor: Visitor,
    uri: Uri,
) -> ApiResult<Json<Attacks>> {
    blocking(move || {
        app.gate.require(&visitor, &[ModuleId::Attacks])?;
        let (since, until) = PeriodQuery::stretch(&uri)?;
        let summary = run(&app, |db| found::attacks(db, since, until))?;
        Ok(Json(stated(summary)?))
    })
    .await
}
