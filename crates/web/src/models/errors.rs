//! What an error answer of the API holds, and what each of its status codes
//! stands for. The routes name in their OpenAPI responses the ones they can
//! give; the web tests fail on an answer a route does not declare.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Every error answer of the API: a fixed text for people. For an internal
/// error the journal names the cause under the answer's `X-Request-Id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetail {
    pub detail: String,
}

/// A parameter, a path segment or the body does not match the API, or a
/// history query cannot be answered as asked.
#[derive(Debug, ToResponse)]
pub struct Invalid(pub ErrorDetail);

/// No valid session: sign in again.
#[derive(Debug, ToResponse)]
pub struct SignInRequired(pub ErrorDetail);

/// Not authorized: the policy refuses this user, which ends the session;
/// the user's rights do not include this module or action; or a write lacks
/// the exact Origin and the session's CSRF token.
#[derive(Debug, ToResponse)]
pub struct Refused(pub ErrorDetail);

/// No recorded events for this ID, or no job of this ID that the user may
/// see.
#[derive(Debug, ToResponse)]
pub struct NotFound(pub ErrorDetail);

/// Another maintenance operation is in progress or may still be running,
/// the unit is busy with an operation of its own, or the request ID belongs
/// to another operation.
#[derive(Debug, ToResponse)]
pub struct Conflict(pub ErrorDetail);

/// The request body is larger than the service reads.
#[derive(Debug, ToResponse)]
pub struct TooLarge(pub ErrorDetail);

/// Too many history queries at once: eight wait for a turn already, or none
/// came within two seconds. Try again.
#[derive(Debug, ToResponse)]
pub struct Busy(pub ErrorDetail);

/// Too soon: the previous operation is settling, or this action is in its
/// cooldown.
#[derive(Debug, ToResponse)]
pub struct Settling(pub ErrorDetail);

/// Something failed inside the service; the journal names the cause under
/// the answer's `X-Request-Id`.
#[derive(Debug, ToResponse)]
pub struct Internal(pub ErrorDetail);

/// The broker gave an answer the web service cannot use.
#[derive(Debug, ToResponse)]
pub struct BadAnswer(pub ErrorDetail);

/// Not available now, as the detail says: the user's rights cannot be
/// checked (Stalwart or the broker is away, or Garrison's setup is broken;
/// the session stays), what the route reads or runs is not there or took too
/// long, or the session could not be ended.
#[derive(Debug, ToResponse)]
pub struct Unavailable(pub ErrorDetail);
