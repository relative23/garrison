//! The event types Garrison records, as a type.
//!
//! Stalwart names an event type as text, such as `delivery.dsn-success`. Text
//! compiles whatever it spells; a variant that does not exist does not. So
//! code that acts on one kind of event names its variant, and text becomes a
//! variant where it comes in: from the webhook, from a query, from a stored
//! row. A stored row may name a type that is no longer recorded; that text
//! is no variant, and nothing acts on it.

/// What a type of event is kept for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Session,
    Delivery,
    Other,
}

/// The list below names every recorded event type once, with its group. The
/// enum, the names and the lookups are all written from that one list, so
/// they cannot disagree; three hand-written lists of 111 lines each could.
macro_rules! event_types {
    ($( $(#[$about:meta])* $group:ident { $( $variant:ident => $name:literal, )* } )*) => {
        /// A recorded event type.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum EventType {
            $( $( #[doc = $name] $variant, )* )*
        }

        impl EventType {
            /// Every recorded event type, in the order of the list.
            pub const ALL: &[EventType] = &[ $( $( EventType::$variant, )* )* ];

            /// The name Stalwart gives the type.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $( EventType::$variant => $name, )* )*
                }
            }

            pub const fn group(self) -> Group {
                match self {
                    $( $( EventType::$variant => Group::$group, )* )*
                }
            }

            /// The type a name spells, if that type is recorded.
            pub fn parse(name: &str) -> Option<EventType> {
                match name {
                    $( $( $name => Some(EventType::$variant), )* )*
                    _ => None,
                }
            }
        }
    };
}

event_types! {
    /// SMTP session milestones, grouped into sessions by span ID.
    Session {
        SmtpConnectionStart => "smtp.connection-start",
        SmtpConnectionEnd => "smtp.connection-end",
        SmtpEhlo => "smtp.ehlo",
        SmtpStartTls => "smtp.start-tls",
        SmtpInvalidEhlo => "smtp.invalid-ehlo",
        SmtpMailFrom => "smtp.mail-from",
        SmtpMailFromUnauthenticated => "smtp.mail-from-unauthenticated",
        SmtpMailFromUnauthorized => "smtp.mail-from-unauthorized",
        SmtpMailFromNotAllowed => "smtp.mail-from-not-allowed",
        SmtpRcptTo => "smtp.rcpt-to",
        SmtpRcptToGreylisted => "smtp.rcpt-to-greylisted",
        SmtpMailboxDoesNotExist => "smtp.mailbox-does-not-exist",
        SmtpRelayNotAllowed => "smtp.relay-not-allowed",
        SmtpTooManyRecipients => "smtp.too-many-recipients",
        SmtpMessageTooLarge => "smtp.message-too-large",
        SmtpRateLimitExceeded => "smtp.rate-limit-exceeded",
        SmtpConcurrencyLimitExceeded => "smtp.concurrency-limit-exceeded",
        SmtpTimeLimitExceeded => "smtp.time-limit-exceeded",
        SmtpSpfEhloPass => "smtp.spf-ehlo-pass",
        SmtpSpfEhloFail => "smtp.spf-ehlo-fail",
        SmtpSpfFromPass => "smtp.spf-from-pass",
        SmtpSpfFromFail => "smtp.spf-from-fail",
        SmtpDkimPass => "smtp.dkim-pass",
        SmtpDkimFail => "smtp.dkim-fail",
        SmtpArcPass => "smtp.arc-pass",
        SmtpArcFail => "smtp.arc-fail",
        SmtpDmarcPass => "smtp.dmarc-pass",
        SmtpDmarcFail => "smtp.dmarc-fail",
        SmtpIprevPass => "smtp.iprev-pass",
        SmtpIprevFail => "smtp.iprev-fail",
    }
    /// Queue lifecycle and outbound delivery events, grouped by queue ID.
    Delivery {
        DeliveryAttemptStart => "delivery.attempt-start",
        DeliveryAttemptEnd => "delivery.attempt-end",
        DeliveryAuth => "delivery.auth",
        DeliveryAuthFailed => "delivery.auth-failed",
        DeliveryCompleted => "delivery.completed",
        DeliveryConcurrencyLimitExceeded => "delivery.concurrency-limit-exceeded",
        DeliveryConnect => "delivery.connect",
        DeliveryConnectError => "delivery.connect-error",
        DeliveryDelivered => "delivery.delivered",
        DeliveryDomainDeliveryStart => "delivery.domain-delivery-start",
        DeliveryDoubleBounce => "delivery.double-bounce",
        DeliveryDsnPermFail => "delivery.dsn-perm-fail",
        DeliveryDsnSuccess => "delivery.dsn-success",
        DeliveryDsnTempFail => "delivery.dsn-temp-fail",
        DeliveryEhlo => "delivery.ehlo",
        DeliveryEhloRejected => "delivery.ehlo-rejected",
        DeliveryFailed => "delivery.failed",
        DeliveryGreetingFailed => "delivery.greeting-failed",
        DeliveryImplicitTlsError => "delivery.implicit-tls-error",
        DeliveryIpLookup => "delivery.ip-lookup",
        DeliveryIpLookupFailed => "delivery.ip-lookup-failed",
        DeliveryMailFrom => "delivery.mail-from",
        DeliveryMailFromRejected => "delivery.mail-from-rejected",
        DeliveryMessageRejected => "delivery.message-rejected",
        DeliveryMissingOutboundHostname => "delivery.missing-outbound-hostname",
        DeliveryMxLookup => "delivery.mx-lookup",
        DeliveryMxLookupFailed => "delivery.mx-lookup-failed",
        DeliveryNullMx => "delivery.null-mx",
        DeliveryRateLimitExceeded => "delivery.rate-limit-exceeded",
        DeliveryRcptTo => "delivery.rcpt-to",
        DeliveryRcptToFailed => "delivery.rcpt-to-failed",
        DeliveryRcptToRejected => "delivery.rcpt-to-rejected",
        DeliveryStartTls => "delivery.start-tls",
        DeliveryStartTlsDisabled => "delivery.start-tls-disabled",
        DeliveryStartTlsError => "delivery.start-tls-error",
        DeliveryStartTlsUnavailable => "delivery.start-tls-unavailable",
        QueueAuthenticatedMessageQueued => "queue.authenticated-message-queued",
        QueueAutogeneratedQueued => "queue.autogenerated-queued",
        QueueBackPressure => "queue.back-pressure",
        QueueBlobNotFound => "queue.blob-not-found",
        QueueConcurrencyLimitExceeded => "queue.concurrency-limit-exceeded",
        QueueDsnQueued => "queue.dsn-queued",
        QueueLocked => "queue.locked",
        QueueMessageQueued => "queue.message-queued",
        QueueQuotaExceeded => "queue.quota-exceeded",
        QueueRateLimitExceeded => "queue.rate-limit-exceeded",
        QueueReportQueued => "queue.report-queued",
        QueueRescheduled => "queue.rescheduled",
        QueueStarted => "queue.started",
    }
    /// Everything else that is recorded: logins, security, the server itself.
    Other {
        AuthFailed => "auth.failed",
        SecurityAbuseBan => "security.abuse-ban",
        SecurityAuthenticationBan => "security.authentication-ban",
        SecurityLoiterBan => "security.loiter-ban",
        SecurityScanBan => "security.scan-ban",
        MessageIngestDuplicate => "message-ingest.duplicate",
        MessageIngestError => "message-ingest.error",
        MessageIngestHam => "message-ingest.ham",
        MessageIngestImapAppend => "message-ingest.imap-append",
        MessageIngestJmapAppend => "message-ingest.jmap-append",
        MessageIngestSpam => "message-ingest.spam",
        MilterActionAccept => "milter.action-accept",
        MilterActionConnectionFailure => "milter.action-connection-failure",
        MilterActionDiscard => "milter.action-discard",
        MilterActionReject => "milter.action-reject",
        MilterActionReplyCode => "milter.action-reply-code",
        MilterActionShutdown => "milter.action-shutdown",
        MilterActionTempFail => "milter.action-temp-fail",
        MilterDisconnected => "milter.disconnected",
        MilterIoError => "milter.io-error",
        MilterTimeout => "milter.timeout",
        MilterTlsInvalidName => "milter.tls-invalid-name",
        MtaHookActionAccept => "mta-hook.action-accept",
        MtaHookActionDiscard => "mta-hook.action-discard",
        MtaHookActionReject => "mta-hook.action-reject",
        MtaHookActionQuarantine => "mta-hook.action-quarantine",
        MtaHookError => "mta-hook.error",
        SpamTrainCompleted => "spam.train-completed",
        TlsHandshakeError => "tls.handshake-error",
        ServerStartup => "server.startup",
        ServerShutdown => "server.shutdown",
        TelemetryEventsDropped => "telemetry.events-dropped",
    }
}

impl EventType {
    /// The part of the name before the first dot: `smtp`, `delivery`, `queue`, ...
    pub fn category(self) -> &'static str {
        let name = self.as_str();
        name.split_once('.').map_or(name, |(first, _)| first)
    }
}
