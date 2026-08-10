//! What happens at end-of-message: validate an ARC chain, and extend it.
//!
//! `main.zig` owns the daemon's configuration and global state; this module only
//! decides and constructs from a snapshot handed down by `main.zig`. Nothing here
//! reads global state, so the AMS and ARC-Seal verification path, and the AAR trust
//! rule that governs what this ADMD is willing to vouch for, are reachable from a
//! test without a running daemon.
//!
//! `MsgCtx` and `SealCtx` are defined here but constructed only in `main.zig`, which
//! avoids an import cycle: this module must not import its parent.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const dns_mod = securemilter.dns;
const zmq = securemilter.zmq;
const log = securemilter.log;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

const arc = @import("arc.zig");
const chain = @import("chain.zig");

const settings = @import("settings.zig");
const OnDnsError = settings.OnDnsError;

const sealbuild = @import("sealbuild.zig");
const buildSigningHeaders = sealbuild.buildSigningHeaders;
const buildSealInput = sealbuild.buildSealInput;
const buildAarContent = sealbuild.buildAarContent;
const foldBase64 = sealbuild.foldBase64;

/// Context shared by the verify and seal paths: everything both need to validate a
/// chain, stamp the result, and publish the event.
///
/// Constructed by `main.zig`, never here — see this file's header for why.
pub const MsgCtx = struct {
    /// This worker's resolver, not a per-message one (audit X-3). Validating a
    /// chain costs one key lookup per ARC set, and a long chain revisits the
    /// same signing domains, so the TTL cache has to survive the message to be
    /// worth having at all. Owned by `main.zig` as thread-local state and
    /// dropped on reload; borrowed here for the length of one message.
    resolver: *dns_mod.Resolver,
    /// Key-acceptance policy: the RSA floor, and how many key records at one
    /// selector to try before giving up (A-24). Grouped because they are always
    /// set together from the same config section and always spent together.
    policy: chain.Policy,
    /// Who this hop identifies as in `Authentication-Results`. Lives here rather
    /// than on `SealCtx` because the verify path stamps too.
    authserv_id: []const u8,
    /// Already constructed, not the endpoint and topic needed to construct one, so
    /// this module never learns that events travel over ZMQ.
    publisher: *zmq.Publisher,

    /// Validate `sets` against DNS.
    ///
    /// Every `failure_reason` `chain.zig` can produce is a string literal --
    /// checked rather than assumed, because the callers below all read it after
    /// this returns. That mattered when the resolver died here; it still does,
    /// for a different reason. The resolver now outlives the call, but its cache
    /// evicts, so a reason borrowed from a cached DNS answer would dangle as soon
    /// as some later lookup pushed that entry out.
    pub fn validate(
        self: MsgCtx,
        allocator: Allocator,
        sets: []const arc.ArcSet,
        all_headers: []const arc.Header,
        body_data: []const u8,
    ) chain.ValidationResult {
        return chain.validateChain(allocator, self.resolver, sets, all_headers, body_data, self.policy);
    }
};

pub fn doVerify(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    // An incomplete copy cannot validate a chain: every AMS in it covers the
    // body, so a truncated body makes each one fail on content grounds rather
    // than on the chain's own merits. arc=fail would blame the sender for our
    // resource limit, so this is temperror (RFC 8617 5.2 treats it as a
    // transient verification failure).
    if (conn.contentTruncated()) {
        addArHeaderSimple(conn, ctx.authserv_id, "arc", "temperror", "message too large to validate") catch |err|
            return auth_stamp.deferCode(err, "arc");
        publishEvent(ctx.publisher, conn.allocator, "verify", "temperror", 0);
        return @intFromEnum(responses.Code.@"continue");
    }

    // Build header list in arc.Header format
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value, .had_space = hdr.had_space }) catch continue;
    }

    // Parse ARC sets from headers.
    //
    // A chain that does not parse is a broken chain, not an absent one
    // (RFC 8617 §5.1.2). Answering arc=none here would let a sender downgrade
    // a failed chain to "unsealed" simply by malforming it — and, before the
    // parser rejected gaps, by appending a garbage set above a genuine one.
    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch |err| {
        if (err == error.OutOfMemory) return @intFromEnum(responses.Code.tempfail);
        const reason = arc.describeChainError(err);
        addArHeaderSimple(conn, ctx.authserv_id, "arc", "fail", reason) catch |e|
            return auth_stamp.deferCode(e, "arc");
        publishEvent(ctx.publisher, conn.allocator, "verify", "fail", 0);
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(sets);

    if (sets.len == 0) {
        addArHeaderSimple(conn, ctx.authserv_id, "arc", "none", null) catch |err|
            return auth_stamp.deferCode(err, "arc");
        publishEvent(ctx.publisher, conn.allocator, "verify", "none", 0);
        return @intFromEnum(responses.Code.@"continue");
    }

    // Validate chain. The truncation check at the top of doVerify established
    // the body is whole.
    const body_data = conn.getBody() orelse return @intFromEnum(responses.Code.@"continue");
    const result = ctx.validate(conn.allocator, sets, arc_headers.items, body_data);

    // A verifier reports what it found and never writes a permanent verdict
    // into the message, so an unevaluable chain is `arc=temperror`: honest,
    // revisable by the next hop, and not configurable (audit A-12). Only a
    // sealer has a policy decision to make, because only a sealer records
    // something RFC 8617 §5.1.2 forbids anyone downstream from revising.
    switch (result.evaluation) {
        .complete => {},
        .dns_temp_error => {
            addArHeaderSimple(conn, ctx.authserv_id, "arc", "temperror", result.failure_reason) catch |err|
                return auth_stamp.deferCode(err, "arc");
            publishEvent(ctx.publisher, conn.allocator, "verify", "temperror", result.highest_instance);
            return @intFromEnum(responses.Code.@"continue");
        },
        // Our fault, so the sender should retry rather than have our failure
        // recorded against their chain (audit A-12a). Unconditional: a local
        // fault is not a policy question.
        .internal_error => {
            log.err("internal error validating ARC chain: {s}", .{result.failure_reason orelse "unknown"});
            return @intFromEnum(responses.Code.tempfail);
        },
        // X-21: the deadline is our budget, not the chain's property -- the
        // sender retries, exactly as for a transient DNS failure, and the log
        // keeps the two apart.
        .deadline_exceeded => {
            log.warn("ARC chain evaluation deadline exceeded at i={d}", .{result.highest_instance});
            addArHeaderSimple(conn, ctx.authserv_id, "arc", "temperror", result.failure_reason) catch |err|
                return auth_stamp.deferCode(err, "arc");
            publishEvent(ctx.publisher, conn.allocator, "verify", "temperror", result.highest_instance);
            return @intFromEnum(responses.Code.@"continue");
        },
    }

    addArHeaderSimple(conn, ctx.authserv_id, "arc", result.status.toString(), result.failure_reason) catch |err|
        return auth_stamp.deferCode(err, "arc");
    publishEvent(ctx.publisher, conn.allocator, "verify", result.status.toString(), result.highest_instance);
    return @intFromEnum(responses.Code.@"continue");
}

/// Everything sealing needs beyond chain validation: this ADMD's identity, the key,
/// and the policy for a chain we could not evaluate.
///
/// Separate from `MsgCtx`: `doVerify` needs 5 values, `doSeal` needs 11; combining
/// them would hand verify a signing key. Sealing includes validating (chain evaluated
/// before extended); `main.zig`'s `sealCtx` is null when not configured to seal.
pub const SealCtx = struct {
    msg: MsgCtx,
    domain: []const u8,
    selector: []const u8,
    /// Acquired once per message and used for both the AMS and the ARC-Seal.
    ///
    /// Holding it here is what makes "one key for the whole set" structural instead
    /// of a comment: there is no cell to re-read halfway through, so a reload cannot
    /// sign the two halves of one set with different keys. Pointer lifetime is
    /// unchanged from the previous code, which held it across the same span.
    sign_key: *const crypto.SigningKey,
    signed_headers: []const u8,
    local_auth_methods: []const []const u8,
    on_dns_error: OnDnsError,
};

/// What sealing should do about the chain already on the message.
///
/// `stamp_temperror` is a variant rather than something the decision writes itself,
/// so every write to the message stays in `doSeal`. That is X-8 as a rule: a partial
/// ARC set is worse than none, so one function emits and emits nothing until there is
/// a complete set to emit.
const ChainOutcome = union(enum) {
    /// Extend the chain, sealing with this `cv=`.
    seal: arc.ChainValidation,
    /// Do not seal; return this milter code. The reason is already logged.
    stop: u8,
    /// Do not seal; stamp `arc=temperror` first, then continue.
    ///
    /// Carries the instance to report rather than letting the caller recompute it:
    /// `chain.zig` sets `highest_instance` to the loop index, the offending set's
    /// instance, the newest set's instance, or a literal 1 or 0 depending on where it
    /// gave up, so it is **not** `sets[sets.len - 1].instance`.
    stamp_temperror: struct {
        reason: ?[]const u8,
        instance: u8,
    },
};

/// Decide the `cv=` value for the set we are about to add, or that we should add none.
///
/// Writes nothing to the message; logs, because the reason a chain was refused is the
/// operator's only view of it.
fn chainOutcome(
    conn: *connection_mod.Connection,
    ctx: SealCtx,
    sets: []const arc.ArcSet,
    all_headers: []const arc.Header,
) ChainOutcome {
    // No prior chain: we are the first hop, so there is nothing to validate and
    // cv=none is the RFC 8617 §5.1.1 value for an initial seal.
    if (sets.len == 0) return .{ .seal = .none };

    // No body means no AMS can be checked, so the chain cannot be shown intact.
    const body_data = conn.getBody() orelse return .{ .seal = .fail };

    // `vr.status` is only used as the cv= value on `.complete` evaluation (audit
    // A-12): a transient DNS failure must not seal a permanent cv=fail, since RFC
    // 8617 §5.1.2 makes that verdict indistinguishable to later hops from a forged
    // signature for the life of the message.
    const vr = ctx.msg.validate(conn.allocator, sets, all_headers, body_data);
    switch (vr.evaluation) {
        .complete => return .{ .seal = vr.status },

        // Ours, not theirs. Defer unconditionally rather than record it against the
        // chain (audit A-12a).
        .internal_error => {
            log.err("not sealing: internal error validating the chain: {s}", .{vr.failure_reason orelse "unknown"});
            return .{ .stop = @intFromEnum(responses.Code.tempfail) };
        },

        .dns_temp_error => return dnsTempOutcome(ctx.on_dns_error, vr),

        // X-21: our budget ran out, which is the seal path's version of a
        // transient failure -- the operator's On-DNSError policy decides, and
        // a permanent cv=fail is never the silent default.
        .deadline_exceeded => {
            log.warn("not sealing: evaluation deadline exceeded at i={d}", .{vr.highest_instance});
            return dnsTempOutcome(ctx.on_dns_error, vr);
        },
    }
}

// The three `On-DNSError` policies. `dnsTempOutcome` is private, and publishing it
// to reach a test in another file is the trade this suite has refused before (audit
// 11.21, treewalk.zig) -- which is the argument for keeping every test beside the
// code it covers, not just this one. Tests and their explanations never count
// against the file's ceiling (11.31), so beside the code is also the cheap place.
//
// Testable at all only because the extraction left this a pure function: policy plus
// a `ValidationResult` in, a decision out, no DNS and no daemon. That is the part of
// the refactor worth the lines it cost.

test "On-DNSError=tempfail defers rather than recording a permanent cv=fail" {
    const out = dnsTempOutcome(.tempfail, .{
        .status = .unknown,
        .highest_instance = 3,
        .failure_reason = "SERVFAIL from 192.0.2.1",
        .evaluation = .dns_temp_error,
    });
    // A-12: a transient DNS failure must not become a verdict (`unknown`, not `fail`).
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(responses.Code.tempfail)),
        out.stop,
    );
}

test "On-DNSError=seal-fail records the failure the operator asked for" {
    const out = dnsTempOutcome(.seal_fail, .{
        .status = .unknown,
        .highest_instance = 2,
        .failure_reason = "timeout",
        .evaluation = .dns_temp_error,
    });
    try std.testing.expectEqual(arc.ChainValidation.fail, out.seal);
}

test "On-DNSError=skip-seal reports the instance validation gave up on, not the last set's" {
    // The regression this pins: an earlier draft of the extraction recomputed the
    // instance as `sets[sets.len - 1].instance`. `chain.zig` sets `highest_instance`
    // to the loop index, the offending set's instance, the newest set's instance, or
    // a literal 1 or 0 depending on where it stopped, so the two are different
    // numbers whenever the chain broke anywhere but its newest set. 3 here stands for
    // "gave up at instance 3", which no property of the set list would recover.
    const out = dnsTempOutcome(.skip_seal, .{
        .status = .unknown,
        .highest_instance = 3,
        .failure_reason = "SERVFAIL fetching i=3 key",
        .evaluation = .dns_temp_error,
    });
    try std.testing.expectEqual(@as(u8, 3), out.stamp_temperror.instance);
    try std.testing.expectEqualStrings(
        "SERVFAIL fetching i=3 key",
        out.stamp_temperror.reason.?,
    );
}

test "a null failure_reason survives to the stamp" {
    // `addArHeaderSimple` takes `?[]const u8`, so null must pass through as null
    // rather than becoming the "transient DNS failure" placeholder used for logging.
    // Those are two different strings for two different audiences.
    const out = dnsTempOutcome(.skip_seal, .{
        .status = .unknown,
        .highest_instance = 1,
        .failure_reason = null,
        .evaluation = .dns_temp_error,
    });
    try std.testing.expect(out.stamp_temperror.reason == null);
}

/// Apply the operator's `On-DNSError` policy to a chain we could not evaluate.
fn dnsTempOutcome(policy: OnDnsError, vr: chain.ValidationResult) ChainOutcome {
    const reason = vr.failure_reason orelse "transient DNS failure";
    switch (policy) {
        // ASCII only: syslog rendered an em dash here as escaped bytes, which is
        // noise in the one log line an operator reads when mail starts deferring.
        .tempfail => {
            log.warn(
                "deferring: {s}; sealing cv=fail would be permanent (On-DNSError=tempfail)",
                .{reason},
            );
            return .{ .stop = @intFromEnum(responses.Code.tempfail) };
        },

        // Pass through with no ARC set of ours. Safe for a hop that does not modify
        // the message; if this hop does modify it, the previous hop's AMS now covers
        // content we changed and the next hop computes cv=fail — so this moves who
        // breaks the chain rather than saving it. That is the operator's call to
        // make, because only they know whether this path rewrites mail.
        .skip_seal => {
            log.warn("not sealing: {s} (On-DNSError=skip-seal)", .{reason});
            return .{ .stamp_temperror = .{
                .reason = vr.failure_reason,
                .instance = vr.highest_instance,
            } };
        },

        .seal_fail => {
            log.warn(
                "sealing cv=fail after a transient DNS failure ({s}) because On-DNSError=seal-fail",
                .{reason},
            );
            return .{ .seal = .fail };
        },
    }
}

/// `maybe_ctx` is optional rather than the caller skipping the call, so the
/// truncation warning below still happens on a listener that is not configured to
/// seal — which is the order the guards ran in before.
pub fn doSeal(conn: *connection_mod.Connection, maybe_ctx: ?SealCtx) u8 {
    // A seal is an attestation over content. Sealing a copy we know to be
    // incomplete would hand the next hop a chain that cannot validate and name
    // this ADMD as the one that broke it (audit X-4). Pass through unsealed.
    if (conn.contentTruncated()) {
        const peer = conn.getPeerDisplay();
        log.warn(
            "not sealing message from {f}[{f}]: accumulated copy is incomplete",
            .{ escape.logField(peer.name), escape.logField(peer.ip) },
        );
        return @intFromEnum(responses.Code.@"continue");
    }

    // Not configured to seal: pass the message through untouched. Was three
    // separate guards on domain, selector and key; `SealCtx.current` returns null
    // for exactly those three reasons.
    const ctx = maybe_ctx orelse return @intFromEnum(responses.Code.@"continue");

    // Determine instance number: count existing ARC sets + 1
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value, .had_space = hdr.had_space }) catch continue;
    }

    // A chain we cannot parse cannot be extended: sealing it would attest to a
    // sequence we were unable to read. Pass the message through unsealed.
    const sets = arc.parseArcSets(conn.allocator, arc_headers.items) catch |err| {
        if (err != error.OutOfMemory) {
            log.warn("not sealing: {s}", .{arc.describeChainError(err)});
        }
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(sets);

    // RFC 8617 §5.1.3: "Once broken, the chain cannot be continued." A seal already
    // on the message saying cv=fail means an earlier hop recorded the break, so
    // there is nothing to extend and no set to add (audit A-19). Distinct from a
    // chain that fails validation *here* — that one is sealed cv=fail below, which
    // is how the break gets recorded in the first place.
    if (arc.chainAlreadyBroken(sets)) {
        log.info("not sealing: the chain is already marked cv=fail and cannot be continued", .{});
        return @intFromEnum(responses.Code.@"continue");
    }

    const new_instance: u8 = if (sets.len > 0) sets[sets.len - 1].instance + 1 else 1;
    if (new_instance > arc.MAX_INSTANCES) return @intFromEnum(responses.Code.@"continue");

    // `chainOutcome` decides and logs; the two non-sealing answers are acted on here,
    // because this function owns every write to the message.
    const cv: arc.ChainValidation = switch (chainOutcome(conn, ctx, sets, arc_headers.items)) {
        .seal => |status| status,
        .stop => |code| return code,
        .stamp_temperror => |t| {
            addArHeaderSimple(conn, ctx.msg.authserv_id, "arc", "temperror", t.reason) catch |err|
                return auth_stamp.deferCode(err, "arc");
            publishEvent(ctx.msg.publisher, conn.allocator, "seal", "temperror", t.instance);
            return @intFromEnum(responses.Code.@"continue");
        },
    };

    // Nothing here writes to the message until every header of the set exists. A
    // partial set is worse than no set at all: the next hop reads it as a broken
    // chain and makes that permanent (X-8). With construction moved to `sealbuild`,
    // which touches neither the socket nor daemon state, that ordering is now
    // structural rather than a rule this function has to remember — there is
    // nothing to emit until `buildSet` has returned a complete one.
    var failed_step: ?[]const u8 = null;
    var set = sealbuild.buildSet(conn, .{
        .instance = new_instance,
        .cv = cv,
        .domain = ctx.domain,
        .selector = ctx.selector,
        .signed_headers = ctx.signed_headers,
        .authserv_id = ctx.msg.authserv_id,
        .local_auth_methods = ctx.local_auth_methods,
        .sign_key = ctx.sign_key,
        .prior_sets = sets,
        // Read here, not `sealbuild`: `sealbuild` is stateless (fixed timestamp for
        // byte-for-byte comparison tests).
        .timestamp = @intCast(std.time.timestamp()),
    }, &failed_step) catch
        return sealInternalError(failed_step orelse "building the ARC set");
    defer set.deinit();

    // The whole set exists now, so it can go out as a unit.
    emitArcSet(
        conn.allocator,
        conn.fd,
        conn.negotiated_protocol.header_leading_space,
        set.aar,
        set.ams,
        set.seal,
    ) catch return sealInternalError("writing the ARC set");

    publishEvent(ctx.msg.publisher, conn.allocator, "seal", cv.toString(), new_instance);
    return @intFromEnum(responses.Code.accept);
}

/// Emit the three headers of one ARC set as a unit.
///
/// A milter `addHeader` packet cannot be recalled once it is on the wire, so a
/// partial set — AAR alone, or AAR and AMS with no ARC-Seal — must never reach it.
/// RFC 8617 requires all three per instance; the next hop reads a partial set as a
/// malformed chain and records a permanent `cv=fail` (§5.1.2), destroying a chain
/// that may have been perfectly valid (audit X-8). Every payload is therefore built
/// before the first byte is written, so an allocation failure always leaves the
/// message untouched; a socket that dies mid-set fails the whole transaction anyway,
/// and the milter protocol offers nothing stronger, since three headers cannot be
/// sent as one packet.
///
/// Takes the allocator and fd rather than the `Connection` it came from: those
/// are all it uses, and the property that matters here — nothing on the wire
/// unless everything is on the wire — is then testable against a pipe.
pub fn emitArcSet(
    allocator: Allocator,
    fd: posix.fd_t,
    leading_space: bool,
    aar: []const u8,
    ams: []const u8,
    seal_hdr: []const u8,
) !void {
    // These three are hashed, so the transmitted field has to be the octet string
    // that was canonicalized: the AMS covers itself with an empty `b=`, and the AS
    // covers AAR, AMS and AS. `sealbuild` builds all of them as `"Name: " ++ value`
    // — with the separator — so that is what must arrive.
    //
    // Which is why the negotiated flag belongs here rather than a fixed `false`.
    // The separator is written by the milter when it owns it and by the MTA
    // otherwise, and exactly one of them does, so the wire reads `"Name: " ++
    // value` either way. Passing `false` transmits `"Name:" ++ value` whenever the
    // flag is granted — one octet short of what was sealed. That is invisible today
    // only because every ARC canonicalization here is `relaxed`, which deletes the
    // whitespace around the colon before hashing; the first `c=simple` AMS to reach
    // this path would have been sealed against bytes we never sent.
    const p_aar = try responses.addHeader(allocator, "ARC-Authentication-Results", aar, leading_space);
    defer allocator.free(p_aar);
    const p_ams = try responses.addHeader(allocator, "ARC-Message-Signature", ams, leading_space);
    defer allocator.free(p_ams);
    const p_seal = try responses.addHeader(allocator, "ARC-Seal", seal_hdr, leading_space);
    defer allocator.free(p_seal);

    // Nothing fallible between here and the final write.
    //
    // Written seal-first because `addHeader` appends: it builds SMFIR_ADDHEADER,
    // which adds to the end of the header block, so writing seal, then AMS, then
    // AAR delivers the message reading AS, AMS, AAR downward (audit A-8).
    //
    // AS, AMS, AAR downward is what OpenARC emits and what every sealed example
    // message in RFC 8617's test corpus shows. Neither is a requirement — §5 says
    // "relative ordering of different trace header fields ... is unimportant" and
    // receivers MUST cope with any order — so this is convention, not conformance.
    // The order that IS mandated is the one fed to the seal's hash, AAR then AMS
    // then AS per §5.1.1, and that lives in `sealbuild.buildSealInput`, untouched
    // here. Conflating the two is what made A-8 prescribe the wrong fix.
    try codec.writePacket(fd, p_seal);
    try codec.writePacket(fd, p_ams);
    try codec.writePacket(fd, p_aar);
}

/// Defer the message after an internal failure while sealing (audit X-8).
///
/// Never `continue`: delivering here would either charge our own fault to the
/// sender's chain or, worse, leave a half-written set behind. The man page
/// already promises that an internal fault defers in either role, and this is
/// what keeps that promise on the sealing path.
pub fn sealInternalError(what: []const u8) u8 {
    log.err("not sealing: internal error {s}", .{what});
    return @intFromEnum(responses.Code.tempfail);
}

/// Record the ARC result on the message. Must stay fallible (audit X-9): on a
/// verify listener the `arc=` field is the only record of what this hop concluded
/// about the chain, and a later hop cannot reconstruct it — the AMS covers content
/// as it was *here*, so once the message moves on, the evidence is gone. Swallowing
/// a stamping failure would deliver the message with no `arc=` field while this
/// daemon reported success.
pub fn addArHeaderSimple(
    conn: *connection_mod.Connection,
    authserv_id: []const u8,
    method: []const u8,
    result_str: []const u8,
    reason: ?[]const u8,
) !void {
    try auth_stamp.stamp(conn.allocator, conn.fd, authserv_id, &.{
        .{
            .method = method,
            .result = result_str,
            .reason = reason,
            .properties = &.{},
        },
    }, conn.negotiated_protocol.header_leading_space);
}

/// Publish a seal or verify event.
///
/// Nothing here is attacker-derived: `action` and `result_str` are this daemon's
/// own fixed strings and `instance` is an integer, so no value can carry a `"`
/// into the payload. That is why this is the one publisher in the suite the X-5
/// pass did not have to change -- stated explicitly so the absence of
/// `escape.jsonString` reads as a checked conclusion rather than an omission. Any
/// future field taken from the message must be wrapped.
pub fn publishEvent(
    publisher: *zmq.Publisher,
    allocator: Allocator,
    action: []const u8,
    result_str: []const u8,
    instance: u8,
) void {
    const json = std.fmt.allocPrint(allocator,
        \\{{"action":"{s}","result":"{s}","instance":{d}}}
    , .{ action, result_str, instance }) catch return;
    defer allocator.free(json);
    publisher.publish(json);
}

// --- X-8: a partial ARC set must never reach the wire ------------------------

test "emitArcSet writes the whole set or nothing, at every failure point" {
    // Stated as a property over every allocation the function performs rather
    // than against a hand-picked fail index, so it cannot rot as the number of
    // allocations inside addHeader changes. See `emitArcSet`'s doc comment for
    // why a partial set must never reach the wire.
    var fail_index: usize = 0;
    var saw_success = false;
    var saw_failure = false;
    while (fail_index < 16) : (fail_index += 1) {
        const fds = try posix.pipe2(.{ .NONBLOCK = true });
        defer posix.close(fds[0]);
        defer posix.close(fds[1]);

        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const res = emitArcSet(
            failing.allocator(),
            fds[1],
            true,
            "i=1; mail.test; spf=pass",
            "i=1; a=rsa-sha256; b=AAAA",
            "i=1; cv=none; a=rsa-sha256; b=BBBB",
        );

        var buf: [1024]u8 = undefined;
        const n = posix.read(fds[0], &buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };

        if (res) |_| {
            saw_success = true;
            // All three present, seal first on the wire, so the delivered top-down
            // order reads AS, AMS, AAR, matching OpenARC and RFC 8617's example
            // messages (audit A-8). Not a conformance property -- §5 calls relative
            // trace-field order "unimportant" -- so this pins a convention.
            const aar_at = std.mem.indexOf(u8, buf[0..n], "ARC-Authentication-Results") orelse
                return error.TestUnexpectedResult;
            const ams_at = std.mem.indexOf(u8, buf[0..n], "ARC-Message-Signature") orelse
                return error.TestUnexpectedResult;
            const seal_at = std.mem.indexOf(u8, buf[0..n], "ARC-Seal") orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(seal_at < ams_at);
            try std.testing.expect(ams_at < aar_at);
        } else |_| {
            saw_failure = true;
            // The message must be untouched: a failure here must never leave one or
            // two of the three headers on the wire (audit X-8).
            try std.testing.expectEqual(@as(usize, 0), n);
        }
    }

    // Guard against the test passing because it exercised nothing: the range must
    // cover both a failing allocation and the fully successful case.
    try std.testing.expect(saw_failure);
    try std.testing.expect(saw_success);
}

// X-9: this wrapper must stay fallible. See `addArHeaderSimple`'s doc comment.
test "the Authentication-Results wrapper cannot swallow failures" {
    comptime {
        const ret = @typeInfo(@TypeOf(addArHeaderSimple)).@"fn".return_type.?;
        if (@typeInfo(ret) != .error_union) @compileError(
            "addArHeaderSimple must return an error union. Swallowing a stamping failure " ++
                "delivers the message with no arc= field while reporting success, and no " ++
                "later hop can reconstruct it: each AMS covers content as it was here " ++
                "(audit X-9).",
        );
        if (@typeInfo(ret).error_union.payload != void) @compileError(
            "addArHeaderSimple should return !void; the caller maps the error to a tempfail.",
        );
    }
}
