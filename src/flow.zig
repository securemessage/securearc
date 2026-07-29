//! What happens at end-of-message: validate an ARC chain, and extend it.
//!
//! Split out of `main.zig`, which had grown to 1063 lines. The seam is ownership of
//! state: this module decides and constructs, `main.zig` owns the daemon's
//! configuration and hands down a snapshot of it.
//!
//! Nothing here reads global state. That is the property that made the move
//! possible, and it is worth keeping: it means the AMS and ARC-Seal verification
//! path, and the AAR trust rule that governs what this ADMD is willing to vouch
//! for, are reachable from a test without a running daemon.
//!
//! The two context structs are defined here but *constructed* in `main.zig`, by
//! `msgCtx` and `sealCtx`. That split is deliberate: a constructor here would have
//! to reach back into `main.zig` for the globals, making the two files circular.
//! Keeping construction where the globals live means this module needs no import of
//! its parent at all.

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

/// Aliased rather than qualified at each use, so moving this code out of `main.zig`
/// did not also rewrite every call site inside it.
const sealbuild = @import("sealbuild.zig");
const buildSigningHeaders = sealbuild.buildSigningHeaders;
const buildSealInput = sealbuild.buildSealInput;
const buildAarContent = sealbuild.buildAarContent;
const foldBase64 = sealbuild.foldBase64;

/// Everything handling one message needs, regardless of whether we go on to seal it:
/// how to reach DNS, the smallest key to accept, who we stamp as, and where events go.
///
/// Named `MsgCtx` rather than the `ChainCtx` it started as. It began as exactly the
/// three values `doVerify` and `doSeal` both used to build a resolver and validate
/// against a key-size floor — a real duplication, not an invented grouping. Moving
/// the code here added two more, because stamping the result and publishing the event
/// are also per-message concerns that used to reach globals. "Chain" stopped being
/// the honest description at that point.
///
/// Constructed by `main.zig`, never here — see this file's header for why.
pub const MsgCtx = struct {
    dns_config: dns_mod.ResolverConfig,
    health_monitor: ?*dns_mod.HealthMonitor,
    min_key_bits: u32,
    /// Who this hop identifies as in `Authentication-Results`. Lives here rather
    /// than on `SealCtx` because the verify path stamps too.
    authserv_id: []const u8,
    /// Already constructed, not the endpoint and topic needed to construct one, so
    /// this module never learns that events travel over ZMQ.
    publisher: *zmq.Publisher,

    /// Validate `sets` against DNS, with a resolver that lives only for the call.
    ///
    /// Safe to destroy the resolver on return because every `failure_reason`
    /// `chain.zig` can produce is a string literal — checked rather than assumed,
    /// since a reason borrowed from resolver-owned memory would dangle here and
    /// the callers below all read it after this returns.
    pub fn validate(
        self: MsgCtx,
        allocator: Allocator,
        sets: []const arc.ArcSet,
        all_headers: []const arc.Header,
        body_data: []const u8,
    ) chain.ValidationResult {
        var resolver = dns_mod.Resolver.initWithMonitor(allocator, self.dns_config, self.health_monitor);
        defer resolver.deinit();
        return chain.validateChain(allocator, &resolver, sets, all_headers, body_data, self.min_key_bits);
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
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
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
    }

    addArHeaderSimple(conn, ctx.authserv_id, "arc", result.status.toString(), result.failure_reason) catch |err|
        return auth_stamp.deferCode(err, "arc");
    publishEvent(ctx.publisher, conn.allocator, "verify", result.status.toString(), result.highest_instance);
    return @intFromEnum(responses.Code.@"continue");
}

/// Everything sealing needs beyond chain validation: this ADMD's identity, the key,
/// and the policy for a chain we could not evaluate.
///
/// Deliberately a second, larger struct rather than more fields on `MsgCtx`.
/// `doVerify` needs five values and `doSeal` needs eleven, so one combined context
/// would hand the verify path a signing key it has no business holding. Composing
/// them keeps that separation while stating the real relationship: sealing
/// *includes* validating, because a chain is evaluated before it is extended.
///
/// `main.zig`'s `sealCtx` returns null when this daemon is not configured to seal,
/// which is the three separate guards `doSeal` used to open with, consolidated into
/// the one place that can answer the question.
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

    // Bound to the names the rest of this function already used, so moving the
    // source of these values does not touch the signing code below.
    const domain = ctx.domain;
    const selector = ctx.selector;
    const sign_key = ctx.sign_key;

    // Determine instance number: count existing ARC sets + 1
    var arc_headers: std.ArrayListUnmanaged(arc.Header) = .{};
    defer arc_headers.deinit(conn.allocator);

    for (conn.headers.items) |hdr| {
        arc_headers.append(conn.allocator, .{ .name = hdr.name, .value = hdr.value }) catch continue;
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

    const new_instance: u8 = if (sets.len > 0) sets[sets.len - 1].instance + 1 else 1;
    if (new_instance > arc.MAX_INSTANCES) return @intFromEnum(responses.Code.@"continue");

    // Determine chain status for our seal.
    //
    // This is where A-12 lived: `vr.status` was taken as the cv= value whatever
    // produced it, so a nameserver blip while fetching a previous hop's key
    // sealed cv=fail — permanent for the life of the message under RFC 8617
    // §5.1.2, and indistinguishable to every later hop from a forged signature.
    const cv: arc.ChainValidation = if (sets.len == 0) .none else blk: {
        const body_data = conn.getBody() orelse break :blk arc.ChainValidation.fail;
        const vr = ctx.msg.validate(conn.allocator, sets, arc_headers.items, body_data);
        switch (vr.evaluation) {
            .complete => break :blk vr.status,
            .internal_error => {
                // Ours, not theirs. Defer unconditionally rather than record it
                // against the chain (audit A-12a).
                log.err("not sealing: internal error validating the chain: {s}", .{vr.failure_reason orelse "unknown"});
                return @intFromEnum(responses.Code.tempfail);
            },
            .dns_temp_error => switch (ctx.on_dns_error) {
                .tempfail => {
                    // ASCII only: syslog rendered an em dash here as escaped
                    // bytes, which is noise in the one log line an operator
                    // reads when mail starts deferring.
                    log.warn(
                        "deferring: {s}; sealing cv=fail would be permanent (On-DNSError=tempfail)",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    return @intFromEnum(responses.Code.tempfail);
                },
                // Pass through with no ARC set of ours. Safe for a hop that does
                // not modify the message; if this hop does modify it, the
                // previous hop's AMS now covers content we changed and the next
                // hop computes cv=fail — so this moves who breaks the chain
                // rather than saving it. That is the operator's call to make,
                // because only they know whether this path rewrites mail.
                .skip_seal => {
                    log.warn(
                        "not sealing: {s} (On-DNSError=skip-seal)",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    addArHeaderSimple(conn, ctx.msg.authserv_id, "arc", "temperror", vr.failure_reason) catch |err|
                        return auth_stamp.deferCode(err, "arc");
                    publishEvent(ctx.msg.publisher, conn.allocator, "seal", "temperror", vr.highest_instance);
                    return @intFromEnum(responses.Code.@"continue");
                },
                .seal_fail => {
                    log.warn(
                        "sealing cv=fail after a transient DNS failure ({s}) because On-DNSError=seal-fail",
                        .{vr.failure_reason orelse "transient DNS failure"},
                    );
                    break :blk arc.ChainValidation.fail;
                },
            },
        }
    };

    // Nothing below writes to the message until every header of the set has been
    // built. See `emitArcSet`: a partial set is worse than no set at all, because
    // the next hop reads it as a broken chain and makes that permanent (X-8).

    // Build AAR content from the results this ADMD produced
    const ar_content = buildAarContent(conn, ctx.msg.authserv_id, ctx.local_auth_methods) orelse
        return sealInternalError("building the ARC-Authentication-Results content");
    defer conn.allocator.free(ar_content);

    const aar = std.fmt.allocPrint(conn.allocator, "i={d}; {s}", .{ new_instance, ar_content }) catch
        return sealInternalError("formatting the ARC-Authentication-Results header");
    defer conn.allocator.free(aar);

    // Build AMS: sign the message (same as DKIM signing). Guarded at the top of
    // doSeal, so the body here is the whole body.
    const body_data = conn.getBody() orelse return sealInternalError("the accumulated body is unavailable");
    const canon_mod = securemilter_crypto.canon;

    // Canonicalize body and compute body hash
    var body_canon = canon_mod.BodyCanonicalizer.init(conn.allocator, .relaxed);
    defer body_canon.deinit();
    body_canon.update(body_data) catch return sealInternalError("canonicalizing the body");
    const canon_body = body_canon.finish() catch return sealInternalError("finishing body canonicalization");
    defer conn.allocator.free(canon_body);
    const body_hash_raw = crypto.sha256(canon_body);
    const body_hash_b64 = crypto.base64Encode(conn.allocator, &body_hash_raw) catch
        return sealInternalError("encoding the body hash");
    defer conn.allocator.free(body_hash_b64);

    // Build AMS template (pre-folded — SAME format used for both signing input AND
    // the header prepended to the message, ensuring byte-identical canonicalization)
    const ams_template = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; a=rsa-sha256;\r\n\tc=relaxed/relaxed; d={s}; s={s};\r\n\th={s};\r\n\tbh={s};\r\n\tb=",
        .{ new_instance, domain, selector, ctx.signed_headers, body_hash_b64 },
    ) catch return sealInternalError("formatting the AMS template");
    defer conn.allocator.free(ams_template);

    // Canonicalize selected headers for AMS signing input
    var ams_input: std.ArrayListUnmanaged(u8) = .{};
    defer ams_input.deinit(conn.allocator);
    buildSigningHeaders(conn, &ams_input, ctx.signed_headers) catch return sealInternalError("canonicalizing the signed headers");

    // Append AMS header template (with empty b=) as final line (no trailing CRLF)
    const ams_full_template = std.fmt.allocPrint(conn.allocator, "ARC-Message-Signature: {s}", .{ams_template}) catch
        return sealInternalError("formatting the AMS signing input");
    defer conn.allocator.free(ams_full_template);
    const canon_ams_tmpl = canon_mod.canonicalizeHeader(conn.allocator, .relaxed, ams_full_template) catch
        return sealInternalError("canonicalizing the AMS header");
    defer conn.allocator.free(canon_ams_tmpl);
    ams_input.appendSlice(conn.allocator, canon_ams_tmpl) catch
        return sealInternalError("assembling the AMS signing input");

    // Sign AMS
    const ams_sig_raw = crypto.rsaSign(conn.allocator, sign_key.rsa_pkey.?, ams_input.items) catch
        return sealInternalError("signing the AMS");
    defer conn.allocator.free(ams_sig_raw);
    const ams_sig_b64 = crypto.base64Encode(conn.allocator, ams_sig_raw) catch
        return sealInternalError("encoding the AMS signature");
    defer conn.allocator.free(ams_sig_b64);

    // Final AMS header value: same pre-folded template + signature (folded base64)
    const folded_ams_sig = foldBase64(conn.allocator, ams_sig_b64) catch ams_sig_b64;
    const ams_value = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; a=rsa-sha256;\r\n\tc=relaxed/relaxed; d={s}; s={s};\r\n\th={s};\r\n\tbh={s};\r\n\tb={s}",
        .{ new_instance, domain, selector, ctx.signed_headers, body_hash_b64, folded_ams_sig },
    ) catch return sealInternalError("formatting the AMS header");
    defer conn.allocator.free(ams_value);

    // Build ARC-Seal: signs over all prior ARC headers + current AAR + AMS + AS(empty b=)
    const as_template = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; cv={s}; a=rsa-sha256; d={s}; s={s};\r\n\tb=",
        .{ new_instance, cv.toString(), domain, selector },
    ) catch return sealInternalError("formatting the ARC-Seal template");
    defer conn.allocator.free(as_template);

    // Build seal signing input
    var seal_input: std.ArrayListUnmanaged(u8) = .{};
    defer seal_input.deinit(conn.allocator);
    buildSealInput(conn, &seal_input, sets, aar, ams_value, as_template) catch
        return sealInternalError("assembling the ARC-Seal signing input");

    // Sign seal
    const seal_sig_raw = crypto.rsaSign(conn.allocator, sign_key.rsa_pkey.?, seal_input.items) catch
        return sealInternalError("signing the ARC-Seal");
    defer conn.allocator.free(seal_sig_raw);
    const seal_sig_b64 = crypto.base64Encode(conn.allocator, seal_sig_raw) catch
        return sealInternalError("encoding the ARC-Seal signature");
    defer conn.allocator.free(seal_sig_b64);

    // Final AS header value (pre-folded)
    const as_value = std.fmt.allocPrint(
        conn.allocator,
        "i={d}; cv={s}; a=rsa-sha256; d={s}; s={s};\r\n\tb={s}",
        .{ new_instance, cv.toString(), domain, selector, foldBase64(conn.allocator, seal_sig_b64) catch seal_sig_b64 },
    ) catch return sealInternalError("formatting the ARC-Seal header");
    defer conn.allocator.free(as_value);

    // The whole set exists now, so it can go out as a unit. Nothing above this
    // line has touched the message.
    emitArcSet(conn.allocator, conn.fd, aar, ams_value, as_value) catch
        return sealInternalError("writing the ARC set");

    publishEvent(ctx.msg.publisher, conn.allocator, "seal", cv.toString(), new_instance);
    return @intFromEnum(responses.Code.accept);
}

/// Emit the three headers of one ARC set as a unit.
///
/// A milter `addHeader` packet cannot be recalled once it is on the wire, and
/// the old code built and wrote each header where it was computed, with fallible
/// allocations in between. An allocation failure partway through therefore
/// delivered a message carrying a *partial* set — AAR alone, or AAR and AMS with
/// no ARC-Seal. RFC 8617 requires all three per instance, so the next hop reads
/// that as a malformed chain and records a permanent `cv=fail` (§5.1.2). Our own
/// resource failure thus destroyed a chain that may have been perfectly valid,
/// which is precisely the harm A-12 was filed to prevent, reached through a
/// different door (audit X-8).
///
/// Every payload is built before the first byte is written, so allocation
/// failures all land while the message is still untouched. What remains is a
/// socket that dies mid-set, and that fails the whole transaction anyway; the
/// milter protocol offers nothing stronger, since three headers cannot be sent
/// as one packet.
/// Takes the allocator and fd rather than the `Connection` it came from: those
/// are all it uses, and the property that matters here — nothing on the wire
/// unless everything is on the wire — is then testable against a pipe.
pub fn emitArcSet(
    allocator: Allocator,
    fd: posix.fd_t,
    aar: []const u8,
    ams: []const u8,
    seal_hdr: []const u8,
) !void {
    const p_aar = try responses.addHeader(allocator, "ARC-Authentication-Results", aar);
    defer allocator.free(p_aar);
    const p_ams = try responses.addHeader(allocator, "ARC-Message-Signature", ams);
    defer allocator.free(p_ams);
    const p_seal = try responses.addHeader(allocator, "ARC-Seal", seal_hdr);
    defer allocator.free(p_seal);

    // Nothing fallible between here and the final write. Each addHeader prepends,
    // so writing AAR, AMS, AS leaves the message reading AS, AMS, AAR downward —
    // the conventional order for the newest set, and byte-for-byte what the
    // previous code produced.
    try codec.writePacket(fd, p_aar);
    try codec.writePacket(fd, p_ams);
    try codec.writePacket(fd, p_seal);
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

/// Record the ARC result on the message.
///
/// Returned `void` and swallowed all three failures, so a message could be
/// delivered with no `arc=` field while the daemon reported success (audit X-9).
/// On a verify listener that field is the only record of what this hop concluded
/// about the chain, and a later hop cannot reconstruct it: the AMS covers content
/// as it was *here*, so once the message moves on, the evidence is gone.
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
    });
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
