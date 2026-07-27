const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const securemilter_crypto = @import("securemilter_crypto");
const crypto = securemilter_crypto.crypto;

fn writeOut(data: []const u8) void {
    _ = posix.write(posix.STDOUT_FILENO, data) catch {};
}

fn writeErr(data: []const u8) void {
    _ = posix.write(posix.STDERR_FILENO, data) catch {};
}

const Usage =
    \\Usage: securearc-testkey [options]
    \\
    \\Fetch an ARC DNS key record and verify it matches a local private key.
    \\ARC uses the same selector._domainkey.domain DNS format as DKIM.
    \\
    \\Options:
    \\  -s <selector>    ARC selector name (required)
    \\  -d <domain>      Domain name (required)
    \\  -k <keyfile>     Private key file to compare against (required)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -h               Show this help
    \\
    \\Examples:
    \\  securearc-testkey -s arc2026 -d bambania.com -k /path/to/arc.key
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = process.args();
    _ = args.next();

    var selector: ?[]const u8 = null;
    var domain: ?[]const u8 = null;
    var keyfile: ?[]const u8 = null;
    var nameserver: []const u8 = "127.0.0.1";

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            writeOut(Usage);
            return;
        } else if (mem.eql(u8, arg, "-s")) {
            selector = args.next() orelse return fatal("missing argument for -s");
        } else if (mem.eql(u8, arg, "-d")) {
            domain = args.next() orelse return fatal("missing argument for -d");
        } else if (mem.eql(u8, arg, "-k")) {
            keyfile = args.next() orelse return fatal("missing argument for -k");
        } else if (mem.eql(u8, arg, "-n")) {
            nameserver = args.next() orelse return fatal("missing argument for -n");
        } else {
            return fatal("unknown option (use -h for help)");
        }
    }

    const sel = selector orelse return fatal("-s <selector> is required");
    const dom = domain orelse return fatal("-d <domain> is required");
    const kf = keyfile orelse return fatal("-k <keyfile> is required");

    // Build DNS query name (ARC uses same format as DKIM)
    const qname = try std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{ sel, dom });
    defer allocator.free(qname);

    // Query DNS
    const ns_slice: []const []const u8 = &.{nameserver};
    const dns_config = dns_mod.ResolverConfig{
        .nameservers = ns_slice,
        .timeout_ms = 5000,
        .retries = 2,
    };
    var resolver = dns_mod.Resolver.init(allocator, dns_config);
    defer resolver.deinit();

    var dns_result = resolver.resolve(qname, .TXT) catch {
        const msg = try std.fmt.allocPrint(allocator, "DNS lookup failed for {s}\n", .{qname});
        defer allocator.free(msg);
        writeErr(msg);
        return fatal("cannot resolve DNS TXT record");
    };
    defer dns_result.deinit();

    // Find key record (same tag format as DKIM: v=DKIM1; k=rsa; p=...)
    var pubkey_b64: ?[]const u8 = null;
    var key_type: []const u8 = "rsa";
    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (mem.indexOf(u8, txt, "p=")) |_| {
            if (findTag(txt, "p")) |p| {
                if (p.len > 0) {
                    pubkey_b64 = p;
                    if (findTag(txt, "k")) |k| key_type = k;
                    break;
                }
            }
        }
    }

    const dns_pub = pubkey_b64 orelse {
        const msg = try std.fmt.allocPrint(allocator, "No key record found at {s}\n", .{qname});
        defer allocator.free(msg);
        writeErr(msg);
        return fatal("key record not found or revoked (empty p=)");
    };

    // Load local private key and extract its public key
    const local_pub_b64 = extractPublicKey(allocator, kf, key_type) catch {
        return fatal("failed to load or parse private key file");
    };
    defer allocator.free(local_pub_b64);

    // Compare
    const out_header = try std.fmt.allocPrint(allocator,
        \\securearc-testkey: checking key {s}._domainkey.{s}
        \\  algorithm: {s}
        \\
    , .{ sel, dom, key_type });
    defer allocator.free(out_header);
    writeOut(out_header);

    if (mem.eql(u8, dns_pub, local_pub_b64)) {
        writeOut("  result: PASS — DNS public key matches local private key\n");
    } else {
        writeErr("  result: FAIL — DNS public key does NOT match local private key\n");
        process.exit(1);
    }
}

/// Extract base64-encoded public key from a private key file.
fn extractPublicKey(allocator: std.mem.Allocator, path: []const u8, key_type: []const u8) ![]u8 {
    if (mem.eql(u8, key_type, "ed25519")) {
        return extractEd25519PublicKey(allocator, path);
    }
    return extractRsaPublicKey(allocator, path);
}

fn extractRsaPublicKey(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const key = try crypto.loadRsaKeyFile(path);
    defer {
        var k = key;
        k.deinit();
    }

    const c = @cImport({
        @cInclude("openssl/evp.h");
        @cInclude("openssl/x509.h");
    });

    const pkey_const: ?*const c.EVP_PKEY = @ptrCast(key.rsa_pkey);
    const der_len: c_int = c.i2d_PUBKEY(pkey_const, null);
    if (der_len <= 0) return error.PubkeyExportFailed;

    const der_buf = try allocator.alloc(u8, @intCast(der_len));
    defer allocator.free(der_buf);

    var der_ptr: [*c]u8 = der_buf.ptr;
    _ = c.i2d_PUBKEY(pkey_const, &der_ptr);

    return crypto.base64Encode(allocator, der_buf);
}

fn extractEd25519PublicKey(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const content = try std.fs.cwd().readFileAlloc(allocator, path, 4096);
    defer allocator.free(content);

    // Find base64 content between PEM markers
    const begin_end = mem.indexOf(u8, content, "-----\n") orelse return error.InvalidPem;
    const data_start = begin_end + 6;
    const end_marker = mem.indexOf(u8, content[data_start..], "\n-----") orelse return error.InvalidPem;
    const seed_b64 = content[data_start..][0..end_marker];

    const seed_bytes = try crypto.base64Decode(allocator, seed_b64);
    defer allocator.free(seed_bytes);

    if (seed_bytes.len != 32) return error.InvalidSeedLength;

    const Ed25519 = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    @memcpy(&seed, seed_bytes);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    return crypto.base64Encode(allocator, &kp.public_key.toBytes());
}

/// Find a tag value in a semicolon-separated tag-list.
fn findTag(header_value: []const u8, tag_name: []const u8) ?[]const u8 {
    var rest = header_value;
    while (rest.len > 0) {
        rest = mem.trimLeft(u8, rest, &(.{ ';', ' ', '\t', '\r', '\n' }));
        if (rest.len == 0) break;

        const eq_pos = mem.indexOfScalar(u8, rest, '=') orelse break;
        const name = mem.trim(u8, rest[0..eq_pos], &std.ascii.whitespace);

        const value_start = eq_pos + 1;
        const semi_pos = mem.indexOfScalar(u8, rest[value_start..], ';');
        const value_end = if (semi_pos) |sp| value_start + sp else rest.len;
        const value = mem.trim(u8, rest[value_start..value_end], &std.ascii.whitespace);

        if (mem.eql(u8, name, tag_name)) return value;
        rest = if (semi_pos) |sp| rest[value_start + sp + 1 ..] else "";
    }
    return null;
}

fn fatal(msg: []const u8) noreturn {
    writeErr("error: ");
    writeErr(msg);
    writeErr("\n");
    process.exit(1);
}
