const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("mbedtls", .{});

    const lib = b.addStaticLibrary(.{
        .name = "mbedtls",
        .optimize = optimize,
        .target = target,
    });

    lib.addCSourceFiles(.{
        .root = upstream.path("library"),
        .files = &.{
            "debug.c",
            "sha1.c",
            "rsa_alt_helpers.c",
            "pk_wrap.c",
            "aes.c",
            "ecp_curves_new.c",
            "camellia.c",
            "block_cipher.c",
            "ssl_tls13_keys.c",
            "psa_crypto_pake.c",
            "psa_crypto_ffdh.c",
            "ssl_tls12_server.c",
            "base64.c",
            "psa_crypto_hash.c",
            "pkcs12.c",
            "pem.c",
            "psa_util.c",
            "psa_crypto_ecp.c",
            "x509write_crt.c",
            "timing.c",
            "entropy.c",
            "poly1305.c",
            "psa_crypto_driver_wrappers_no_static.c",
            "aesce.c",
            "version.c",
            "psa_crypto_storage.c",
            "ssl_tls13_client.c",
            "ssl_ticket.c",
            "padlock.c",
            "bignum_core.c",
            "cmac.c",
            "dhm.c",
            "gcm.c",
            "ssl_tls12_client.c",
            "des.c",
            "ctr_drbg.c",
            "ssl_tls13_generic.c",
            "md.c",
            "psa_crypto_rsa.c",
            "lms.c",
            "constant_time.c",
            "pkwrite.c",
            "psa_crypto.c",
            "chachapoly.c",
            "x509write.c",
            "pk.c",
            "sha256.c",
            "sha512.c",
            "ssl_tls13_server.c",
            "psa_crypto_se.c",
            "ecdsa.c",
            "hkdf.c",
            "ecp_curves.c",
            "x509_csr.c",
            "version_features.c",
            "mps_trace.c",
            "ssl_cookie.c",
            "bignum.c",
            "nist_kw.c",
            "platform.c",
            "entropy_poll.c",
            "pkcs5.c",
            "ssl_client.c",
            "asn1parse.c",
            "memory_buffer_alloc.c",
            "ecp.c",
            "psa_crypto_cipher.c",
            "bignum_mod_raw.c",
            "hmac_drbg.c",
            "ssl_tls.c",
            "mps_reader.c",
            "pk_ecc.c",
            "error.c",
            "psa_crypto_aead.c",
            "x509_crt.c",
            "ecdh.c",
            "ripemd160.c",
            "bignum_mod.c",
            "cipher_wrap.c",
            "psa_its_file.c",
            "ssl_cache.c",
            "md5.c",
            "asn1write.c",
            "ecjpake.c",
            "platform_util.c",
            "x509write_csr.c",
            "ssl_msg.c",
            "psa_crypto_slot_management.c",
            "psa_crypto_mac.c",
            "psa_crypto_client.c",
            "ssl_ciphersuites.c",
            "pkcs7.c",
            "aesni.c",
            "cipher.c",
            "x509_create.c",
            "oid.c",
            "net_sockets.c",
            "chacha20.c",
            "x509.c",
            "aria.c",
            "rsa.c",
            "pkparse.c",
            "ssl_debug_helpers_generated.c",
            "lmots.c",
            "ccm.c",
            "sha3.c",
            "threading.c",
            "x509_crl.c",
        },
    });

    lib.addIncludePath(upstream.path("library"));
    lib.addIncludePath(upstream.path("include"));

    lib.installHeadersDirectory(upstream.path("include"), "", .{});
    lib.installHeadersDirectory(upstream.path("library"), "", .{});

    lib.linkLibC();

    b.installArtifact(lib);
}
