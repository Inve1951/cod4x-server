const std = @import("std");
const ResolvedTarget = std.Build.ResolvedTarget;

const StringList = std.ArrayList([]const u8);
var source_files: *StringList = undefined;

var build_plugins_only: *std.Build.Step = undefined;

pub fn build(b: *std.Build) !void {
    source_files = try b.allocator.create(StringList);
    source_files.* = try StringList.initCapacity(b.allocator, 200);

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "cod4x18_dedrun",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = optimize == .ReleaseSmall,
        // .omit_frame_pointer = false,
    });
    // exe.pie = false;
    exe.addIncludePath(.{ .path = "src" });
    // obj.defineCMacro("__cdecl", "__cdecl");

    var c_flags = try StringList.initCapacity(b.allocator, 13);
    c_flags.appendSliceAssumeCapacity(&.{
        "-Wno-implicit-function-declaration",
        // TODO: Get these values from the git cli
        // exe.addConfigHeader
        "-DBUILD_NUMBER=1165",
        "-DBUILD_BRANCH=master",
        "-DBUILD_REVISION=f73c628d8a08e9a4b4ec77d1c0eb0557ec56290e",
        "-fno-omit-frame-pointer",
        "-fvisibility=hidden",
        "-g3",
    });
    exe.rdynamic = true;
    c_flags.appendSliceAssumeCapacity(switch (target.result.os.tag) {
        .windows => &.{"-DWINVER=0x501"},
        else => &.{"-D_GNU_SOURCE"},
    });
    if (target.result.os.tag != .windows and
        (b.option(bool, "link-ubsan", "Link ubsan1 external system library") orelse false) and
        (optimize == .Debug or optimize == .ReleaseSafe))
    {
        // https://github.com/ziglang/zig/issues/5163#issuecomment-811606110
        c_flags.appendSliceAssumeCapacity(&.{
            "-fno-sanitize=alignment",
            "-fno-sanitize-trap=undefined",
            "-fno-sanitize-recover=undefined",
        });
        // https://github.com/ziglang/zig/issues/16733
        // exe.addLibraryPath(.{ .path = b.fmt("/usr/lib/{s}", .{try target.result.linuxTriple(b.allocator)}) });
        exe.addLibraryPath(.{ .path = "/usr/lib/i386-linux-gnu" });
        // `sudo apt install libubsan1:i386` and create unversioned symlink manually if it's missing
        exe.linkSystemLibrary("ubsan");
    }

    {
        defer source_files.clearRetainingCapacity();
        try addFilesFromDir(b, source_files, "src", ".c");
        try addFilesFromDir(b, source_files, "src/zlib", ".c");
        try addFilesFromDir(b, source_files, "src/xassets", ".c");
        try addFilesFromDir(b, source_files, "src/version", ".c");
        switch (target.result.os.tag) {
            .windows => try addFilesFromDir(b, source_files, "src/win32", ".c"),
            .linux, .freebsd => try addFilesFromDir(b, source_files, "src/unix", ".c"),
            inline else => |tag| @panic("Unsupported OS: " ++ @tagName(tag)),
        }
        exe.addCSourceFiles(.{
            .files = source_files.items,
            .flags = c_flags.items,
        });
    }

    {
        defer source_files.clearRetainingCapacity();
        try addFilesFromDir(b, source_files, "src", ".cpp");
        c_flags.appendSliceAssumeCapacity(&.{
            "-std=c++14",
        });
        exe.addCSourceFiles(.{
            .files = source_files.items,
            .flags = c_flags.items,
        });
    }

    for (try buildAsm(b, target)) |o_file| {
        exe.addObjectFile(o_file);
    }

    exe.linkLibrary(try buildTomcrypt(b, target, optimize));

    for (try buildMbedtlsLibs(b, target, optimize)) |lib| {
        exe.linkLibrary(lib);
    }

    exe.linkLibCpp();
    switch (target.result.os.tag) {
        .windows => {
            exe.linkSystemLibrary("ws2_32");
            exe.linkSystemLibrary("wsock32");
            exe.linkSystemLibrary("iphlpapi");
            exe.linkSystemLibrary("gdi32");
            exe.linkSystemLibrary("winmm");
            exe.linkSystemLibrary("crypt32");
        },
        .freebsd => {
            exe.linkLibC();
            exe.linkSystemLibrary("execinfo");
        },
        else => {
            exe.linkLibC();
        },
    }

    b.installArtifact(exe);
}

fn addFilesFromDir(b: *std.Build, files: *StringList, path: []const u8, ext: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(b.pathFromRoot(path), .{ .access_sub_paths = false, .iterate = true, .no_follow = true });
    defer dir.close();
    var it = dir.iterate();
    var found = false;
    while (try it.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ext)) {
            files.appendAssumeCapacity(b.pathJoin(&.{ path, entry.name }));
            found = true;
        }
    }
    if (!found) @panic(b.fmt("Found no files in '{s}' with '{s}' extension", .{ path, ext }));
}

fn buildAsm(b: *std.Build, target: ResolvedTarget) ![]std.Build.LazyPath {
    const nasm = b.dependency("nasm", .{
        .optimize = .ReleaseSafe,
    }).artifact("nasm");

    defer source_files.clearRetainingCapacity();
    try addFilesFromDir(b, source_files, "src/asmsource", ".asm");

    var o_files = try std.ArrayListUnmanaged(std.Build.LazyPath).initCapacity(b.allocator, source_files.items.len);

    for (source_files.items) |asm_file| {
        const nasm_run = b.addRunArtifact(nasm);

        switch (target.result.os.tag) {
            .windows => nasm_run.addArgs(&.{ "-f", "win", "-dWin32", "--prefix", "_" }),
            else => nasm_run.addArgs(&.{ "-f", "elf" }),
        }

        nasm_run.addArg(asm_file);
        nasm_run.addArg("-o");
        const o_file = nasm_run.addOutputFileArg(b.fmt("{s}{s}", .{ std.fs.path.basename(asm_file[0 .. asm_file.len - 4]), ".o" }));
        o_files.appendAssumeCapacity(o_file);

        nasm_run.expectExitCode(0);
        nasm_run.expectStdErrEqual("");
    }

    return o_files.items;
}

fn buildTomcrypt(b: *std.Build, target: ResolvedTarget, optimize: std.builtin.OptimizeMode) !*std.Build.Step.Compile {
    const tomcrypt = b.addStaticLibrary(.{
        .name = "tomcrypt",
        .target = target,
        .optimize = optimize,
        .strip = optimize == .ReleaseSmall,
    });
    defer source_files.clearRetainingCapacity();
    source_files.appendAssumeCapacity("src/tomcrypt/ciphers/aes/aes.c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/hashes", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/misc/crypt", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/misc/base64", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/misc", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/misc/pkcs5", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/mac/hmac", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/bit", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/boolean", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/choice", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/ia5", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/integer", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/object_identifier", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/octet", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/printable_string", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/sequence", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/short_integer", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/utctime", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/utf8", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/asn1/der/set", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/rsa", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/pk/pkcs1", ".c");
    try addFilesFromDir(b, source_files, "src/tomcrypt/math", ".c");

    tomcrypt.addIncludePath(.{ .path = "src/tomcrypt" });
    tomcrypt.addIncludePath(.{ .path = "src/tomcrypt/math" });
    tomcrypt.linkLibC();
    tomcrypt.addCSourceFiles(.{
        .files = source_files.items,
        .flags = &.{
            "-Wno-implicit-function-declaration",
            "-DLTC_NO_ROLC",
            "-DLTC_SOURCE",
        },
    });
    return tomcrypt;
}

fn buildMbedtlsLibs(b: *std.Build, target: ResolvedTarget, optimize: std.builtin.OptimizeMode) ![]const *std.Build.Step.Compile {
    const mbedtls = b.addStaticLibrary(.{
        .name = "mbedtls",
        .target = target,
        .optimize = optimize,
        .strip = optimize == .ReleaseSmall,
    });
    mbedtls.addIncludePath(.{ .path = "src" });
    mbedtls.linkLibC();
    mbedtls.addCSourceFiles(.{ .files = &.{
        "src/mbedtls/debug.c",
        "src/mbedtls/ssl_cache.c",
        "src/mbedtls/ssl_ciphersuites.c",
        "src/mbedtls/ssl_cli.c",
        "src/mbedtls/ssl_cookie.c",
        "src/mbedtls/ssl_srv.c",
        "src/mbedtls/ssl_ticket.c",
        "src/mbedtls/ssl_tls.c",
        "src/mbedtls/pkparse.c",
        "src/mbedtls/pkcs5.c",
    } });

    const mbedx509 = b.addStaticLibrary(.{
        .name = "mbedx509",
        .target = target,
        .optimize = optimize,
        .strip = optimize == .ReleaseSmall,
    });
    mbedx509.addIncludePath(.{ .path = "src" });
    mbedx509.linkLibC();
    mbedx509.addCSourceFiles(.{ .files = &.{
        "src/mbedtls/certs.c",
        "src/mbedtls/pkcs11.c",
        "src/mbedtls/x509.c",
        "src/mbedtls/x509_create.c",
        "src/mbedtls/x509_crl.c",
        "src/mbedtls/x509_crt.c",
        "src/mbedtls/x509_csr.c",
        "src/mbedtls/x509write_crt.c",
        "src/mbedtls/x509write_csr.c",
        "src/mbedtls/pkparse.c",
        "src/mbedtls/pkcs5.c",
        "src/mbedtls/pk.c",
        "src/mbedtls/pkcs12.c",
    } });

    const mbedcrypto = b.addStaticLibrary(.{
        .name = "mbedcrypto",
        .target = target,
        .optimize = optimize,
        .strip = optimize == .ReleaseSmall,
    });
    mbedcrypto.addIncludePath(.{ .path = "src" });
    mbedcrypto.linkLibC();
    mbedcrypto.addCSourceFiles(.{ .files = &.{
        "src/mbedtls/aes.c",              "src/mbedtls/aesni.c",               "src/mbedtls/arc4.c",
        "src/mbedtls/asn1parse.c",        "src/mbedtls/asn1write.c",           "src/mbedtls/base64.c",
        "src/mbedtls/bignum.c",           "src/mbedtls/blowfish.c",            "src/mbedtls/camellia.c",
        "src/mbedtls/ccm.c",              "src/mbedtls/cipher.c",              "src/mbedtls/cipher_wrap.c",
        "src/mbedtls/ctr_drbg.c",         "src/mbedtls/des.c",                 "src/mbedtls/dhm.c",
        "src/mbedtls/ecdh.c",             "src/mbedtls/ecdsa.c",               "src/mbedtls/ecjpake.c",
        "src/mbedtls/ecp.c",              "src/mbedtls/ecp_curves.c",          "src/mbedtls/entropy.c",
        "src/mbedtls/entropy_poll.c",     "src/mbedtls/error.c",               "src/mbedtls/gcm.c",
        "src/mbedtls/havege.c",           "src/mbedtls/hmac_drbg.c",           "src/mbedtls/md.c",
        "src/mbedtls/md2.c",              "src/mbedtls/md4.c",                 "src/mbedtls/md5.c",
        "src/mbedtls/md_wrap.c",          "src/mbedtls/memory_buffer_alloc.c", "src/mbedtls/oid.c",
        "src/mbedtls/padlock.c",          "src/mbedtls/pem.c",                 "src/mbedtls/pk.c",
        "src/mbedtls/pk_wrap.c",          "src/mbedtls/pkcs12.c",              "src/mbedtls/pkcs5.c",
        "src/mbedtls/pkparse.c",          "src/mbedtls/pkwrite.c",             "src/mbedtls/platform.c",
        "src/mbedtls/ripemd160.c",        "src/mbedtls/rsa.c",                 "src/mbedtls/sha1.c",
        "src/mbedtls/sha256.c",           "src/mbedtls/sha512.c",              "src/mbedtls/threading.c",
        "src/mbedtls/timing.c",           "src/mbedtls/version.c",             "src/mbedtls/platform_util.c",
        "src/mbedtls/version_features.c", "src/mbedtls/xtea.c",                "src/mbedtls/chacha20.c",
        "src/mbedtls/chachapoly.c",       "src/mbedtls/poly1305.c",            "src/mbedtls/rsa_internal.c",
    } });

    const res = try b.allocator.alloc(*std.Build.Step.Compile, 3);
    res[0..3].* = .{ mbedtls, mbedx509, mbedcrypto };
    return res;
}
