// main.cpp
//
// Command-line front end for the SE05x crypto operations.
//
//   se05x_crypto_app [--port <conn>] <group> <command> [options]
//
//   groups : rng | ecc | rsa
//
//   rng    <nbytes>
//
//   ecc genkey  --id <hex> [--curve p256|p384|p521] [--force]
//   ecc pub     --id <hex> [--out <file>]
//   ecc sign    --id <hex> --in <file> [--out <file>]
//   ecc verify  --id <hex> --in <file> --sig <file>
//   ecc ecdh    --id <hex> --peer <pub.der> [--out <file>]
//   ecc csr     --id <hex> --subject "<DN>" [--out <file>]
//
//   rsa genkey  --id <hex> [--bits 2048|3072|4096] [--force]
//   rsa pub     --id <hex> [--out <file>]
//   rsa sign    --id <hex> --in <file> [--out <file>]
//   rsa verify  --id <hex> --in <file> --sig <file>
//   rsa encrypt --id <hex> --in <file> [--out <file>]
//   rsa decrypt --id <hex> --in <file> [--out <file>]
//   rsa csr     --id <hex> --subject "<DN>" [--out <file>]
//
// Connect string: pass --port (e.g. --port /dev/i2c-1:0x48) or set the
// EX_SSS_BOOT_SSS_PORT environment variable. sign/verify hash the input file
// with SHA-256 and operate on that digest.

#include "se05x_crypto.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
#include "mbedtls/sha256.h"
}

namespace {

// ----- tiny option parser ----------------------------------------------------
struct Args {
    std::string group;
    std::string command;
    std::string positional;                 // e.g. nbytes for rng
    std::map<std::string, std::string> opt;  // --key value
    bool flag(const std::string &k) const { return opt.count(k) != 0; }
    std::string get(const std::string &k, const std::string &def = "") const {
        auto it = opt.find(k);
        return it == opt.end() ? def : it->second;
    }
};

// ----- file / hex helpers ----------------------------------------------------
std::vector<uint8_t> readFile(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open input file: " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

void writeFile(const std::string &path, const std::vector<uint8_t> &d) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open output file: " + path);
    f.write(reinterpret_cast<const char *>(d.data()),
            static_cast<std::streamsize>(d.size()));
}

void printHex(const std::vector<uint8_t> &d) {
    for (uint8_t b : d) std::printf("%02x", b);
    std::printf("\n");
}

// Write to --out as binary, or hex to stdout.
void emit(const Args &a, const std::vector<uint8_t> &d) {
    std::string out = a.get("--out");
    if (!out.empty()) {
        writeFile(out, d);
        std::fprintf(stderr, "[+] wrote %zu bytes to %s\n", d.size(), out.c_str());
    } else {
        printHex(d);
    }
}

void emitText(const Args &a, const std::string &text) {
    std::string out = a.get("--out");
    if (!out.empty()) {
        std::vector<uint8_t> d(text.begin(), text.end());
        writeFile(out, d);
        std::fprintf(stderr, "[+] wrote %s\n", out.c_str());
    } else {
        std::fputs(text.c_str(), stdout);
    }
}

uint32_t parseId(const Args &a) {
    std::string s = a.get("--id");
    if (s.empty()) throw std::runtime_error("--id is required");
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 0));
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &msg) {
    std::vector<uint8_t> out(32);
    mbedtls_sha256(msg.data(), msg.size(), out.data(), 0);
    return out;
}

se05x::EcCurve parseCurve(const std::string &s) {
    if (s.empty() || s == "p256") return se05x::EcCurve::NistP256;
    if (s == "p384") return se05x::EcCurve::NistP384;
    if (s == "p521") return se05x::EcCurve::NistP521;
    throw std::runtime_error("unknown curve: " + s);
}

se05x::RsaBits parseBits(const std::string &s) {
    if (s.empty() || s == "2048") return se05x::RsaBits::Rsa2048;
    if (s == "3072") return se05x::RsaBits::Rsa3072;
    if (s == "4096") return se05x::RsaBits::Rsa4096;
    throw std::runtime_error("unknown RSA size: " + s);
}

// ----- subcommand handlers ---------------------------------------------------
int doRng(se05x::Session &s, const Args &a) {
    if (a.positional.empty()) throw std::runtime_error("usage: rng <nbytes>");
    size_t n = std::strtoul(a.positional.c_str(), nullptr, 0);
    emit(a, se05x::getRandom(s, n));
    return 0;
}

int doEcc(se05x::Session &s, const Args &a) {
    const std::string &cmd = a.command;

    if (cmd == "genkey" || cmd == "provision") {
        uint32_t id = parseId(a);
        if (a.flag("--force")) { try { se05x::eraseKey(s, id); } catch (...) {} }
        auto k = se05x::EcKey::generate(s, id, parseCurve(a.get("--curve")));
        std::fprintf(stderr, "[+] EC key provisioned (id=0x%08X)\n", id);
        emit(a, k.publicKeyDer());
        return 0;
    }
    if (cmd == "pub") {
        auto k = se05x::EcKey::open(s, parseId(a));
        emit(a, k.publicKeyDer());
        return 0;
    }
    if (cmd == "sign") {
        auto k = se05x::EcKey::open(s, parseId(a));
        k.setSigAlgo(kAlgorithm_SSS_SHA256);
        auto digest = sha256(readFile(a.get("--in")));
        emit(a, k.sign(digest));
        return 0;
    }
    if (cmd == "verify") {
        auto k = se05x::EcKey::open(s, parseId(a));
        k.setSigAlgo(kAlgorithm_SSS_SHA256);
        auto digest = sha256(readFile(a.get("--in")));
        auto sig = readFile(a.get("--sig"));
        bool ok = k.verify(digest, sig);
        std::printf("%s\n", ok ? "VERIFY OK" : "VERIFY FAILED");
        return ok ? 0 : 2;
    }
    if (cmd == "ecdh") {
        auto k = se05x::EcKey::open(s, parseId(a));
        auto peer = readFile(a.get("--peer"));
        emit(a, k.ecdh(peer));
        return 0;
    }
    if (cmd == "csr") {
        auto k = se05x::EcKey::open(s, parseId(a));
        k.setSigAlgo(kAlgorithm_SSS_SHA256);
        std::string dn = a.get("--subject");
        if (dn.empty()) throw std::runtime_error("--subject is required");
        emitText(a, k.makeCsr(dn));
        return 0;
    }
    throw std::runtime_error("unknown ecc command: " + cmd);
}

int doRsa(se05x::Session &s, const Args &a) {
    const std::string &cmd = a.command;

    if (cmd == "genkey" || cmd == "provision") {
        uint32_t id = parseId(a);
        if (a.flag("--force")) { try { se05x::eraseKey(s, id); } catch (...) {} }
        auto k = se05x::RsaKey::generate(s, id, parseBits(a.get("--bits")));
        std::fprintf(stderr, "[+] RSA key provisioned (id=0x%08X)\n", id);
        emit(a, k.publicKeyDer());
        return 0;
    }
    if (cmd == "pub") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        emit(a, k.publicKeyDer());
        return 0;
    }
    if (cmd == "sign") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        auto digest = sha256(readFile(a.get("--in")));
        emit(a, k.sign(digest));
        return 0;
    }
    if (cmd == "verify") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        auto digest = sha256(readFile(a.get("--in")));
        auto sig = readFile(a.get("--sig"));
        bool ok = k.verify(digest, sig);
        std::printf("%s\n", ok ? "VERIFY OK" : "VERIFY FAILED");
        return ok ? 0 : 2;
    }
    if (cmd == "encrypt") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        emit(a, k.encrypt(readFile(a.get("--in"))));
        return 0;
    }
    if (cmd == "decrypt") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        emit(a, k.decrypt(readFile(a.get("--in"))));
        return 0;
    }
    if (cmd == "csr") {
        auto k = se05x::RsaKey::open(s, parseId(a));
        std::string dn = a.get("--subject");
        if (dn.empty()) throw std::runtime_error("--subject is required");
        emitText(a, k.makeCsr(dn));
        return 0;
    }
    throw std::runtime_error("unknown rsa command: " + cmd);
}

void usage(const char *prog) {
    std::fprintf(stderr,
        "Usage: %s [--port <conn>] <group> <command> [options]\n\n"
        "Groups:\n"
        "  rng <nbytes>\n"
        "  ecc genkey|pub|sign|verify|ecdh|csr\n"
        "  rsa genkey|pub|sign|verify|encrypt|decrypt|csr\n\n"
        "Common options: --id <hex>  --in <file>  --out <file>  --sig <file>\n"
        "  --curve p256|p384|p521   --bits 2048|3072|4096\n"
        "  --peer <pub.der>  --subject \"CN=...,O=...\"  --force\n\n"
        "Connect string via --port or $EX_SSS_BOOT_SSS_PORT.\n",
        prog);
}

Args parseArgs(int argc, char **argv) {
    Args a;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            // flags that take no value
            if (t == "--force") { a.opt[t] = "1"; continue; }
            if (i + 1 < argc) { a.opt[t] = argv[++i]; }
            else { a.opt[t] = "1"; }
        } else {
            pos.push_back(t);
        }
    }
    if (pos.size() > 0) a.group = pos[0];
    if (pos.size() > 1) a.command = pos[1];
    if (pos.size() > 2) a.positional = pos[2];
    // rng takes its count as the 2nd positional
    if (a.group == "rng" && a.positional.empty()) a.positional = a.command;
    return a;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    Args a = parseArgs(argc, argv);
    if (a.group.empty()) { usage(argv[0]); return 1; }

    // Resolve connect string.
    std::string port = a.get("--port");
    const char *portName =
        !port.empty() ? port.c_str() : std::getenv("EX_SSS_BOOT_SSS_PORT");

    ex_sss_boot_ctx_t ctx;
    std::memset(&ctx, 0, sizeof(ctx));

    sss_status_t st = ex_sss_boot_open(&ctx, portName);
    if (st != kStatus_SSS_Success) {
        std::fprintf(stderr, "[!] ex_sss_boot_open failed (0x%04x). "
                             "Set --port or $EX_SSS_BOOT_SSS_PORT.\n",
                     static_cast<unsigned>(st));
        return 1;
    }
    st = ex_sss_key_store_and_object_init(&ctx);
    if (st != kStatus_SSS_Success) {
        std::fprintf(stderr, "[!] key store init failed (0x%04x)\n",
                     static_cast<unsigned>(st));
        ex_sss_session_close(&ctx);
        return 1;
    }

    int rc = 0;
    try {
        se05x::Session session(&ctx);
        if (a.group == "rng")      rc = doRng(session, a);
        else if (a.group == "ecc") rc = doEcc(session, a);
        else if (a.group == "rsa") rc = doRsa(session, a);
        else { usage(argv[0]); rc = 1; }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "[!] %s\n", e.what());
        rc = 1;
    }

    ex_sss_session_close(&ctx);
    return rc;
}