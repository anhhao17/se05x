// se05x_crypto.cpp
#include "se05x_crypto.hpp"

#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace se05x {

std::string CryptoError::hex(sss_status_t st) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04x", static_cast<unsigned>(st));
    return buf;
}

void check(sss_status_t st, const char *where) {
    if (st != kStatus_SSS_Success) {
        throw CryptoError(std::string("SSS call failed: ") + where, st);
    }
}

void eraseKey(Session &s, uint32_t keyId) {
    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "key_object_init(erase)");
    check(sss_key_object_get_handle(&obj, keyId), "key_object_get_handle(erase)");
    check(sss_key_store_erase_key(s.keystore(), &obj), "key_store_erase_key");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
namespace {

uint32_t curveBits(EcCurve c) {
    switch (c) {
        case EcCurve::NistP256: return 256;
        case EcCurve::NistP384: return 384;
        case EcCurve::NistP521: return 521;
    }
    return 256;
}

sss_algorithm_t curveSigAlgo(EcCurve c) {
    switch (c) {
        case EcCurve::NistP256: return kAlgorithm_SSS_SHA256;
        case EcCurve::NistP384: return kAlgorithm_SSS_SHA384;
        case EcCurve::NistP521: return kAlgorithm_SSS_SHA512;
    }
    return kAlgorithm_SSS_SHA256;
}

// Allocate + bind a key object handle to an existing persisted key.
void openHandle(Session &s, sss_object_t *obj, uint32_t keyId) {
    check(sss_key_object_init(obj, s.keystore()), "key_object_init");
    check(sss_key_object_get_handle(obj, keyId), "key_object_get_handle");
}

} // namespace

// ---------------------------------------------------------------------------
// RNG
// ---------------------------------------------------------------------------
std::vector<uint8_t> getRandom(Session &s, size_t numBytes) {
    sss_rng_context_t rng{};
    check(sss_rng_context_init(&rng, s.session()), "rng_context_init");
    std::vector<uint8_t> out(numBytes);
    sss_status_t st = sss_rng_get_random(&rng, out.data(), out.size());
    sss_rng_context_free(&rng);
    check(st, "rng_get_random");
    return out;
}

// ---------------------------------------------------------------------------
// EcKey
// ---------------------------------------------------------------------------
EcKey EcKey::generate(Session &s, uint32_t keyId, EcCurve curve) {
    EcKey k(s);
    k.curve_   = curve;
    k.sigAlgo_ = curveSigAlgo(curve);
    k.owns_    = true;

    const uint32_t bits  = curveBits(curve);
    const size_t   bytes = (bits + 7) / 8;

    check(sss_key_object_init(&k.obj_, s.keystore()), "key_object_init");
    check(sss_key_object_allocate_handle(
              &k.obj_, keyId,
              kSSS_KeyPart_Pair,
              kSSS_CipherType_EC_NIST_P,
              3 * bytes + 8 /* room for pub point */,
              kKeyObject_Mode_Persistent),
          "key_object_allocate_handle(EC)");
    check(sss_key_store_generate_key(s.keystore(), &k.obj_, bits, nullptr),
          "key_store_generate_key(EC)");
    return k;
}

EcKey EcKey::open(Session &s, uint32_t keyId) {
    EcKey k(s);
    k.owns_ = false;
    openHandle(s, &k.obj_, keyId);
    // Default to SHA-256; caller can sign P-384/521 digests too.
    k.sigAlgo_ = kAlgorithm_SSS_SHA256;
    return k;
}

std::vector<uint8_t> EcKey::sign(const std::vector<uint8_t> &digest) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      sigAlgo_, kMode_SSS_Sign),
          "asymmetric_context_init(EC sign)");

    std::vector<uint8_t> sig(256); // DER ECDSA sig is small; 256 is plenty
    size_t sigLen = sig.size();
    sss_status_t st = sss_asymmetric_sign_digest(
        &ctx,
        const_cast<uint8_t *>(digest.data()), digest.size(),
        sig.data(), &sigLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_sign_digest(EC)");
    sig.resize(sigLen);
    return sig;
}

bool EcKey::verify(const std::vector<uint8_t> &digest,
                   const std::vector<uint8_t> &signature) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      sigAlgo_, kMode_SSS_Verify),
          "asymmetric_context_init(EC verify)");
    sss_status_t st = sss_asymmetric_verify_digest(
        &ctx,
        const_cast<uint8_t *>(digest.data()), digest.size(),
        const_cast<uint8_t *>(signature.data()), signature.size());
    sss_asymmetric_context_free(&ctx);
    return st == kStatus_SSS_Success;
}

std::vector<uint8_t> EcKey::ecdh(const std::vector<uint8_t> &peerPubKeyDer) {
    // Load the peer public key into a transient host/SE key object.
    sss_object_t peer{};
    check(sss_key_object_init(&peer, s_.keystore()), "key_object_init(peer)");
    check(sss_key_object_allocate_handle(
              &peer, 0xEF009E01u,
              kSSS_KeyPart_Public,
              kSSS_CipherType_EC_NIST_P,
              peerPubKeyDer.size(),
              kKeyObject_Mode_Transient),
          "key_object_allocate_handle(peer)");
    check(sss_key_store_set_key(s_.keystore(), &peer,
                                peerPubKeyDer.data(), peerPubKeyDer.size(),
                                curveBits(curve_), nullptr, 0),
          "key_store_set_key(peer)");

    // Derived shared secret lands in a transient object we can read back.
    sss_object_t shared{};
    check(sss_key_object_init(&shared, s_.keystore()), "key_object_init(shared)");
    check(sss_key_object_allocate_handle(
              &shared, 0xEF009E02u,
              kSSS_KeyPart_Default,
              kSSS_CipherType_AES,            // shared secret as raw bytes
              64,
              kKeyObject_Mode_Transient),
          "key_object_allocate_handle(shared)");

    sss_derive_key_t dctx{};
    check(sss_derive_key_context_init(&dctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_ECDH,
                                      kMode_SSS_ComputeSharedSecret),
          "derive_key_context_init");
    sss_status_t st = sss_derive_key_dh(&dctx, &peer, &shared);
    sss_derive_key_context_free(&dctx);
    check(st, "derive_key_dh");

    // Read the shared secret back out.
    std::vector<uint8_t> secret(64);
    size_t secretLen = secret.size();
    size_t secretBits = secretLen * 8;
    st = sss_key_store_get_key(s_.keystore(), &shared,
                               secret.data(), &secretLen, &secretBits);
    check(st, "key_store_get_key(shared)");
    secret.resize(secretLen);
    return secret;
}

std::vector<uint8_t> EcKey::publicKeyDer() {
    std::vector<uint8_t> buf(256);
    size_t len = buf.size();
    size_t bits = 0;
    check(sss_key_store_get_key(s_.keystore(), &obj_, buf.data(), &len, &bits),
          "key_store_get_key(EC pub)");
    buf.resize(len);
    return buf;
}

EcKey::EcKey(EcKey &&o) noexcept
    : s_(o.s_), obj_(o.obj_), sigAlgo_(o.sigAlgo_), curve_(o.curve_), owns_(o.owns_) {
    o.owns_ = false;
}

EcKey::~EcKey() {
    // Note: persisted keys are intentionally NOT erased here. We only free the
    // in-RAM context. Use a dedicated delete operation to wipe SE storage.
}

// ---------------------------------------------------------------------------
// RsaKey
// ---------------------------------------------------------------------------
RsaKey RsaKey::generate(Session &s, uint32_t keyId, RsaBits bits) {
    RsaKey k(s);
    k.bits_ = static_cast<size_t>(bits);
    k.owns_ = true;

    check(sss_key_object_init(&k.obj_, s.keystore()), "key_object_init");
    check(sss_key_object_allocate_handle(
              &k.obj_, keyId,
              kSSS_KeyPart_Pair,
              kSSS_CipherType_RSA,
              k.bits_ / 8,
              kKeyObject_Mode_Persistent),
          "key_object_allocate_handle(RSA)");
    check(sss_key_store_generate_key(s.keystore(), &k.obj_,
                                     static_cast<uint32_t>(k.bits_), nullptr),
          "key_store_generate_key(RSA)");
    return k;
}

RsaKey RsaKey::open(Session &s, uint32_t keyId) {
    RsaKey k(s);
    k.owns_ = false;
    openHandle(s, &k.obj_, keyId);
    return k;
}

std::vector<uint8_t> RsaKey::sign(const std::vector<uint8_t> &digest) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                      kMode_SSS_Sign),
          "asymmetric_context_init(RSA sign)");
    std::vector<uint8_t> sig(bits_ / 8);
    size_t sigLen = sig.size();
    sss_status_t st = sss_asymmetric_sign_digest(
        &ctx,
        const_cast<uint8_t *>(digest.data()), digest.size(),
        sig.data(), &sigLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_sign_digest(RSA)");
    sig.resize(sigLen);
    return sig;
}

bool RsaKey::verify(const std::vector<uint8_t> &digest,
                    const std::vector<uint8_t> &signature) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                      kMode_SSS_Verify),
          "asymmetric_context_init(RSA verify)");
    sss_status_t st = sss_asymmetric_verify_digest(
        &ctx,
        const_cast<uint8_t *>(digest.data()), digest.size(),
        const_cast<uint8_t *>(signature.data()), signature.size());
    sss_asymmetric_context_free(&ctx);
    return st == kStatus_SSS_Success;
}

std::vector<uint8_t> RsaKey::encrypt(const std::vector<uint8_t> &plaintext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                      kMode_SSS_Encrypt),
          "asymmetric_context_init(RSA enc)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t outLen = out.size();
    sss_status_t st = sss_asymmetric_encrypt(
        &ctx,
        const_cast<uint8_t *>(plaintext.data()), plaintext.size(),
        out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_encrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::decrypt(const std::vector<uint8_t> &ciphertext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                      kMode_SSS_Decrypt),
          "asymmetric_context_init(RSA dec)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t outLen = out.size();
    sss_status_t st = sss_asymmetric_decrypt(
        &ctx,
        const_cast<uint8_t *>(ciphertext.data()), ciphertext.size(),
        out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_decrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::publicKeyDer() {
    std::vector<uint8_t> buf(bits_ / 8 + 64);
    size_t len = buf.size();
    size_t bits = 0;
    check(sss_key_store_get_key(s_.keystore(), &obj_, buf.data(), &len, &bits),
          "key_store_get_key(RSA pub)");
    buf.resize(len);
    return buf;
}

RsaKey::RsaKey(RsaKey &&o) noexcept
    : s_(o.s_), obj_(o.obj_), bits_(o.bits_), owns_(o.owns_) {
    o.owns_ = false;
}

RsaKey::~RsaKey() {}

} // namespace se05x