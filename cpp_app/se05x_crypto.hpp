// se05x_crypto.hpp
//
// C++ wrapper around the NXP SSS (Secure Subsystem) API for the SE05x
// secure element. Provides EC / RSA / RNG operations plus CSR generation
// (key stays on the SE; the CSR is signed by the SE via mbedTLS for the
// ASN.1 structure work).
//
// Built on top of the plug-and-trust ex_sss boot framework.

#ifndef SE05X_CRYPTO_HPP
#define SE05X_CRYPTO_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

namespace se05x {

// Thrown on any SSS / mbedTLS failure. Carries the sss_status_t when relevant.
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string &what, sss_status_t st = kStatus_SSS_Fail)
        : std::runtime_error(what + " (sss_status=0x" + hex(st) + ")"), status_(st) {}
    sss_status_t status() const { return status_; }

private:
    static std::string hex(sss_status_t st);
    sss_status_t status_;
};

enum class EcCurve { NistP256, NistP384, NistP521 };
enum class RsaBits { Rsa2048 = 2048, Rsa3072 = 3072, Rsa4096 = 4096 };

// Throws CryptoError if status != kStatus_SSS_Success.
void check(sss_status_t st, const char *where);

// Erase a persisted key object by id (no-op-safe: throws if it doesn't exist).
void eraseKey(class Session &s, uint32_t keyId);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
// Thin RAII-ish wrapper over the ex_sss boot context. The boot framework owns
// the actual open/close lifecycle (driven from main via ex_sss_entry), so this
// class just borrows the already-open context.
class Session {
public:
    explicit Session(ex_sss_boot_ctx_t *ctx) : ctx_(ctx) {}

    sss_session_t   *session()  { return &ctx_->session; }
    sss_key_store_t *keystore() { return &ctx_->ks; }
    ex_sss_boot_ctx_t *raw()    { return ctx_; }

private:
    ex_sss_boot_ctx_t *ctx_;
};

// ---------------------------------------------------------------------------
// Random number generator
// ---------------------------------------------------------------------------
std::vector<uint8_t> getRandom(Session &s, size_t numBytes);

// ---------------------------------------------------------------------------
// EC operations
// ---------------------------------------------------------------------------
class EcKey {
public:
    // Generates a fresh EC key pair persisted under `keyId` on the SE.
    static EcKey generate(Session &s, uint32_t keyId, EcCurve curve);

    // Binds to an existing persisted key object.
    static EcKey open(Session &s, uint32_t keyId);

    // Sign a precomputed digest. Returns ASN.1 DER (r,s) ECDSA signature.
    std::vector<uint8_t> sign(const std::vector<uint8_t> &digest);

    // Verify a DER ECDSA signature over a digest.
    bool verify(const std::vector<uint8_t> &digest,
                const std::vector<uint8_t> &signature);

    // ECDH: compute shared secret with a peer public key.
    // peerPubKeyDer is a DER SubjectPublicKeyInfo for the peer's EC public key.
    std::vector<uint8_t> ecdh(const std::vector<uint8_t> &peerPubKeyDer);

    // Export the public key as DER SubjectPublicKeyInfo.
    std::vector<uint8_t> publicKeyDer();

    // Generate a PKCS#10 CSR (PEM). Key never leaves the SE.
    std::string makeCsr(const std::string &subjectDn);

    sss_object_t       *object()    { return &obj_; }
    sss_algorithm_t     sigAlgo() const { return sigAlgo_; }
    void                setSigAlgo(sss_algorithm_t a) { sigAlgo_ = a; }
    Session            &session()   { return s_; }

    ~EcKey();
    EcKey(EcKey &&) noexcept;
    EcKey &operator=(EcKey &&) = delete;
    EcKey(const EcKey &) = delete;
    EcKey &operator=(const EcKey &) = delete;

private:
    EcKey(Session &s) : s_(s) {}
    Session        &s_;
    sss_object_t    obj_{};
    sss_algorithm_t sigAlgo_ = kAlgorithm_SSS_SHA256;
    EcCurve         curve_ = EcCurve::NistP256;
    bool            owns_ = false;
};

// ---------------------------------------------------------------------------
// RSA operations
// ---------------------------------------------------------------------------
class RsaKey {
public:
    static RsaKey generate(Session &s, uint32_t keyId, RsaBits bits);
    static RsaKey open(Session &s, uint32_t keyId);

    // RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    std::vector<uint8_t> sign(const std::vector<uint8_t> &digest);
    bool verify(const std::vector<uint8_t> &digest,
                const std::vector<uint8_t> &signature);

    // RSAES-OAEP-SHA256.
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);

    std::vector<uint8_t> publicKeyDer();
    std::string makeCsr(const std::string &subjectDn);

    sss_object_t   *object()  { return &obj_; }
    Session        &session() { return s_; }

    ~RsaKey();
    RsaKey(RsaKey &&) noexcept;
    RsaKey &operator=(RsaKey &&) = delete;
    RsaKey(const RsaKey &) = delete;
    RsaKey &operator=(const RsaKey &) = delete;

private:
    RsaKey(Session &s) : s_(s) {}
    Session     &s_;
    sss_object_t obj_{};
    size_t       bits_ = 2048;
    bool         owns_ = false;
};

} // namespace se05x

#endif // SE05X_CRYPTO_HPP