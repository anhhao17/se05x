/*
 * pkcs11_demo.c — PKCS#11 demo for NXP SE051
 *
 * Demonstrates via libsss_pkcs11.so:
 *   1. Hardware RNG (C_GenerateRandom)
 *   2. EC P-256 key pair generation (C_GenerateKeyPair / CKM_EC_KEY_PAIR_GEN)
 *   3. ECDSA-SHA256 sign (C_Sign / CKM_ECDSA_SHA256)
 *   4. ECDSA-SHA256 verify (C_Verify)
 *   5. Key destruction (C_DestroyObject)
 *
 * Usage:
 *   ./pkcs11_demo [/path/to/libsss_pkcs11.so]
 *
 * The library is loaded at runtime via dlopen so the binary has no
 * link-time dependency on it.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

/* cryptoki.h defines the required platform macros then includes pkcs11.h */
#include "cryptoki.h"

/* ---- Key ID used for the demo ---------------------------------------- */
#define DEMO_KEY_ID      0xEF000020u
#define DEMO_KEY_LABEL   "sss:0xEF000020"

/* P-256 (prime256v1) OID — DER encoding of ECParameters namedCurve */
static const CK_BYTE kEcP256Params[] = {
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

/* 4-byte big-endian key ID for CKA_ID */
static const CK_BYTE kKeyId[] = { 0xEF, 0x00, 0x00, 0x20 };

static const CK_BYTE kMessage[] = "SE051 PKCS#11 demo — sign this";

/* ---- Helpers ------------------------------------------------------------- */
static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;

static void print_hex(const char *label, const CK_BYTE *buf, CK_ULONG len)
{
    printf("  %-24s(%3lu B): ", label, len);
    for (CK_ULONG i = 0; i < len && i < 48; i++)
        printf("%02x", buf[i]);
    if (len > 48)
        printf("...");
    printf("\n");
}

#define CK_CHECK(call) \
    do { \
        CK_RV _rv = (call); \
        if (_rv != CKR_OK) { \
            fprintf(stderr, "[FAIL] %s: 0x%08lX\n", #call, _rv); \
            rc = 1; \
            goto cleanup; \
        } \
    } while (0)

/* ---- Main ---------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    const char *lib_path = (argc > 1) ? argv[1] : "libsss_pkcs11.so";

    int           rc      = 0;
    void         *lib     = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hPriv  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hPub   = CK_INVALID_HANDLE;

    CK_BBOOL ck_true = CK_TRUE;

    /* Signature buffer: CKM_ECDSA_SHA256 output is raw r||s, 64 B for P-256 */
    CK_BYTE   sig[128];
    CK_ULONG  sigLen = sizeof(sig);

    CK_BYTE   ecPoint[128];
    CK_BYTE   rnd[32];
    CK_ULONG  slotCount = 0;
    CK_SLOT_ID slots[8];
    CK_SLOT_ID slot = 0;

    /* ------------------------------------------------------------------ */
    /* Load library                                                         */
    /* ------------------------------------------------------------------ */
    lib = dlopen(lib_path, RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen(%s): %s\n", lib_path, dlerror());
        return 1;
    }

    CK_C_GetFunctionList getFnList =
        (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
    if (!getFnList || getFnList(&p11) != CKR_OK || !p11) {
        fprintf(stderr, "C_GetFunctionList failed\n");
        rc = 1;
        goto done;
    }

    printf("=== SE051 PKCS#11 Demo ===\n");
    printf("Library : %s\n\n", lib_path);

    /* ------------------------------------------------------------------ */
    /* Initialize and open session                                          */
    /* ------------------------------------------------------------------ */
    CK_CHECK(p11->C_Initialize(NULL_PTR));

    CK_CHECK(p11->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount));
    if (slotCount == 0) {
        fprintf(stderr, "No PKCS#11 slots found — is the SE connected?\n");
        rc = 1;
        goto cleanup;
    }
    /* Fetch the actual slot IDs — do not assume the slot ID is 0. */
    if (slotCount > sizeof(slots)/sizeof(slots[0]))
        slotCount = sizeof(slots)/sizeof(slots[0]);
    CK_CHECK(p11->C_GetSlotList(CK_TRUE, slots, &slotCount));
    slot = slots[0];
    printf("Slots   : %lu  (using slot ID %lu)\n", slotCount, slot);

    CK_CHECK(p11->C_OpenSession(slot,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &session));
    printf("Session : %lu\n\n", session);

    /* ------------------------------------------------------------------ */
    /* 1. Hardware RNG                                                      */
    /* ------------------------------------------------------------------ */
    printf("--- Hardware RNG ---\n");
    CK_CHECK(p11->C_GenerateRandom(session, rnd, sizeof(rnd)));
    print_hex("32 random bytes", rnd, sizeof(rnd));
    printf("\n");

    /* ------------------------------------------------------------------ */
    /* 2. EC P-256 key pair generation                                      */
    /* ------------------------------------------------------------------ */
    printf("--- EC P-256 Key Pair Generation ---\n");

    CK_ATTRIBUTE pubTemplate[] = {
        { CKA_TOKEN,     &ck_true,                       sizeof(ck_true)          },
        { CKA_VERIFY,    &ck_true,                       sizeof(ck_true)          },
        { CKA_EC_PARAMS, (CK_VOID_PTR)kEcP256Params,    sizeof(kEcP256Params)    },
        { CKA_LABEL,     (CK_VOID_PTR)DEMO_KEY_LABEL,   sizeof(DEMO_KEY_LABEL)-1 },
        { CKA_ID,        (CK_VOID_PTR)kKeyId,            sizeof(kKeyId)           },
    };
    CK_ATTRIBUTE privTemplate[] = {
        { CKA_TOKEN,     &ck_true,                       sizeof(ck_true)          },
        { CKA_SIGN,      &ck_true,                       sizeof(ck_true)          },
        { CKA_LABEL,     (CK_VOID_PTR)DEMO_KEY_LABEL,   sizeof(DEMO_KEY_LABEL)-1 },
        { CKA_ID,        (CK_VOID_PTR)kKeyId,            sizeof(kKeyId)           },
    };
    CK_MECHANISM mechKeyGen = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

    CK_CHECK(p11->C_GenerateKeyPair(
        session, &mechKeyGen,
        pubTemplate,  sizeof(pubTemplate)  / sizeof(pubTemplate[0]),
        privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
        &hPub, &hPriv));

    printf("  Key label : %s (ID 0x%08X)\n", DEMO_KEY_LABEL, DEMO_KEY_ID);
    printf("  hPub=%lu  hPriv=%lu\n", hPub, hPriv);

    /* Export and display the EC public key point */
    CK_ATTRIBUTE ecPointAttr = { CKA_EC_POINT, ecPoint, sizeof(ecPoint) };
    if (p11->C_GetAttributeValue(session, hPub, &ecPointAttr, 1) == CKR_OK)
        print_hex("EC public key point", ecPoint, ecPointAttr.ulValueLen);
    printf("\n");

    /* ------------------------------------------------------------------ */
    /* 3 & 4. ECDSA-SHA256 sign + verify                                   */
    /* ------------------------------------------------------------------ */
    printf("--- ECDSA-SHA256 Sign / Verify ---\n");
    printf("  Message : \"%s\"\n", (const char *)kMessage);

    CK_MECHANISM mechSign = { CKM_ECDSA_SHA256, NULL_PTR, 0 };

    CK_CHECK(p11->C_SignInit(session, &mechSign, hPriv));
    CK_CHECK(p11->C_Sign(session,
                         (CK_BYTE_PTR)kMessage, (CK_ULONG)(sizeof(kMessage) - 1),
                         sig, &sigLen));
    print_hex("Signature (raw r||s)", sig, sigLen);

    CK_CHECK(p11->C_VerifyInit(session, &mechSign, hPub));
    CK_CHECK(p11->C_Verify(session,
                           (CK_BYTE_PTR)kMessage, (CK_ULONG)(sizeof(kMessage) - 1),
                           sig, sigLen));
    printf("  Signature : VALID\n\n");

    printf("=== All operations succeeded ===\n");

cleanup:
    /* Destroy the key objects provisioned on the SE */
    if (hPriv != CK_INVALID_HANDLE && p11)
        p11->C_DestroyObject(session, hPriv);
    if (hPub != CK_INVALID_HANDLE && p11)
        p11->C_DestroyObject(session, hPub);
    if (session != CK_INVALID_HANDLE && p11)
        p11->C_CloseSession(session);
    if (p11)
        p11->C_Finalize(NULL_PTR);
done:
    if (lib)
        dlclose(lib);
    return rc;
}
