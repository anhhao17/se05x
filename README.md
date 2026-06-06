# Features request.
# Because since we dont have hardware to test, please make sure we use correctly API from SSS or mbedtls and note that this is cross compilation for ARM32 bit

## Application minimum requirements using c++ and SSS or mbedtls API. 
### As initial step:
1) Communicate with SE05X, handling error.
2) Provision keys using RSA first, ECC(Later). Check exist KEYID if it's our type like RSA or ECC... has option to force override it
3) Abilty to sign and export public key to send along with data

### New task
1) Client server application, use Private key in SE05X and public key to establish connection and communicate. (1 side has SE05X) both applications

### Your recommendations changes to use SE05X features, like
```
    EC crypto
        EC key generation
        EC sign/verify
        ECDH compute key
        CSR
    RSA crypto
        RSA key generation
        RSA sign/verify
        RSA encrypt/decrypt
        CSR
    Random generator
```

## Since we dont have SE05X we should handle like if can't load SE05X fallback to use standard