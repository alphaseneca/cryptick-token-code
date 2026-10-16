// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "u2f.h"
#include "ctaphid.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "crypto.h"
#include "util.h"
#include "log.h"
#include "device.h"
#include APP_CONFIG
#include "wallet.h"
#include "extensions.h"

#include "device.h"
#include "data_migration.h"
#include <board_config.h>

uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

AuthenticatorState STATE;

static void ctap_reset_key_agreement();

struct _getAssertionState getAssertionState;

// Generate a mask to keep the confidentiality of the "metadata" field in the credential ID.
// Mask = hmac(device-secret, 14-random-bytes-in-credential-id)
// Masked_output = Mask ^ metadata
static void add_masked_metadata_for_credential(CredentialId * credential, uint32_t metadata){
    uint8_t mask[32];
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, mask);
    crypto_sha256_update(credential->entropy.nonce, CREDENTIAL_NONCE_SIZE - 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0, mask);

    credential->entropy.metadata.value = *((uint32_t*)mask) ^ metadata;
}

static uint32_t read_metadata_from_masked_credential(CredentialId * credential){
    uint8_t mask[32];
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, mask);
    crypto_sha256_update(credential->entropy.nonce, CREDENTIAL_NONCE_SIZE - 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0, mask);

    return credential->entropy.metadata.value ^ *((uint32_t*)mask);
}

static uint32_t read_cred_protect_from_masked_credential(CredentialId * credential)
{
    return read_metadata_from_masked_credential(credential) & 0xffffU;
}

static int32_t read_cose_alg_from_masked_credential(CredentialId * credential)
{
    uint8_t  alg = (read_metadata_from_masked_credential(credential) >> 16) & 0xffU;

    switch (alg)
    {
        default: // what else?
        case CREDID_ALG_ES256:
            return COSE_ALG_ES256;
        case CREDID_ALG_EDDSA:
            return COSE_ALG_EDDSA;
    }
}

static uint8_t check_credential_metadata(CredentialId * credential, uint8_t is_verified, uint8_t is_from_credid_list)
{
    uint32_t cred_protect = read_cred_protect_from_masked_credential(credential);

    switch (cred_protect){
        case EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID:
            if (!is_from_credid_list) {
                if (!is_verified)
                {
                    return CTAP2_ERR_NOT_ALLOWED;
                }
            }
        break;
        case EXT_CRED_PROTECT_REQUIRED:
            if (!is_verified)
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }
        break;
    }

    return 0;
}

static uint8_t verify_pin_auth_ex(uint8_t * pinAuth, uint8_t *buf, size_t len)
{
    uint8_t hmac[32];

    crypto_sha256_hmac_init(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);
    crypto_sha256_hmac_update(buf, len);
    crypto_sha256_hmac_final(PIN_TOKEN, PIN_TOKEN_SIZE, hmac);

    if (memcmp(pinAuth, hmac, 16) == 0)
    {
        return 0;
    }
    else
    {
        printf2(TAG_ERR,"Pin auth failed\n");
        dump_hex1(TAG_ERR,pinAuth,16);
        dump_hex1(TAG_ERR,hmac,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
}

uint8_t verify_pin_auth(uint8_t * pinAuth, uint8_t * clientDataHash)
{
    return verify_pin_auth_ex(pinAuth, clientDataHash, CLIENT_DATA_HASH_SIZE);
}

uint8_t ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    CborEncoder pins;
    uint8_t aaguid[16];
    device_read_aaguid(aaguid);

    /*
     * Product policy (browser WebAuthn):
     *  - UV = fingerprint (options.uv=true), not clientPin.
     *  - NEVER advertise clientPin:false — presence of the key means "PIN capable".
     *    Chrome then sends empty pinAuth as a touch probe; after finger we returned
     *    CTAP2_ERR_PIN_NOT_SET → generic browser NotAllowedError while OLED still
     *    showed Place finger. Only list clientPin when a PIN is actually set.
     *  - versions: U2F_V2 + FIDO_2_0 (Chrome often creates via CTAPHID_MSG/U2F).
     *  - Not FIDO_2_1_PRE: stay on CTAP2.0 built-in UV, not pinUvAuthToken-only.
     *    (That is about the everyday sign-in ceremony only — MakeCredential/
     *    GetAssertion still gate on a direct per-request touch, never on a
     *    pinUvAuthToken. It does not affect whether authenticatorClientPIN's
     *    own subcommands, below, are advertised.)
     *  - pinUvAuthProtocols: a platform needs this to know which protocol
     *    number to negotiate keyAgreement/pinUvAuthParam under *before* it
     *    can call CP_cmdGetPinUvAuthTokenUsingUvWithPermissions (CTAP2.1
     *    §6.5.5) for credential management — so, like `uv` above, this is
     *    advertised whenever a pinUvAuthToken is obtainable at all, by PIN
     *    *or* by UV, not only when a PIN happens to be set. This device
     *    implements exactly PIN/UV Auth Protocol One (see the pinProtocol
     *    != 1 check in ctap_client_pin()), so the array is always `[1]`.
     */
    const int pin_set = (ctap_is_pin_set() != 0);
    /* UV (fingerprint) is always available on this product, per the `uv`
     * policy above — so a pinUvAuthToken is always obtainable one way or
     * the other, and pinUvAuthProtocols is unconditional like `uv` is,
     * not conditional like `clientPin` (which depends on a PIN existing). */
    const int uv_token_obtainable = 1;
    const int map_keys = (pin_set || uv_token_obtainable) ? 10 : 9;
    const int opt_keys = pin_set ? 6 : 5;

    ret = cbor_encoder_create_map(encoder, &map, map_keys);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, RESP_versions);     //  versions key
        check_ret(ret);
        {
            /*
             * Prefer FIDO_2_0 first so platforms that pick versions[0] use CTAP2
             * MakeCredential (fmt "none") when possible. Keep U2F_V2 for macOS
             * Chrome CTAPHID_MSG fallback (do not set CAPABILITY_NMSG).
             */
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "U2F_V2");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_extensions);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "credProtect");
                check_ret(ret);

                ret = cbor_encode_text_stringz(&array, "hmac-secret");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_aaguid);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, aaguid, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_options);
        check_ret(ret);
        {
            ret = cbor_encoder_create_map(&map, &options, opt_keys);
            check_ret(ret);
            {
                /*
                 * Canonical CBOR key order (RFC 7049 §3.9 / RFC 8949 §4.2.1):
                 * 1. Shortest encoded byte length first:
                 *    - 2-byte keys: "rk" (0x62726b), "up" (0x627570), "uv" (0x627576)
                 *    - 4-byte keys: "plat" (0x64706c6174)
                 *    - 8-byte keys: "credMgmt" (0x68637265644d676d74)
                 *    - 9-byte keys: "clientPin" (0x69636c69656e7450696e)
                 * 2. Lexicographical order for equal lengths.
                 */
                ret = cbor_encode_text_string(&options, "rk", 2);
                check_ret(ret);
                ret = cbor_encode_boolean(&options, 1);
                check_ret(ret);

                ret = cbor_encode_text_string(&options, "up", 2);
                check_ret(ret);
                ret = cbor_encode_boolean(&options, 1);
                check_ret(ret);

                ret = cbor_encode_text_string(&options, "uv", 2);
                check_ret(ret);
                ret = cbor_encode_boolean(&options, 1);
                check_ret(ret);

                ret = cbor_encode_text_string(&options, "plat", 4);
                check_ret(ret);
                ret = cbor_encode_boolean(&options, 0);
                check_ret(ret);

                ret = cbor_encode_text_string(&options, "credMgmt", 8);
                check_ret(ret);
                ret = cbor_encode_boolean(&options, 1);
                check_ret(ret);

                if (pin_set)
                {
                    ret = cbor_encode_text_string(&options, "clientPin", 9);
                    check_ret(ret);
                    ret = cbor_encode_boolean(&options, 1);
                    check_ret(ret);
                }
            }
            ret = cbor_encoder_close_container(&map, &options);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_maxMsgSize);
        check_ret(ret);
        {
            ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
            check_ret(ret);
        }

        if (pin_set || uv_token_obtainable)
        {
            ret = cbor_encode_uint(&map, RESP_pinProtocols);
            check_ret(ret);
            {
                ret = cbor_encoder_create_array(&map, &pins, 1);
                check_ret(ret);
                {
                    ret = cbor_encode_int(&pins, 1);
                    check_ret(ret);
                }
                ret = cbor_encoder_close_container(&map, &pins);
                check_ret(ret);
            }
        }


        ret = cbor_encode_uint(&map, 0x07); //maxCredentialCountInList
        check_ret(ret);
        {
            ret = cbor_encode_uint(&map, ALLOW_LIST_MAX_SIZE);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x08); // maxCredentialIdLength
        check_ret(ret);
        {
            ret = cbor_encode_uint(&map, 128);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x09); // transports
        check_ret(ret);
        {
#if defined(CRYPTICK_BLE_FIDO) && CRYPTICK_BLE_FIDO
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "usb");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "ble");
            check_ret(ret);
#else
            ret = cbor_encoder_create_array(&map, &array, 1);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "usb");
            check_ret(ret);
#endif
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x0a); // algorithms
        check_ret(ret);
        {
            CborEncoder alg;
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);

            /* Canonical key order: "alg" then "type" */
            ret = cbor_encoder_create_map(&array, &alg, 2);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "alg");
            check_ret(ret);
            ret = cbor_encode_int(&alg, -7); // ES256
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "type");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "public-key");
            check_ret(ret);
            ret = cbor_encoder_close_container(&array, &alg);
            check_ret(ret);

            ret = cbor_encoder_create_map(&array, &alg, 2);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "alg");
            check_ret(ret);
            ret = cbor_encode_int(&alg, -8); // EDDSA (Ed25519)
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "type");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&alg, "public-key");
            check_ret(ret);
            ret = cbor_encoder_close_container(&array, &alg);
            check_ret(ret);

            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return CTAP1_ERR_SUCCESS;
}



static int ctap_add_cose_key(CborEncoder * cose_key, uint8_t * x, uint8_t * y, uint8_t credtype, int32_t algtype)
{
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, algtype != COSE_ALG_EDDSA? 5 : 4);
    check_ret(ret);


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA? COSE_KEY_KTY_EC2 : COSE_KEY_KTY_OKP);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA? COSE_KEY_CRV_P256: COSE_KEY_CRV_ED25519);
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, x, 32);
        check_ret(ret);
    }

    if (algtype != COSE_ALG_EDDSA)
    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, y, 32);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(cose_key, &map);
    check_ret(ret);

    return 0;
}
static int ctap_generate_cose_key(CborEncoder * cose_key, uint8_t * hmac_input, int len, uint8_t credtype, int32_t algtype)
{
    uint8_t x[32], y[32];

    if (credtype != PUB_KEY_CRED_PUB_KEY)
    {
        printf2(TAG_ERR,"Error, pubkey credential type not supported\n");
        return -1;
    }
    switch(algtype)
    {
        case COSE_ALG_ES256:
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ecc256_derive_public_key(hmac_input, len, x, y);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
            break;
        case COSE_ALG_EDDSA:
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ed25519_derive_public_key(hmac_input, len, x);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
            break;
        default:
            printf2(TAG_ERR,"Error, COSE alg %d not supported\n", algtype);
            return -1;
    }
    int ret = ctap_add_cose_key(cose_key, x, y, credtype, algtype);
    check_ret(ret);
    return 0;
}

void make_auth_tag(uint8_t * rpIdHash, uint8_t * nonce, uint32_t count, uint8_t * tag)
{
    uint8_t hashbuf[32];
    memset(hashbuf,0,sizeof(hashbuf));
    crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY, 0, hashbuf);
    crypto_sha256_update(rpIdHash, 32);
    crypto_sha256_update(nonce, CREDENTIAL_NONCE_SIZE);
    crypto_sha256_update((uint8_t*)&count, 4);
    crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY,0,hashbuf);

    memmove(tag, hashbuf, CREDENTIAL_TAG_SIZE);
}

void ctap_flush_state()
{
    authenticator_write_state(&STATE);
}

static uint32_t auth_data_update_count(CTAP_authDataHeader * authData)
{
    uint32_t count = ctap_atomic_count( 1 );
    if (count == 0)     // count 0 will indicate invalid token
    {
        count = ctap_atomic_count( 1 );

    }
    uint8_t * byte = (uint8_t*) &authData->signCount;

    *byte++ = (count >> 24) & 0xff;
    *byte++ = (count >> 16) & 0xff;
    *byte++ = (count >> 8) & 0xff;
    *byte++ = (count >> 0) & 0xff;

    return count;
}

static void ctap_increment_rk_store()
{
    STATE.rk_stored++;
    ctap_flush_state();
}
static void ctap_decrement_rk_store()
{
    STATE.rk_stored--;
    ctap_flush_state();
}

// Return 1 if rk is valid, 0 if not.
static int ctap_rk_is_valid(CTAP_residentKey * rk)
{
    return (rk->id.count > 0 && rk->id.count != 0xffffffff);
}

static int load_nth_valid_rk(int n, CTAP_residentKey * rk) {

    int valid_count = 0;
    unsigned int i;
    for (i = 0; i < ctap_rk_size(); i++)
    {
        ctap_load_rk(i, rk);
        if ( ctap_rk_is_valid(rk) ) {
            if (valid_count == n) {
                return i;
            }
            valid_count++;
        }
    }
    return -1;
}

static int is_matching_rk(CTAP_residentKey * rk, CTAP_residentKey * rk2)
{
    return (memcmp(rk->id.rpIdHash, rk2->id.rpIdHash, 32) == 0) &&
           (memcmp(rk->user.id, rk2->user.id, rk->user.id_size) == 0) &&
           (rk->user.id_size == rk2->user.id_size);
}

static int is_cred_id_matching_rk(CredentialId * credId, CTAP_residentKey * rk)
{
    return (memcmp(credId, &rk->id, sizeof(CredentialId)) == 0);
}

static int ctap_make_extensions(CTAP_extensions * ext, uint8_t * ext_encoder_buf, unsigned int * ext_encoder_buf_size)
{
    CborEncoder extensions;
    int ret;
    uint8_t extensions_used = 0;
    uint8_t hmac_secret_output_is_valid = 0;
    uint8_t hmac_secret_requested_is_valid = 0;
    uint8_t cred_protect_is_valid = 0;
    uint8_t hmac_secret_output[64];
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    uint8_t credRandom[32];
    uint8_t saltEnc[64];

    if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        printf1(TAG_CTAP, "Processing hmac-secret..\r\n");
        memmove(saltEnc, ext->hmac_secret.saltEnc, sizeof(saltEnc));

        crypto_ecc256_shared_secret((uint8_t*) &ext->hmac_secret.keyAgreement.pubkey,
                                    KEY_AGREEMENT_PRIV,
                                    shared_secret);
        crypto_sha256_init();
        crypto_sha256_update(shared_secret, 32);
        crypto_sha256_final(shared_secret);

        crypto_sha256_hmac_init(shared_secret, 32, hmac);
        crypto_sha256_update(saltEnc, ext->hmac_secret.saltLen);
        crypto_sha256_hmac_final(shared_secret, 32, hmac);

        if (memcmp(ext->hmac_secret.saltAuth, hmac, 16) == 0)
        {
            printf1(TAG_CTAP, "saltAuth is valid\r\n");
        }
        else
        {
            printf1(TAG_CTAP, "saltAuth is invalid\r\n");
            return CTAP2_ERR_EXTENSION_FIRST;
        }

        // Generate credRandom
        crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY2, 0, credRandom);
        crypto_sha256_update((uint8_t*)&ext->hmac_secret.credential->id, sizeof(CredentialId));
        crypto_sha256_update(&getAssertionState.user_verified, 1);
        crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY2, 0, credRandom);

        // Decrypt saltEnc
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_decrypt(saltEnc, ext->hmac_secret.saltLen);

        // Generate outputs
        crypto_sha256_hmac_init(credRandom, 32, hmac_secret_output);
        crypto_sha256_update(saltEnc, 32);
        crypto_sha256_hmac_final(credRandom, 32, hmac_secret_output);

        if (ext->hmac_secret.saltLen == 64)
        {
            crypto_sha256_hmac_init(credRandom, 32, hmac_secret_output + 32);
            crypto_sha256_update(saltEnc + 32, 32);
            crypto_sha256_hmac_final(credRandom, 32, hmac_secret_output + 32);
        }

        // Encrypt for final output
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_encrypt(hmac_secret_output, ext->hmac_secret.saltLen);


        extensions_used += 1;
        hmac_secret_output_is_valid = 1;
    }
    else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED)
    {
        extensions_used += 1;
        hmac_secret_requested_is_valid = 1;
    }
    if (ext->cred_protect != EXT_CRED_PROTECT_INVALID) {
        if (
            ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL ||
            ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID ||
            ext->cred_protect == EXT_CRED_PROTECT_REQUIRED
            )
        {
            extensions_used += 1;
            cred_protect_is_valid = 1;
        }
    }

    if (extensions_used > 0)
    {

        // output
        cbor_encoder_init(&extensions, ext_encoder_buf, *ext_encoder_buf_size, 0);
        {
            CborEncoder extension_output_map;
            ret = cbor_encoder_create_map(&extensions, &extension_output_map, extensions_used);
            check_ret(ret);
            if (hmac_secret_output_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
                    check_ret(ret);

                    ret = cbor_encode_byte_string(&extension_output_map, hmac_secret_output, ext->hmac_secret.saltLen);
                    check_ret(ret);
                }
            }
            if (cred_protect_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "credProtect");
                    check_ret(ret);

                    ret = cbor_encode_int(&extension_output_map, ext->cred_protect);
                    check_ret(ret);
                }
            }
            if (hmac_secret_requested_is_valid) {
                {
                    ret = cbor_encode_text_stringz(&extension_output_map, "hmac-secret");
                    check_ret(ret);

                    ret = cbor_encode_boolean(&extension_output_map, 1);
                    check_ret(ret);
                }
            }

            ret = cbor_encoder_close_container(&extensions, &extension_output_map);
            check_ret(ret);

        }
        *ext_encoder_buf_size = cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);

    } else
    {
        *ext_encoder_buf_size = 0;
    }



    return 0;
}

static unsigned int get_credential_id_size(int type)
{
    if (type == PUB_KEY_CRED_CTAP1)
        return U2F_KEY_HANDLE_SIZE;
    if (type == PUB_KEY_CRED_CUSTOM)
        return getAssertionState.customCredIdSize;
    return sizeof(CredentialId);
}

static int ctap2_user_presence_test(int allow_uv_cache)
{
    /* Cache is a GetTouch credit for MakeCredential only. */
    int ret = ctap_user_presence_test_ex(CTAP2_UP_DELAY_MS, allow_uv_cache);
    if ( ret > 1 )
    {
        return CTAP2_ERR_PROCESSING;
    }
    else if ( ret > 0 )
    {
        return CTAP1_ERR_SUCCESS;
    }
    else if (ret < 0)
    {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    else
    {
        return CTAP2_ERR_ACTION_TIMEOUT;
    }
}

static int ctap_make_auth_data(struct rpId * rp, CborEncoder * map, uint8_t * auth_data_buf, uint32_t * len, CTAP_credInfo * credInfo, CTAP_extensions * extensions)
{
    CborEncoder cose_key;

    unsigned int auth_data_sz = sizeof(CTAP_authDataHeader);
    uint32_t count;
    CTAP_residentKey rk, rk2;
    CTAP_authData * authData = (CTAP_authData *)auth_data_buf;

    uint8_t * cose_key_buf = auth_data_buf + sizeof(CTAP_authData);

    // memset(&cose_key, 0, sizeof(CTAP_residentKey));
    memset(&rk, 0, sizeof(CTAP_residentKey));
    memset(&rk2, 0, sizeof(CTAP_residentKey));

    if((sizeof(CTAP_authDataHeader)) > *len)
    {
        printf1(TAG_ERR,"assertion fail, auth_data_buf must be at least %d bytes\n", sizeof(CTAP_authData) - sizeof(CTAP_attestHeader));
        return CTAP2_ERR_VENDOR_FIRST;
    }

    crypto_sha256_init();
    crypto_sha256_update(rp->id, rp->size);
    crypto_sha256_final(authData->head.rpIdHash);

    count = auth_data_update_count(&authData->head);

    int but;

    but = ctap2_user_presence_test(credInfo != NULL);
    if (CTAP2_ERR_PROCESSING == but)
    {
        authData->head.flags = (0 << 0);        // User presence disabled
    }
    else
    {
        check_retr(but);
        authData->head.flags = (1 << 0);        // User presence
        /*
         * Product: fingerprint presence is also userVerification (GetInfo uv=true).
         * clientPin UV still sets the same bit when PIN is configured.
         */
        authData->head.flags |= (1 << 2);
    }


    device_set_status(CTAPHID_STATUS_PROCESSING);

    if (ctap_is_pin_set())
        authData->head.flags |= (1 << 2);


    if (credInfo != NULL)
    {
        // add attestedCredentialData
        authData->head.flags |= (1 << 6);//include attestation data

        cbor_encoder_init(&cose_key, cose_key_buf, *len - sizeof(CTAP_authData), 0);

        device_read_aaguid(authData->attest.aaguid);
        authData->attest.credLenL =  sizeof(CredentialId) & 0x00FF;
        authData->attest.credLenH = (sizeof(CredentialId) & 0xFF00) >> 8;

        memset((uint8_t*)&authData->attest.id, 0, sizeof(CredentialId));

        ctap_generate_rng(authData->attest.id.entropy.nonce, CREDENTIAL_NONCE_SIZE);

        uint8_t alg = credInfo->COSEAlgorithmIdentifier == COSE_ALG_EDDSA? CREDID_ALG_EDDSA : CREDID_ALG_ES256;
        add_masked_metadata_for_credential(&authData->attest.id, extensions->cred_protect | (alg << 16));

        authData->attest.id.count = count;

        memmove(authData->attest.id.rpIdHash, authData->head.rpIdHash, 32);

        // Make a tag we can later check to make sure this is a token we made
        make_auth_tag(authData->head.rpIdHash, authData->attest.id.entropy.nonce, count, authData->attest.id.tag);

        // resident key
        if (credInfo->rk)
        {
            memmove(&rk.id, &authData->attest.id, sizeof(CredentialId));
            memmove(&rk.user, &credInfo->user, sizeof(CTAP_userEntity));

            // Copy rpId to RK, but it could be cropped.
            int rp_id_size = rp->size < sizeof(rk.rpId) ? rp->size : sizeof(rk.rpId);
            memmove(rk.rpId, rp->id, rp_id_size);
            rk.rpIdSize = rp_id_size;

            unsigned int index = STATE.rk_stored;
            unsigned int i;
            for (i = 0; i < index; i++)
            {
                int raw_i = load_nth_valid_rk(i, &rk2);
                if (is_matching_rk(&rk, &rk2))
                {
                    ctap_overwrite_rk(raw_i, &rk);
                    goto done_rk;
                }
            }
            for (i = 0; i < ctap_rk_size(); i++){
                ctap_load_rk(i, &rk2);
                if ( ! ctap_rk_is_valid(&rk2) ){
                    ctap_increment_rk_store();
                    ctap_store_rk(i, &rk);
                    printf1(TAG_GREEN, "Created rk %d:", i); dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);
                    goto done_rk;
                }
            }

            printf2(TAG_ERR, "Out of memory for resident keys\r\n");
            return CTAP2_ERR_KEY_STORE_FULL;
        }
done_rk:

        printf1(TAG_GREEN, "MADE credId: "); dump_hex1(TAG_GREEN, (uint8_t*) &authData->attest.id, sizeof(CredentialId));

        ctap_generate_cose_key(&cose_key, (uint8_t*)&authData->attest.id, sizeof(CredentialId), credInfo->publicKeyCredentialType, credInfo->COSEAlgorithmIdentifier);

        auth_data_sz = sizeof(CTAP_authData) + cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);

    }





    *len = auth_data_sz;
    return 0;
}


/**
 * Pack r||s (64 B) into a DER SEQUENCE for ECDSA-Sig-Value (U2F / packed
 * attStmt). Strips leading zeros and adds the high-bit INTEGER padding so
 * Chrome's BoringSSL accepts the signature.
 *
 * @param in_sigbuf  IN  raw r||s, exactly 64 bytes
 * @param out_sigder OUT DER signature, buffer must be at least 72 bytes
 * @return bytes written: 8 in the degenerate all-zero case, at most 72 when
 *         both INTEGERs need a pad byte (2 + 2 + 33 + 2 + 33).
 */
int ctap_encode_der_sig(const uint8_t * const in_sigbuf, uint8_t * const out_sigder)
{
    int lead_r = 0;
    int lead_s = 0;
    int i;

    for (i = 0; i < 32; i++) {
        if (in_sigbuf[i] == 0)
            lead_r++;
        else
            break;
    }
    for (i = 0; i < 32; i++) {
        if (in_sigbuf[i + 32] == 0)
            lead_s++;
        else
            break;
    }
    /* never strip everything — INTEGER must contain at least one content byte */
    if (lead_r >= 32)
        lead_r = 31;
    if (lead_s >= 32)
        lead_s = 31;

    int pad_r = ((in_sigbuf[lead_r] & 0x80) != 0) ? 1 : 0;
    int pad_s = ((in_sigbuf[32 + lead_s] & 0x80) != 0) ? 1 : 0;
    int r_len = 32 - lead_r + pad_r;
    int s_len = 32 - lead_s + pad_s;
    int total = 2 + r_len + 2 + s_len; /* two INTEGER TLVs inside SEQUENCE */

    /*
     * r_len and s_len are each at most 33 (32 content + 1 pad), so total is at
     * most 70 and the encoding always fits the 72-byte output buffer. The old
     * guard clamped total to 70 on overflow, which would have written a length
     * byte that disagreed with the bytes actually emitted.
     */

    out_sigder[0] = 0x30;
    out_sigder[1] = (uint8_t)total;

    int o = 2;
    out_sigder[o++] = 0x02;
    out_sigder[o++] = (uint8_t)r_len;
    if (pad_r)
        out_sigder[o++] = 0x00;
    memmove(out_sigder + o, in_sigbuf + lead_r, (size_t)(32 - lead_r));
    o += 32 - lead_r;

    out_sigder[o++] = 0x02;
    out_sigder[o++] = (uint8_t)s_len;
    if (pad_s)
        out_sigder[o++] = 0x00;
    memmove(out_sigder + o, in_sigbuf + 32 + lead_s, (size_t)(32 - lead_s));
    o += 32 - lead_s;

    return o;
}

// require load_key prior to this
// @data data to hash before signature, MUST have room to append clientDataHash for ED25519
// @clientDataHash for signature
// @tmp buffer for hash.  (can be same as data if data >= 32 bytes)
// @sigbuf OUT location to deposit signature (must be 64 bytes)
// @sigder OUT location to deposit der signature (must be 72 bytes)
// @return length of der signature
int ctap_calculate_signature(uint8_t * data, int datalen, uint8_t * clientDataHash, uint8_t * hashbuf, uint8_t * sigbuf, uint8_t * sigder, int32_t alg)
{
    // calculate attestation sig
    if (alg == COSE_ALG_EDDSA)
    {
        crypto_ed25519_sign(data, datalen, clientDataHash, CLIENT_DATA_HASH_SIZE, sigder); // not DER, just plain binary!
        return 64;
    }
    else
    {
        crypto_sha256_init();
        crypto_sha256_update(data, datalen);
        crypto_sha256_update(clientDataHash, CLIENT_DATA_HASH_SIZE);
        crypto_sha256_final(hashbuf);

        crypto_ecc256_sign(hashbuf, 32, sigbuf);
        return ctap_encode_der_sig(sigbuf,sigder);
    }
}

uint8_t ctap_add_attest_statement(CborEncoder * map, uint8_t * sigder, int len)
{
    int ret;
    uint8_t cert[1024];
    uint16_t cert_size = device_attestation_cert_der_get_size();
    if (cert_size > sizeof(cert)){
        printf2(TAG_ERR,"Certificate is too large for CTAP2 buffer\r\n");
        return CTAP2_ERR_PROCESSING;
    }
    device_attestation_read_cert_der(cert);

    CborEncoder stmtmap;
    CborEncoder x5carr;

    ret = cbor_encode_int(map,RESP_attStmt);
    check_ret(ret);
    ret = cbor_encoder_create_map(map, &stmtmap, 3);
    check_ret(ret);
    {
        ret = cbor_encode_text_stringz(&stmtmap,"alg");
        check_ret(ret);
        ret = cbor_encode_int(&stmtmap,COSE_ALG_ES256);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"sig");
        check_ret(ret);
        ret = cbor_encode_byte_string(&stmtmap, sigder, len);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"x5c");
        check_ret(ret);
        ret = cbor_encoder_create_array(&stmtmap, &x5carr, 1);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&x5carr, cert, device_attestation_cert_der_get_size());
            check_ret(ret);
            ret = cbor_encoder_close_container(&stmtmap, &x5carr);
            check_ret(ret);
        }
    }

    ret = cbor_encoder_close_container(map, &stmtmap);
    check_ret(ret);
    return 0;
}

// Return 1 if credential belongs to this token
int ctap_authenticate_credential(struct rpId * rp, CTAP_credentialDescriptor * desc)
{
    uint8_t rpIdHash[32];
    uint8_t tag[16];

    switch(desc->type)
    {
        case PUB_KEY_CRED_PUB_KEY:
            crypto_sha256_init();
            crypto_sha256_update(rp->id, rp->size);
            crypto_sha256_final(rpIdHash);

            printf1(TAG_RED,"rpId: %s\r\n", rp->id); dump_hex1(TAG_RED,rp->id, rp->size);
            if (memcmp(desc->credential.id.rpIdHash, rpIdHash, 32) != 0)
            {
                return 0;
            }
            make_auth_tag(rpIdHash, desc->credential.id.entropy.nonce, desc->credential.id.count, tag);
            return (memcmp(desc->credential.id.tag, tag, CREDENTIAL_TAG_SIZE) == 0);
        break;
        case PUB_KEY_CRED_CTAP1:
            crypto_sha256_init();
            crypto_sha256_update(rp->id, rp->size);
            crypto_sha256_final(rpIdHash);
            return u2f_authenticate_credential((struct u2f_key_handle *)&desc->credential.id, U2F_KEY_HANDLE_SIZE,rpIdHash);
        break;
        case PUB_KEY_CRED_CUSTOM:
            return is_extension_request(getAssertionState.customCredId, getAssertionState.customCredIdSize);
        break;
        default:
        printf1(TAG_ERR, "PUB_KEY_CRED_UNKNOWN %x\r\n",desc->type);
        break;
    }

    return 0;
}



uint8_t ctap_make_credential(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_makeCredential MC;
    int ret;
    unsigned int i;
    /* Separate signature temps from authData: shared-buffer layout was tight on large cose keys. */
    uint8_t auth_data_buf[512];
#if !(defined(CRYPTICK_ATTEST_FMT_NONE) && CRYPTICK_ATTEST_FMT_NONE)
    uint8_t hashbuf[32];
    uint8_t sigbuf[64];
    uint8_t sigder[72];
#endif
    CTAP_credentialDescriptor * excl_cred = (CTAP_credentialDescriptor *) auth_data_buf;

    ret = ctap_parse_make_credential(&MC,encoder,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_make_credential failed\n");
        return ret;
    }
    if (MC.rp.id[0] != 0)
    {
        device_set_ui_label((const char *)MC.rp.id);
    }
    if (MC.pinAuthEmpty)
    {
        /*
         * Empty pinAuth is a platform "touch probe" for clientPin-capable keys.
         * We omit clientPin from GetInfo when no PIN is set so Chrome should not
         * send this on product builds. If it still appears, complete UV then return
         * the CTAP2 pin probe status (never map it into a full successful MC).
         */
        ret = ctap2_user_presence_test(0);
        check_retr(ret);
        return ctap_is_pin_set() == 1 ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_PIN_NOT_SET;
    }
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask)
    {
        printf2(TAG_ERR,"error, required parameter(s) for makeCredential are missing\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (ctap_is_pin_set() == 1 && MC.pinAuthPresent == 0)
    {
        printf2(TAG_ERR,"pinAuth is required\n");
        return CTAP2_ERR_PIN_REQUIRED;
    }
    else
    {
        if (ctap_is_pin_set() || (MC.pinAuthPresent))
        {
            ret = verify_pin_auth(MC.pinAuth, MC.clientDataHash);
            check_retr(ret);
        }
    }

    printf1(TAG_MC, "MC Options -> UP: %d, UV: %d, RK: %d\n", MC.up, MC.uv, MC.credInfo.rk);

    // [FIX] Removed erroneous rejection of explicit UP options. 
    // Modern browsers always send UP=true/1, and firmware should allow it.
    /*
    if (MC.up == 1 || MC.up == 0)
    {
        return CTAP2_ERR_INVALID_OPTION;
    }
    */

    // crypto_aes256_init(CRYPTO_TRANSPORT_KEY, NULL);
    for (i = 0; i < MC.excludeListSize; i++)
    {
        ret = parse_credential_descriptor(&MC.excludeList, excl_cred);
        if (ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        {
            continue;
        }
        check_retr(ret);

        printf1(TAG_GREEN, "checking credId: "); dump_hex1(TAG_GREEN, (uint8_t*) &excl_cred->credential.id, sizeof(CredentialId));

        if (ctap_authenticate_credential(&MC.rp, excl_cred))
        {
            if ( check_credential_metadata(&excl_cred->credential.id, MC.pinAuthPresent, 1) == 0)
            {
                ret = ctap2_user_presence_test(0);
                check_retr(ret);
                printf1(TAG_MC, "Cred %d failed!\r\n",i);
                return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }
        }

        ret = cbor_value_advance(&MC.excludeList);
        check_ret(ret);
    }


    CborEncoder map;
    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    {
        ret = cbor_encode_int(&map,RESP_fmt);
        check_ret(ret);
#if defined(CRYPTICK_ATTEST_FMT_NONE) && CRYPTICK_ATTEST_FMT_NONE
        ret = cbor_encode_text_stringz(&map, "none");
#else
        ret = cbor_encode_text_stringz(&map, "packed");
#endif
        check_ret(ret);
    }

    uint32_t auth_data_sz = sizeof(auth_data_buf);

    ret = ctap_make_auth_data(&MC.rp, &map, auth_data_buf, &auth_data_sz,
            &MC.credInfo, &MC.extensions);
    check_retr(ret);

    {
        unsigned int ext_encoder_buf_size = sizeof(auth_data_buf) - auth_data_sz;
        uint8_t * ext_encoder_buf = auth_data_buf + auth_data_sz;

        ret = ctap_make_extensions(&MC.extensions, ext_encoder_buf, &ext_encoder_buf_size);
        check_retr(ret);
        if (ext_encoder_buf_size)
        {
            ((CTAP_authData *)auth_data_buf)->head.flags |= (1 << 7);
            auth_data_sz += ext_encoder_buf_size;
        }
    }

    {
        ret = cbor_encode_int(&map,RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
        check_ret(ret);
    }

#if defined(CRYPTICK_ATTEST_FMT_NONE) && CRYPTICK_ATTEST_FMT_NONE
    /* Empty attStmt map — small, reliable CTAPHID multi-frame writeback. */
    {
        CborEncoder empty;
        ret = cbor_encode_int(&map, RESP_attStmt);
        check_ret(ret);
        ret = cbor_encoder_create_map(&map, &empty, 0);
        check_ret(ret);
        ret = cbor_encoder_close_container(&map, &empty);
        check_ret(ret);
    }
#else
    crypto_ecc256_load_attestation_key();
    int sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_sz, MC.clientDataHash,
                                             hashbuf, sigbuf, sigder, COSE_ALG_ES256);
    printf1(TAG_MC,"der sig [%d]: ", sigder_sz); dump_hex1(TAG_MC, sigder, sigder_sz);

    ret = ctap_add_attest_statement(&map, sigder, sigder_sz);
    check_retr(ret);
#endif

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return CTAP1_ERR_SUCCESS;
}

/*static int pick_first_authentic_credential(CTAP_getAssertion * GA)*/
/*{*/
    /*int i;*/
    /*for (i = 0; i < GA->credLen; i++)*/
    /*{*/
        /*if (GA->creds[i].credential.enc.count != 0)*/
        /*{*/
            /*return i;*/
        /*}*/
    /*}*/
    /*return -1;*/
/*}*/

static uint8_t ctap_add_credential_descriptor(CborEncoder * map, struct Credential * cred, int type)
{
    CborEncoder desc;

    int ret = cbor_encoder_create_map(map, &desc, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)&cred->id,
            get_credential_id_size(type));
        check_ret(ret);
    }

    {
        ret = cbor_encode_text_string(&desc, "type", 4);
        check_ret(ret);

        ret = cbor_encode_text_string(&desc, "public-key", 10);
        check_ret(ret);
    }


    ret = cbor_encoder_close_container(map, &desc);
    check_ret(ret);

    return 0;
}

uint8_t ctap_add_user_entity(CborEncoder * map, CTAP_userEntity * user, int is_verified)
{
    CborEncoder entity;
    int dispname = (user->name[0] != 0) && is_verified;
    int ret;
    int map_size = 1;

    if (dispname)
    {
        map_size = strlen((const char *)user->icon) > 0 ? 4 : 3;
    }
    ret = cbor_encoder_create_map(map, &entity, map_size);
    check_ret(ret);

    ret = cbor_encode_text_string(&entity, "id", 2);
    check_ret(ret);

    ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
    check_ret(ret);

    if (dispname)
    {
        if (strlen((const char *)user->icon) > 0)
        {
            ret = cbor_encode_text_string(&entity, "icon", 4);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&entity, (const char *)user->icon);
            check_ret(ret);
        }

        ret = cbor_encode_text_string(&entity, "name", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->name);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "displayName", 11);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->displayName);
        check_ret(ret);

    }

    ret = cbor_encoder_close_container(map, &entity);
    check_ret(ret);

    return 0;
}

static int cred_cmp_func(const void * _a, const void * _b)
{
    CTAP_credentialDescriptor * a = (CTAP_credentialDescriptor * )_a;
    CTAP_credentialDescriptor * b = (CTAP_credentialDescriptor * )_b;
    return b->credential.id.count - a->credential.id.count;
}

// Return 1 if existing info found, 0 otherwise
static int add_existing_user_info(CTAP_credentialDescriptor * cred)
{
    CTAP_residentKey rk;
    int index = STATE.rk_stored;
    int i;
    for (i = 0; i < index; i++)
    {
        load_nth_valid_rk(i, &rk);
        if (is_cred_id_matching_rk(&cred->credential.id, &rk))
        {
            printf1(TAG_GREEN, "found rk match for allowList item (%d)\r\n", i);
            memmove(&cred->credential.user, &rk.user, sizeof(CTAP_userEntity));
            return 1;
        }

    }
    printf1(TAG_GREEN, "NO rk match for allowList item \r\n");
    return 0;
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones last.
int ctap_filter_invalid_credentials(CTAP_getAssertion * GA)
{
    unsigned int i;
    int count = 0;
    uint8_t rpIdHash[32];
    CTAP_residentKey rk;

    for (i = 0; i < (unsigned int)GA->credLen; i++)
    {
        if (! ctap_authenticate_credential(&GA->rp, &GA->creds[i]))
        {
            printf1(TAG_GA, "CRED #%d is invalid\n", GA->creds[i].credential.id.count);
#ifdef ENABLE_U2F_EXTENSIONS
            if (is_extension_request((uint8_t*)&GA->creds[i].credential.id, sizeof(CredentialId)))
            {
                printf1(TAG_EXT, "CRED #%d is extension\n", GA->creds[i].credential.id.count);
                count++;
            }
            else
#endif
            {
                GA->creds[i].credential.id.count = 0;      // invalidate
            }

        }
        else
        {

            int protection_status =
                check_credential_metadata(&GA->creds[i].credential.id, getAssertionState.user_verified, 1);

            if (protection_status != 0) {
                printf1(TAG_GREEN,"skipping protected wrapped credential.\r\n");
                GA->creds[i].credential.id.count = 0;      // invalidate
            }
            else
            {
                count++;
                // add user info if it exists
                if ( add_existing_user_info(&GA->creds[i]) ) {
                    printf1(TAG_GREEN,"USER ID SIZE: %d\r\n", GA->creds[i].credential.user.id_size);
                    // If RK matches credential in the allow_list, we should
                    // only return one credential.
                    GA->credLen = i+1;
                    break;
                }
            }

        }
    }

    // No allowList, so use all matching RK's matching rpId
    if (!GA->credLen)
    {
        crypto_sha256_init();
        crypto_sha256_update(GA->rp.id,GA->rp.size);
        crypto_sha256_final(rpIdHash);

        printf1(TAG_GREEN, "true rpIdHash: ");  dump_hex1(TAG_GREEN, rpIdHash, 32);
        for(i = 0; i < ctap_rk_size(); i++)
        {
            ctap_load_rk(i, &rk);
            if (! ctap_rk_is_valid(&rk)) {
                continue;
            }

            printf1(TAG_GREEN, "rpIdHash%d: ", i);  dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);

            int protection_status =
                check_credential_metadata(&rk.id, getAssertionState.user_verified, 0);

            if (protection_status != 0) {
                printf1(TAG_GREEN,"skipping protected rk credential.\r\n");
                continue;
            }

            if (memcmp(rk.id.rpIdHash, rpIdHash, 32) == 0)
            {
                printf1(TAG_GA, "RK %d is a rpId match!\r\n", i);
                if (count >= ALLOW_LIST_MAX_SIZE)
                {
                    printf2(TAG_ERR, "not enough ram allocated for matching RK's (%d).  Skipping.\r\n", count);
                    break;
                }
                GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;
                memmove(&(GA->creds[count].credential), &rk, sizeof(struct Credential));
                count++;
            }
        }
        GA->credLen = count;
    }

    printf1(TAG_GA, "qsort length: %d\n", GA->credLen);
    qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor), cred_cmp_func);
    return count;
}


static int8_t save_credential_list( uint8_t * clientDataHash,
                                    CTAP_credentialDescriptor * creds,
                                    uint32_t count,
                                    CTAP_extensions * extensions)
{
    if(count)
    {
        if (count > ALLOW_LIST_MAX_SIZE-1)
        {
            printf2(TAG_ERR, "ALLOW_LIST_MAX_SIZE Exceeded\n");
            return CTAP2_ERR_TOO_MANY_ELEMENTS;
        }

        memmove(getAssertionState.clientDataHash, clientDataHash, CLIENT_DATA_HASH_SIZE);
        memmove(getAssertionState.creds, creds, sizeof(CTAP_credentialDescriptor) * (count));
        memmove(&getAssertionState.extensions, extensions, sizeof(CTAP_extensions));

    }
    getAssertionState.count = count;
    getAssertionState.index = 0;
    printf1(TAG_GA,"saved %d credentials\n",count);
    return 0;
}

static CTAP_credentialDescriptor * pop_credential()
{
    if (getAssertionState.count > 0 && getAssertionState.index < getAssertionState.count)
    {
        return &getAssertionState.creds[getAssertionState.index++];
    }
    else
    {
        return NULL;
    }
}

// adds 2 to map, or 3 if add_user is true
uint8_t ctap_end_get_assertion(CborEncoder * map, CTAP_credentialDescriptor * cred, uint8_t * auth_data_buf, unsigned int auth_data_buf_sz, uint8_t * clientDataHash)
{
    int ret;
    uint8_t sigbuf[64];
    uint8_t sigder[72];
    int sigder_sz;

    ret = cbor_encode_int(map, RESP_credential);
    check_ret(ret);

    ret = ctap_add_credential_descriptor(map, &cred->credential, cred->type);  // 1
    check_retr(ret);

    {
        ret = cbor_encode_int(map,RESP_authData);  // 2
        check_ret(ret);
        ret = cbor_encode_byte_string(map, auth_data_buf, auth_data_buf_sz);
        check_ret(ret);
    }

    unsigned int cred_size = get_credential_id_size(cred->type);
    int32_t cose_alg = read_cose_alg_from_masked_credential(&cred->credential.id);
    if (cose_alg == COSE_ALG_EDDSA)
    {
        crypto_ed25519_load_key((uint8_t*)&cred->credential.id, cred_size);
    }
    else
    {
        crypto_ecc256_load_key((uint8_t*)&cred->credential.id, cred_size, NULL, 0);
    }

    uint8_t hashbuf[32];
#ifdef ENABLE_U2F_EXTENSIONS
    if ( extend_fido2(&cred->credential.id, sigder) )
    {
        sigder_sz = 72;
    }
    else
#endif
    {
        sigder_sz = ctap_calculate_signature(auth_data_buf, auth_data_buf_sz, clientDataHash, hashbuf, sigbuf, sigder, cose_alg);
    }

    printf1(TAG_GREEN, "sigder_sz = %d\n", sigder_sz);

    {
        ret = cbor_encode_int(map, RESP_signature);  // 3
        check_ret(ret);
        ret = cbor_encode_byte_string(map, sigder, sigder_sz);
        check_ret(ret);
    }

    if (cred->credential.user.id_size)
    {
        printf1(TAG_GREEN, "adding user details to output\r\n");

        int ret = cbor_encode_int(map, RESP_publicKeyCredentialUserEntity);
        check_ret(ret);

        ret = ctap_add_user_entity(map, &cred->credential.user, getAssertionState.user_verified);  // 4
        check_retr(ret);
    }


    return 0;
}

uint8_t ctap_get_next_assertion(CborEncoder * encoder)
{
    int ret;
    CborEncoder map;

    CTAP_credentialDescriptor * cred = pop_credential();

    if (cred == NULL)
    {
        return CTAP2_ERR_NOT_ALLOWED;
    }

    auth_data_update_count(&getAssertionState.buf.authData);
    memmove(getAssertionState.buf.authData.rpIdHash, cred->credential.id.rpIdHash, 32);

    if (cred->credential.user.id_size)
    {
        printf1(TAG_GREEN, "adding user info to assertion response\r\n");
        ret = cbor_encoder_create_map(encoder, &map, 4);
    }
    else
    {
        printf1(TAG_GREEN, "NOT adding user info to assertion response\r\n");
        ret = cbor_encoder_create_map(encoder, &map, 3);
    }

    check_ret(ret);

    // if only one account for this RP, null out the user details
    if (!getAssertionState.user_verified)
    {
        printf1(TAG_GREEN, "Not verified, nulling out user details on response\r\n");
        memset(cred->credential.user.name, 0, USER_NAME_LIMIT);
    }

    unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);
    ret = ctap_make_extensions(&getAssertionState.extensions, getAssertionState.buf.extensions, &ext_encoder_buf_size);

    if (ret == 0)
    {
        if (ext_encoder_buf_size)
        {
            getAssertionState.buf.authData.flags |= (1 << 7);
        } else {
            getAssertionState.buf.authData.flags &= ~(1 << 7);
        }
    }

    ret = ctap_end_get_assertion(&map, cred,
                                (uint8_t *)&getAssertionState.buf.authData,
                                sizeof(CTAP_authDataHeader) + ext_encoder_buf_size,
                                getAssertionState.clientDataHash);

    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return 0;
}

uint8_t ctap_cred_metadata(CborEncoder * encoder)
{
    CborEncoder map;
    int ret = cbor_encoder_create_map(encoder, &map, 2);
    check_ret(ret);
    ret = cbor_encode_int(&map, 1);
    check_ret(ret);
    ret = cbor_encode_int(&map, STATE.rk_stored);
    check_ret(ret);
    ret = cbor_encode_int(&map, 2);
    check_ret(ret);
    int remaining_rks = ctap_rk_size() - STATE.rk_stored;
    ret = cbor_encode_int(&map, remaining_rks);
    check_ret(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_rp(CborEncoder * encoder, int rk_ind, int rp_count)
{
    CTAP_residentKey rk;
    ctap_load_rk(rk_ind, &rk);

    CborEncoder map;
    size_t map_size = rp_count > 0 ? 3 : 2;
    int ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);
    ret = cbor_encode_int(&map, 3);
    check_ret(ret);
    {
        CborEncoder rp;
        ret = cbor_encoder_create_map(&map, &rp, 2);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, "id");
        check_ret(ret);
        if (rk.rpIdSize <= sizeof(rk.rpId))
        {
            ret = cbor_encode_text_string(&rp, (const char *)rk.rpId, rk.rpIdSize);
        }
        else
        {
            ret = cbor_encode_text_string(&rp, "", 0);
        }
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, "name");
        check_ret(ret);
        ret = cbor_encode_text_stringz(&rp, (const char *)rk.user.name);
        check_ret(ret);
        ret = cbor_encoder_close_container(&map, &rp);
        check_ret(ret);
    }
    ret = cbor_encode_int(&map, 4);
    check_ret(ret);
    cbor_encode_byte_string(&map, rk.id.rpIdHash, 32);
    check_ret(ret);
    if (rp_count > 0)
    {
        ret = cbor_encode_int(&map, 5);
        check_ret(ret);
        ret = cbor_encode_int(&map, rp_count);
        check_ret(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_rk(CborEncoder * encoder, int rk_ind, int rk_count)
{
    CTAP_residentKey rk;
    ctap_load_rk(rk_ind, &rk);

    uint32_t cred_protect = read_metadata_from_masked_credential(&rk.id);
    if ( cred_protect == 0 || cred_protect > 3 )
    {
        // Take default value of userVerificationOptional
        cred_protect = EXT_CRED_PROTECT_OPTIONAL;
    }

    int32_t cose_alg = read_cose_alg_from_masked_credential(&rk.id);

    CborEncoder map;
    size_t map_size = rk_count > 0 ? 5 : 4;
    int ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

    ret = cbor_encode_int(&map, 6);
    check_ret(ret);
    {
        ret = ctap_add_user_entity(&map, &rk.user, 1);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 7);
    check_ret(ret);
    {
        ret = ctap_add_credential_descriptor(&map, (struct Credential*)&rk, PUB_KEY_CRED_PUB_KEY);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 8);
    check_ret(ret);
    {
        ctap_generate_cose_key(&map, (uint8_t*)&rk.id, sizeof(CredentialId), PUB_KEY_CRED_PUB_KEY, cose_alg);
    }

    if (rk_count > 0)
    {
        ret = cbor_encode_int(&map, 9);
        check_ret(ret);
        ret = cbor_encode_int(&map, rk_count);
        check_ret(ret);
    }

    ret = cbor_encode_int(&map, 0x0A);
    check_ret(ret);
    ret = cbor_encode_int(&map, cred_protect);
    check_ret(ret);

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);
    return 0;
}

uint8_t ctap_cred_mgmt_pinauth(CTAP_credMgmt *CM)
{
    if (CM->cmd != CM_cmdMetadata &&
        CM->cmd != CM_cmdRPBegin &&
        CM->cmd != CM_cmdRKBegin &&
        CM->cmd != CM_cmdRKDelete)
    {
        // pinAuth is not required for other commands
        return 0;
    }

    int8_t ret = verify_pin_auth_ex(CM->pinAuth, (uint8_t*)&CM->hashed, CM->subCommandParamsCborSize + 1);

    if (ret == CTAP2_ERR_PIN_AUTH_INVALID)
    {
        ctap_decrement_pin_attempts();
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    else
    {
        ctap_reset_pin_attempts();
    }

    return ret;
}

static int credentialId_to_rk_index(CredentialId * credId){
    unsigned int i;
    CTAP_residentKey rk;

    for (i = 0; i < ctap_rk_size(); i++)
    {
        ctap_load_rk(i, &rk);
        if ( ctap_rk_is_valid(&rk) ) {
            if (memcmp(&rk.id, credId, sizeof(CredentialId)) == 0)
            {
                return i;
            }
        }
    }

    return -1;
}

// Load the next valid resident key of a different rpIdHash
static int scan_for_next_rp(int index){
    CTAP_residentKey rk;
    uint8_t nextRpIdHash[32];

    if (index == -1)
    {
        ctap_load_rk(0, &rk);
        if (ctap_rk_is_valid(&rk))
        {
            return 0;
        }
        else
        {
            index = 0;
        }
    }

    int occurs_previously;
    do {
        occurs_previously = 0;

        index++;
        if ((unsigned int)index >= ctap_rk_size())
        {
            return -1;
        }

        ctap_load_rk(index, &rk);
        memmove(nextRpIdHash, rk.id.rpIdHash, 32);

        if (!ctap_rk_is_valid(&rk))
        {
            occurs_previously = 1;
            continue;
        } else {
        }

        // Check if we have scanned the rpIdHash before.
        int i;
        for (i = 0; i < index; i++)
        {
            ctap_load_rk(i, &rk);
            if (memcmp(rk.id.rpIdHash, nextRpIdHash, 32) == 0)
            {
                occurs_previously = 1;
                break;
            }
        }

    } while (occurs_previously);

    return index;
}

// Load the next valid resident key of the same rpIdHash
static int scan_for_next_rk(int index, uint8_t * initialRpIdHash){
    CTAP_residentKey rk;
    uint8_t lastRpIdHash[32];

    if (initialRpIdHash != NULL) {
        memmove(lastRpIdHash, initialRpIdHash, 32);
        index = -1;
    }
    else
    {
        ctap_load_rk(index, &rk);
        memmove(lastRpIdHash, rk.id.rpIdHash, 32);
    }

    do
    {
        index++;
        if ((unsigned int)index >= ctap_rk_size())
        {
            return -1;
        }
        ctap_load_rk(index, &rk);
    }
    while ( memcmp( rk.id.rpIdHash, lastRpIdHash, 32 ) != 0 );

    return index;
}



uint8_t ctap_cred_mgmt(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_credMgmt CM;
    int i = 0;

    // RP / RK pointers
    static int curr_rp_ind = 0;
    static int curr_rk_ind = 0;

    // flags that authenticate whether *Begin was before *Next
    static bool rp_auth = false;
    static bool rk_auth = false;

    int rp_count = 0;
    int rk_count = 0;

    int ret = ctap_parse_cred_mgmt(&CM, request, length);
    if (ret != 0)
    {
        printf2(TAG_ERR,"error, ctap_parse_cred_mgmt failed\n");
        return ret;
    }
    ret = ctap_cred_mgmt_pinauth(&CM);
    check_retr(ret);
    if (STATE.rk_stored == 0 && CM.cmd != CM_cmdMetadata)
    {
        printf2(TAG_ERR,"No resident keys\n");
        return 0;
    }
    if (CM.cmd == CM_cmdRPBegin)
    {
        curr_rk_ind = -1;
        rp_auth = true;
        rk_auth = false;
        curr_rp_ind = scan_for_next_rp(-1);

        // Count total unique RP's
        while (curr_rp_ind >= 0)
        {
            curr_rp_ind = scan_for_next_rp(curr_rp_ind);
            rp_count++;
        }

        // Reset scan
        curr_rp_ind = scan_for_next_rp(-1);

        printf1(TAG_MC, "RP Begin @%d.  %d total.\n", curr_rp_ind, rp_count);
    }
    else if (CM.cmd == CM_cmdRKBegin)
    {
        curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
        rk_auth = true;

        // Count total RK's associated to RP
        while (curr_rk_ind >= 0)
        {
            curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);
            rk_count++;
        }

        // Reset scan
        curr_rk_ind = scan_for_next_rk(0, CM.subCommandParams.rpIdHash);
        printf1(TAG_MC, "Cred Begin @%d.  %d total.\n", curr_rk_ind, rk_count);
    }
    else if (CM.cmd != CM_cmdRKNext && CM.cmd != CM_cmdRPNext)
    {
        rk_auth = false;
        rp_auth = false;
        curr_rk_ind = -1;
        curr_rp_ind = -1;
    }

    switch (CM.cmd)
    {
        case CM_cmdMetadata:
            printf1(TAG_CM, "CM_cmdMetadata\n");
            ret = ctap_cred_metadata(encoder);
            check_ret(ret);
            break;
        case CM_cmdRPBegin:
        case CM_cmdRPNext:
            printf1(TAG_CM, "Get RP %d\n", curr_rp_ind);
            if (curr_rp_ind < 0 || !rp_auth) {
                rp_auth = false;
                rk_auth = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ret = ctap_cred_rp(encoder, curr_rp_ind, rp_count);
            check_ret(ret);
            curr_rp_ind = scan_for_next_rp(curr_rp_ind);

            break;
        case CM_cmdRKBegin:
        case CM_cmdRKNext:
            printf1(TAG_CM, "Get Cred %d\n", curr_rk_ind);
            if (curr_rk_ind < 0 || !rk_auth) {
                rp_auth = false;
                rk_auth = false;
                return CTAP2_ERR_NO_CREDENTIALS;
            }

            ret = ctap_cred_rk(encoder, curr_rk_ind, rk_count);
            check_ret(ret);

            curr_rk_ind = scan_for_next_rk(curr_rk_ind, NULL);

            break;
        case CM_cmdRKDelete:
            printf1(TAG_CM, "CM_cmdRKDelete\n");
            i = credentialId_to_rk_index(&CM.subCommandParams.credentialDescriptor.credential.id);
            if (i >= 0) {
                ctap_delete_rk(i);
                ctap_decrement_rk_store();
                printf1(TAG_CM, "Deleted rk %d\n", i);
            } else {
                printf1(TAG_CM, "No Rk by given credId\n");
                return CTAP2_ERR_NO_CREDENTIALS;
            }
            break;
        default:
            printf2(TAG_ERR, "error, invalid credMgmt cmd: 0x%02x\n", CM.cmd);
            return CTAP1_ERR_INVALID_COMMAND;
    }
    return 0;
}

uint8_t ctap_get_assertion(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_getAssertion GA;

    int ret = ctap_parse_get_assertion(&GA,request,length);

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_get_assertion failed\n");
        return ret;
    }
    if (GA.rp.id[0] != 0)
    {
        device_set_ui_label((const char *)GA.rp.id);
    }

    if (GA.pinAuthEmpty)
    {
        ret = ctap2_user_presence_test(0);
        check_retr(ret);
        return ctap_is_pin_set() == 1 ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_PIN_NOT_SET;
    }
    if (GA.pinAuthPresent)
    {
        ret = verify_pin_auth(GA.pinAuth, GA.clientDataHash);
        check_retr(ret);
        getAssertionState.user_verified = 1;
    }
    else
    {
        getAssertionState.user_verified = 0;
    }

    if (!GA.rp.size || !GA.clientDataHashPresent)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CborEncoder map;

    int map_size = 3;

    printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
    int validCredCount = ctap_filter_invalid_credentials(&GA);

    if (validCredCount == 0)
    {
        printf2(TAG_ERR,"Error, no authentic credential\n");
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    else if (validCredCount > 1)
    {
       map_size += 1;
    }

    printf1(TAG_GREEN,"2 USER ID SIZE: %d\r\n", GA.creds[0].credential.user.id_size);

    if (GA.creds[validCredCount - 1].credential.user.id_size)
    {
        map_size += 1;
    }
    if (GA.extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        printf1(TAG_GA, "hmac-secret is present\r\n");
    }

    ret = cbor_encoder_create_map(encoder, &map, map_size);
    check_ret(ret);

    // if only one account for this RP, null out the user details
    if (validCredCount < 2 || !getAssertionState.user_verified)
    {
        printf1(TAG_GREEN, "Only one account, nulling out user details on response\r\n");
        memset(&GA.creds[0].credential.user.name, 0, USER_NAME_LIMIT);
    }

    printf1(TAG_GA,"resulting order of creds:\n");
    int j;
    for (j = 0; j < GA.credLen; j++)
    {
        printf1(TAG_GA,"CRED ID (# %d)\n", GA.creds[j].credential.id.count);
    }

    CTAP_credentialDescriptor * cred = &GA.creds[0];

    GA.extensions.hmac_secret.credential = &cred->credential;

    uint32_t auth_data_buf_sz = sizeof(CTAP_authDataHeader);

#ifdef ENABLE_U2F_EXTENSIONS
    if ( is_extension_request((uint8_t*)&GA.creds[0].credential.id, sizeof(CredentialId)) )
    {
        crypto_sha256_init();
        crypto_sha256_update(GA.rp.id, GA.rp.size);
        crypto_sha256_final(getAssertionState.buf.authData.rpIdHash);

        getAssertionState.buf.authData.flags = (1 << 0);
        getAssertionState.buf.authData.flags |= (1 << 2);
    }
    else
#endif
    {
        device_disable_up(GA.up == 0);
        ret = ctap_make_auth_data(&GA.rp, &map, (uint8_t*)&getAssertionState.buf.authData, &auth_data_buf_sz, NULL, &GA.extensions);
        device_disable_up(false);
        check_retr(ret);

        /* UP via fingerprint counts as product UV even without clientPin. */
        if (getAssertionState.buf.authData.flags & 0x01)
            getAssertionState.user_verified = 1;
        getAssertionState.buf.authData.flags &= ~(1 << 2);
        getAssertionState.buf.authData.flags |= (getAssertionState.user_verified << 2);

        {
            unsigned int ext_encoder_buf_size = sizeof(getAssertionState.buf.extensions);

            ret = ctap_make_extensions(&GA.extensions, getAssertionState.buf.extensions, &ext_encoder_buf_size);
            check_retr(ret);
            if (ext_encoder_buf_size)
            {
                getAssertionState.buf.authData.flags |= (1 << 7);
                auth_data_buf_sz += ext_encoder_buf_size;
            }
        }

    }

    ret = ctap_end_get_assertion(&map, cred, (uint8_t*)&getAssertionState.buf, auth_data_buf_sz, GA.clientDataHash);  // 1,2,3,4
    check_retr(ret);

    if (validCredCount > 1)
    {
        ret = cbor_encode_int(&map, RESP_numberOfCredentials);  // 5
        check_ret(ret);
        ret = cbor_encode_int(&map, validCredCount);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    ret = save_credential_list( GA.clientDataHash,
                                GA.creds + 1 /* skip first credential*/,
                                validCredCount - 1,
                                &GA.extensions);
    check_retr(ret);

    return 0;
}

// Return how many trailing zeros in a buffer
static int trailing_zeros(uint8_t * buf, int indx)
{
    int c = 0;
    while(0==buf[indx] && indx)
    {
        indx--;
        c++;
    }
    return c;
}

uint8_t ctap_update_pin_if_verified(uint8_t * pinEnc, int len, uint8_t * platform_pubkey, uint8_t * pinAuth, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    int ret;

//    Validate incoming data packet len
    if (len < 64)
    {
        return CTAP1_ERR_OTHER;
    }

//    Validate device's state
    if (ctap_is_pin_set())  // Check first, prevent SCA
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
    }

//    calculate shared_secret
    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_sha256_hmac_init(shared_secret, 32, hmac);
    crypto_sha256_hmac_update(pinEnc, len);
    if (pinHashEnc != NULL)
    {
        crypto_sha256_hmac_update(pinHashEnc, 16);
    }
    crypto_sha256_hmac_final(shared_secret, 32, hmac);

    if (memcmp(hmac, pinAuth, 16) != 0)
    {
        printf2(TAG_ERR,"pinAuth failed for update pin\n");
        dump_hex1(TAG_ERR, hmac,16);
        dump_hex1(TAG_ERR, pinAuth,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

//     decrypt new PIN with shared secret
    crypto_aes256_init(shared_secret, NULL);

    while((len & 0xf) != 0) // round up to nearest  AES block size multiple
    {
        len++;
    }

    crypto_aes256_decrypt(pinEnc, len);

//      validate new PIN (length)

    ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
    ret = NEW_PIN_ENC_MIN_SIZE  - ret;

    if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE)
    {
        printf2(TAG_ERR,"new PIN is too short or too long [%d bytes]\n", ret);
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    else
    {
        printf1(TAG_CP,"new pin set [len %d]\n", ret);
    }

//    validate device's state, decrypt and compare pinHashEnc (user provided current PIN hash) with stored PIN_CODE_HASH

    if (ctap_is_pin_set())
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        crypto_aes256_reset_iv(NULL);
        crypto_aes256_decrypt(pinHashEnc, 16);

        uint8_t pinHashEncSalted[32];
        crypto_sha256_init();
        crypto_sha256_update(pinHashEnc, 16);
        crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
        crypto_sha256_final(pinHashEncSalted);

        if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 32) != 0)
        {
            ctap_reset_key_agreement();
            ctap_decrement_pin_attempts();
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
            return CTAP2_ERR_PIN_INVALID;
        }
        else
        {
            ctap_reset_pin_attempts();
        }
    }

//      set new PIN (update and store PIN_CODE_HASH)
    return ctap_update_pin(pinEnc, ret);
}

uint8_t ctap_add_pin_if_verified(uint8_t * pinTokenEnc, uint8_t * platform_pubkey, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_aes256_init(shared_secret, NULL);

    crypto_aes256_decrypt(pinHashEnc, 16);

    uint8_t pinHashEncSalted[32];
    crypto_sha256_init();
    crypto_sha256_update(pinHashEnc, 16);
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(pinHashEncSalted);
    if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 32) != 0)
    {
        printf2(TAG_ERR,"Pin does not match!\n");
        printf2(TAG_ERR,"platform-pin-hash: "); dump_hex1(TAG_ERR, pinHashEnc, 16);
        printf2(TAG_ERR,"authentic-pin-hash: "); dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
        printf2(TAG_ERR,"shared-secret: "); dump_hex1(TAG_ERR, shared_secret, 32);
        printf2(TAG_ERR,"platform-pubkey: "); dump_hex1(TAG_ERR, platform_pubkey, 64);
        printf2(TAG_ERR,"device-pubkey: "); dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);
        // Generate new keyAgreement pair
        ctap_reset_key_agreement();
        ctap_decrement_pin_attempts();
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_INVALID;
    }

    ctap_reset_pin_attempts();
    crypto_aes256_reset_iv(NULL);

    memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
    crypto_aes256_encrypt(pinTokenEnc, PIN_TOKEN_SIZE);

    return 0;
}

/*
 * UV counterpart of ctap_add_pin_if_verified(): no pinHashEnc to check (the
 * fingerprint match already happened, in the caller, via
 * ctap2_user_presence_test()) — this only derives the shared secret and
 * wraps a token under it, for CP_cmdGetPinUvAuthTokenUsingUvWithPermissions.
 *
 * Generates a brand-new PIN_TOKEN (same ctap_generate_rng() + reboot-on-
 * failure convention as ctap_init()/ctap_reset(), ctap.c ~line 2626/2842)
 * rather than re-wrapping whatever the PIN path last issued: a fresh UV
 * grant is a new token issuance, not a re-delivery of an old one. This
 * invalidates any token a prior CP_cmdGetPinToken call handed out, which is
 * correct for a single-session authenticator — there is exactly one
 * standing PIN_TOKEN, and whichever ceremony (PIN or UV) most recently
 * proved the user is the one that gets to mint it.
 *
 * verify_pin_auth_ex() / ctap_cred_mgmt_pinauth() need no changes: both
 * already just HMAC-check against whatever PIN_TOKEN currently holds.
 */
uint8_t ctap_make_uv_pin_token(uint8_t * pinTokenEnc, uint8_t * platform_pubkey)
{
    uint8_t shared_secret[32];

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        /* Cannot produce a safe authenticator state; reboot instead of exit(). */
        device_reboot();
    }

    crypto_aes256_init(shared_secret, NULL);
    crypto_aes256_reset_iv(NULL);

    memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
    crypto_aes256_encrypt(pinTokenEnc, PIN_TOKEN_SIZE);

    return 0;
}

uint8_t ctap_client_pin(CborEncoder * encoder, uint8_t * request, int length)
{
    CTAP_clientPin CP;
    CborEncoder map;
    uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
    int ret = ctap_parse_client_pin(&CP,request,length);


    switch(CP.subCommand)
    {
        case CP_cmdSetPin:
        case CP_cmdChangePin:
        case CP_cmdGetPinToken:
            if (ctap_device_locked())
            {
                return  CTAP2_ERR_PIN_BLOCKED;
            }
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
    }

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_client_pin failed\n");
        return ret;
    }

    if (CP.pinProtocol != 1 || CP.subCommand == 0)
    {
        return CTAP1_ERR_OTHER;
    }

    int num_map = (CP.getRetries ? 1 : 0);

    switch(CP.subCommand)
    {
        case CP_cmdGetRetries:
            printf1(TAG_CP,"CP_cmdGetRetries\n");
            ret = cbor_encoder_create_map(encoder, &map, 1);
            check_ret(ret);

            CP.getRetries = 1;

            break;
        case CP_cmdGetKeyAgreement:
            printf1(TAG_CP,"CP_cmdGetKeyAgreement\n");
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            ret = cbor_encode_int(&map, RESP_keyAgreement);
            check_ret(ret);

            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ecc256_compute_public_key(KEY_AGREEMENT_PRIV, KEY_AGREEMENT_PUB);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);

            ret = ctap_add_cose_key(&map, KEY_AGREEMENT_PUB, KEY_AGREEMENT_PUB+32, PUB_KEY_CRED_PUB_KEY, COSE_ALG_ECDH_ES_HKDF_256);
            check_retr(ret);

            break;
        case CP_cmdSetPin:
            printf1(TAG_CP,"CP_cmdSetPin\n");

            if (ctap_is_pin_set())
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }
            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, NULL);
            check_retr(ret);
            break;
        case CP_cmdChangePin:
            printf1(TAG_CP,"CP_cmdChangePin\n");

            if (! ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }

            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent || !CP.pinHashEncPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, CP.pinHashEnc);
            check_retr(ret);
            break;
        case CP_cmdGetPinToken:
            if (!ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            printf1(TAG_CP,"CP_cmdGetPinToken\n");
            if (CP.keyAgreementPresent == 0 || CP.pinHashEncPresent == 0)
            {
                printf2(TAG_ERR,"Error, missing keyAgreement or pinHashEnc for cmdGetPin\n");
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            ret = cbor_encode_int(&map, RESP_pinToken);
            check_ret(ret);

            /*ret = ctap_add_pin_if_verified(&map, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);*/
            ret = ctap_add_pin_if_verified(pinTokenEnc, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);
            check_retr(ret);

            ret = cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
            check_ret(ret);



            break;

        case CP_cmdGetPinUvAuthTokenUsingUvWithPermissions:
            /*
             * CTAP2.1 §6.5.5 / §6.5.5.7.2: the actual spec mechanism for
             * obtaining a pinUvAuthToken via built-in UV instead of a PIN.
             * This is the fix that lets credential management
             * (ctap_cred_mgmt_pinauth(), which only ever checks whatever is
             * in PIN_TOKEN via verify_pin_auth_ex()) be gated by the
             * fingerprint sensor instead of requiring a PIN flow — no
             * change needed to either of those, by design.
             */
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            printf1(TAG_CP,"CP_cmdGetPinUvAuthTokenUsingUvWithPermissions\n");
            if (CP.keyAgreementPresent == 0 || CP.permissionsPresent == 0)
            {
                printf2(TAG_ERR,"Error, missing keyAgreement or permissions for cmdGetPinUvAuthTokenUsingUvWithPermissions\n");
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            if (CP.permissions == 0)
            {
                /* §6.5.5.7.2: a platform must ask for at least one specific
                 * permission — zero is not "no restriction", it is invalid. */
                printf2(TAG_ERR,"Error, permissions == 0\n");
                return CTAP1_ERR_INVALID_PARAMETER;
            }

            /*
             * Real, fresh fingerprint match — not the cached GetTouch
             * credit. allow_uv_cache must be 0 here: per device.h's own
             * doc comment, that cache is a one-shot MakeCredential-only
             * credit for a Chrome U2F quirk (ctap_uv_cache_arm_gettouch()),
             * consumed by ctap_user_presence_test_ex() when the *caller*
             * passes allow_uv_cache=1 — nothing else may opt into it. If
             * this call opted in, a touch meant for an entirely unrelated
             * MakeCredential moments earlier could silently authorize
             * listing/deleting resident credentials, exactly the
             * cross-ceremony double-count hazard that comment warns about.
             * ctap2_user_presence_test(0) is this file's own existing
             * UP/UV-test-to-CTAP-status helper (used by CTAP_RESET above)
             * — it already converts ctap_user_presence_test_ex()'s raw
             * 1/0/-1 into CTAP1_ERR_SUCCESS / CTAP2_ERR_ACTION_TIMEOUT /
             * CTAP2_ERR_KEEPALIVE_CANCEL, so this introduces no new
             * timeout/cancel error convention.
             */
            ret = ctap2_user_presence_test(0);
            if (ret != CTAP1_ERR_SUCCESS)
            {
                return ret;
            }

            ret = cbor_encode_int(&map, RESP_pinToken);
            check_ret(ret);

            ret = ctap_make_uv_pin_token(pinTokenEnc, (uint8_t*)&CP.keyAgreement.pubkey);
            check_retr(ret);

            ret = cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
            check_ret(ret);

            break;

        default:
            printf2(TAG_ERR,"Error, invalid client pin subcommand\n");
            return CTAP1_ERR_OTHER;
    }

    if (CP.getRetries)
    {
        ret = cbor_encode_int(&map, RESP_retries);
        check_ret(ret);
        ret = cbor_encode_int(&map, ctap_leftover_pin_attempts());
        check_ret(ret);
    }

    if (num_map || CP.getRetries)
    {
        ret = cbor_encoder_close_container(encoder, &map);
        check_ret(ret);
    }

    return 0;
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
    memset(resp, 0, sizeof(CTAP_RESPONSE));
    resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}


uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));
    uint8_t status = 0;
    uint8_t cmd = *pkt_raw;
    pkt_raw++;
    length--;

    uint8_t * buf = resp->data;

    cbor_encoder_init(&encoder, buf, resp->data_size, 0);

    printf1(TAG_CTAP,"[CTAP] RX Command: 0x%02X | payload: %d bytes\n", cmd, length);

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
        case CTAP_GET_ASSERTION:
        case CTAP_CBOR_CRED_MGMT:
        case CTAP_CBOR_CRED_MGMT_PRE:
            if (ctap_device_locked())
            {
                status = CTAP2_ERR_PIN_BLOCKED;
                goto done;
            }
            if (ctap_device_boot_locked())
            {
                status = CTAP2_ERR_PIN_AUTH_BLOCKED;
                goto done;
            }
            break;
    }

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            solo_timestamp();
            status = ctap_make_credential(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"make_credential time: %d ms\n", solo_timestamp());

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, resp->length);

            break;
        case CTAP_GET_ASSERTION:
            printf1(TAG_CTAP,"CTAP_GET_ASSERTION\n");
            solo_timestamp();
            status = ctap_get_assertion(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"get_assertion time: %d ms\n", solo_timestamp());

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            printf1(TAG_DUMP,"cbor [%d]: \n",  resp->length);
                dump_hex1(TAG_DUMP,buf, resp->length);
            break;
        case CTAP_CANCEL:
            printf1(TAG_CTAP,"CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf1(TAG_CTAP,"[CTAP] GET_INFO\n");
            /* Probe only — never drive Place-finger / Working / success UI. */
            status = ctap_get_info(&encoder);
            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            break;

        case CTAP_CLIENT_PIN:
            printf1(TAG_CTAP,"[CTAP] CLIENT_PIN\n");
            /* PIN probes (getRetries / getKeyAgreement) are not a ceremony. */
            status = ctap_client_pin(&encoder, pkt_raw, length);
            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
            break;
        case CTAP_RESET:
            printf1(TAG_CTAP,"CTAP_RESET\n");
            status = ctap2_user_presence_test(0);
            if (status == CTAP1_ERR_SUCCESS)
            {
                ctap_reset();
            }
            break;
        case GET_NEXT_ASSERTION:
            printf1(TAG_CTAP,"CTAP_NEXT_ASSERTION\n");
            if (getAssertionState.lastcmd == CTAP_GET_ASSERTION)
            {
                status = ctap_get_next_assertion(&encoder);
                resp->length = cbor_encoder_get_buffer_size(&encoder, buf);
                dump_hex1(TAG_DUMP, buf, resp->length);
                if (status == 0)
                {
                    cmd = CTAP_GET_ASSERTION;       // allow for next assertion
                }
            }
            else
            {
                printf2(TAG_ERR, "unwanted GET_NEXT_ASSERTION.  lastcmd == 0x%02x\n", getAssertionState.lastcmd);
                status = CTAP2_ERR_NOT_ALLOWED;
            }
            break;
        case CTAP_CBOR_CRED_MGMT:
        case CTAP_CBOR_CRED_MGMT_PRE:
            printf1(TAG_CTAP,"CTAP_CBOR_CRED_MGMT_PRE\n");
            status = ctap_cred_mgmt(&encoder, pkt_raw, length);

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            dump_hex1(TAG_DUMP,buf, resp->length);
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd: 0x%02x\n", cmd);
    }

done:
    getAssertionState.lastcmd = cmd;

    /*
     * Do NOT set IDLE here — CTAPHID still must stream the multi-frame reply.
     * ctaphid_handle_packet sets IDLE after ctaphid_write completes so the
     * browser is not left waiting with an incomplete CBOR body while OLED OK.
     */

    if (status != CTAP1_ERR_SUCCESS)
    {
        resp->length = 0;
    }

    printf1(TAG_CTAP,"[CTAP] Command Done. Status: 0x%02x | Data: %d bytes\n", status, resp->length);

    return status;
}



static void ctap_state_init()
{
    // Set to 0xff instead of 0x00 to be easier on flash
    memset(&STATE, 0xff, sizeof(AuthenticatorState));
    // Fresh RNG for key
    ctap_generate_rng(STATE.key_space, KEY_SPACE_BYTES);

    STATE.is_initialized = INITIALIZED_MARKER;
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    STATE.is_pin_set = 0;
    STATE.rk_stored = 0;
    STATE.data_version = STATE_VERSION;

    ctap_reset_rk();

    if (ctap_generate_rng(STATE.PIN_SALT, sizeof(STATE.PIN_SALT)) != 1) {
        printf2(TAG_ERR, "Error, rng failed\n");
        /* Cannot produce a safe authenticator state; reboot instead of exit(). */
        device_reboot();
    }

    printf1(TAG_STOR, "Generated PIN SALT: ");
    dump_hex1(TAG_STOR, STATE.PIN_SALT, sizeof STATE.PIN_SALT);
}

/** Overwrite master secret from external source.
 * @param keybytes an array of KEY_SPACE_BYTES length.
 *
 * This function should only be called from a privilege mode.
*/
void ctap_load_external_keys(uint8_t * keybytes){
    memmove(STATE.key_space, keybytes, KEY_SPACE_BYTES);
    authenticator_write_state(&STATE);
    crypto_load_master_secret(STATE.key_space);
}

#include "version.h"
void ctap_init()
{
    printf1(TAG_ERR,"Current firmware version address: %p\r\n", &firmware_version);
    printf1(TAG_ERR,"Current firmware version: %d.%d.%d.%d (%02x.%02x.%02x.%02x)\r\n",
            firmware_version.major, firmware_version.minor, firmware_version.patch, firmware_version.reserved,
            firmware_version.major, firmware_version.minor, firmware_version.patch, firmware_version.reserved
            );
    crypto_ecc256_init();

    int is_init = authenticator_read_state(&STATE);
    
    device_set_status(CTAPHID_STATUS_IDLE);

    if (is_init)
    {
        printf1(TAG_STOR, "[FIDO] Auth Loaded | Tries: %d\n", STATE.remaining_tries);
    }
    else
    {
        printf1(TAG_STOR, "[FIDO] Fresh Init.\n");
        ctap_state_init();
    }

    // Failsafe is no longer needed with standard SoloKeys logic.

    do_migration_if_required(&STATE);

    crypto_load_master_secret(STATE.key_space);

    if (ctap_is_pin_set())
    {
        printf1(TAG_STOR,"pin is set.\n");
    }
    else
    {
        printf1(TAG_STOR,"pin not set.\n");
    }

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        /* Cannot produce a safe authenticator state; reboot instead of exit(). */
        device_reboot();
    }

    ctap_reset_key_agreement();

#ifdef BRIDGE_TO_WALLET
    wallet_init();
#endif


}

uint8_t ctap_is_pin_set()
{
    return STATE.is_pin_set == 1;
}

/**
 * Set new PIN, by updating PIN hash. Save state.
 * Globals: STATE
 * @param pin new PIN (raw)
 * @param len pin array length
 * @return 0 on success, CTAP2_ERR_PIN_POLICY_VIOLATION on a bad length
 *
 * Callers already range-check the length, so this is a backstop. It must not
 * abort the process: on a token, that is a host-triggerable reset rather than
 * a rejected request.
 */
uint8_t ctap_update_pin(uint8_t * pin, int len)
{
    if (len >= NEW_PIN_ENC_MIN_SIZE || len < NEW_PIN_MIN_SIZE)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

    crypto_sha256_init();
    crypto_sha256_update(pin, len);
    uint8_t intermediateHash[32];
    crypto_sha256_final(intermediateHash);

    crypto_sha256_init();
    crypto_sha256_update(intermediateHash, 16);
    memset(intermediateHash, 0, sizeof(intermediateHash));
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(STATE.PIN_CODE_HASH);

    STATE.is_pin_set = 1;

    authenticator_write_state(&STATE);

    printf1(TAG_CTAP, "New pin hash set.\n");
    return 0;
}

uint8_t ctap_decrement_pin_attempts()
{
    if (PIN_BOOT_ATTEMPTS_LEFT > 0)
    {
        PIN_BOOT_ATTEMPTS_LEFT--;
    }
    if (! ctap_device_locked())
    {
        STATE.remaining_tries--;
        ctap_flush_state();
        printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);
    }
    else
    {
        printf1(TAG_CP, "Device locked!\n");
        return -1;
    }
    return 0;
}

void ctap_reset_pin_attempts()
{
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
    ctap_flush_state();
}

int8_t ctap_device_locked()
{
    return STATE.remaining_tries <= 0;
}

int8_t ctap_device_boot_locked()
{
    return PIN_BOOT_ATTEMPTS_LEFT <= 0;
}

int8_t ctap_leftover_pin_attempts()
{
    return STATE.remaining_tries;
}

void ctap_reset_state()
{
    memset(&getAssertionState, 0, sizeof(getAssertionState));
}

uint16_t ctap_keys_stored()
{
    int total = 0;
    int i;
    for (i = 0; i < MAX_KEYS; i++)
    {
        if (STATE.key_lens[i] != 0xffff)
        {
            total += 1;
        }
        else
        {
            break;
        }
    }
    return total;
}

static uint16_t key_addr_offset(int index)
{
    uint16_t offset = 0;
    int i;
    for (i = 0; i < index; i++)
    {
        if (STATE.key_lens[i] != 0xffff) offset += STATE.key_lens[i];
    }
    return offset;
}

uint16_t ctap_key_len(uint8_t index)
{
    int i = ctap_keys_stored();
    if (index >= i || index >= MAX_KEYS)
    {
        return 0;
    }
    if (STATE.key_lens[index] == 0xffff) return 0;
    return STATE.key_lens[index];

}

int8_t ctap_store_key(uint8_t index, uint8_t * key, uint16_t len)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    if (i >= MAX_KEYS || index >= MAX_KEYS || !len)
    {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] != 0xffff)
    {
        return ERR_KEY_SPACE_TAKEN;
    }

    offset = key_addr_offset(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    STATE.key_lens[index] = len;

    memmove(STATE.key_space + offset, key, len);

    ctap_flush_state();

    return 0;
}

int8_t ctap_load_key(uint8_t index, uint8_t * key)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    uint16_t len;
    if (index >= i || index >= MAX_KEYS)
    {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] == 0xffff)
    {
        return ERR_KEY_SPACE_EMPTY;
    }

    offset = key_addr_offset(index);
    len = ctap_key_len(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    memmove(key, STATE.key_space + offset, len);

    return 0;
}

static void ctap_reset_key_agreement()
{
    ctap_generate_rng(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
}

void ctap_reset()
{
    ctap_state_init();

    authenticator_write_state(&STATE);

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        /* Cannot produce a safe authenticator state; reboot instead of exit(). */
        device_reboot();
    }

    ctap_reset_state();
    ctap_reset_key_agreement();

    crypto_load_master_secret(STATE.key_space);
}

// End of file
