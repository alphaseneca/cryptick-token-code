// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// Status codes. Source of truth: CTAP 2.1 Proposed Standard (2021-06-15)
// §8.2 "Status codes". That table is byte-for-byte identical in CTAP 2.2 PS
// (2025-07-14) §8.2, so every value below holds for both revisions.
//
// This device advertises versions ["FIDO_2_0", "U2F_V2"] (see ctap.c
// authenticatorGetInfo) and deliberately not FIDO_2_1_PRE, so codes that exist
// only in CTAP 2.0 are still legitimate for us to emit and are kept below,
// marked "CTAP2.0 only". Codes that exist in neither published table are not.
//
// Six names in the 2019 SoloKeys original were bound to values that appear in
// NEITHER the CTAP 2.0 PS (2019-01-30) §8.2 table nor the CTAP 2.1/2.2 one, and
// have been removed. Recorded here so they are not reintroduced:
//
//   0x10 CTAP2_ERR_CBOR_PARSING          -> use CTAP2_ERR_INVALID_CBOR (0x12),
//                                           "Error when parsing CBOR."
//   0x13 CTAP2_ERR_INVALID_CBOR_TYPE     -> use CTAP2_ERR_CBOR_UNEXPECTED_TYPE
//                                           (0x11), "Invalid/unexpected CBOR error."
//   0x17 CTAP2_ERR_TOO_MANY_ELEMENTS     -> use CTAP2_ERR_LIMIT_EXCEEDED (0x15),
//                                           "Limit for number of items exceeded."
//   0x18 CTAP2_ERR_EXTENSION_NOT_SUPPORTED -> no spec equivalent; unused.
//   0x20 CTAP2_ERR_CREDENTIAL_NOT_VALID  -> use CTAP2_ERR_INVALID_CREDENTIAL
//                                           (0x22), "Credential not valid for
//                                           the authenticator."
//   0x29 CTAP2_ERR_NOT_BUSY              -> no spec equivalent; unused.
//
// 0x17 and 0x18 were the dangerous two: CTAP 2.1 assigns those values to
// CTAP2_ERR_FP_DATABASE_FULL and CTAP2_ERR_LARGE_BLOB_STORAGE_FULL, so emitting
// the old names put a byte on the wire that a 2.1-aware platform reads as a
// completely different failure. They are defined below under their real names.
//
// PROJECT.md §20: verify constants against the specification, not against the
// other side's code.

#define CTAP1_ERR_SUCCESS                   0x00
#define CTAP1_ERR_INVALID_COMMAND           0x01
#define CTAP1_ERR_INVALID_PARAMETER         0x02
#define CTAP1_ERR_INVALID_LENGTH            0x03
#define CTAP1_ERR_INVALID_SEQ               0x04
#define CTAP1_ERR_TIMEOUT                   0x05
#define CTAP1_ERR_CHANNEL_BUSY              0x06
#define CTAP1_ERR_LOCK_REQUIRED             0x0A
#define CTAP1_ERR_INVALID_CHANNEL           0x0B
// 0x07-0x09, 0x0C-0x10, 0x13 unassigned in §8.2.
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11
#define CTAP2_ERR_INVALID_CBOR              0x12
#define CTAP2_ERR_MISSING_PARAMETER         0x14
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15
// CTAP2.0 only: present in CTAP 2.0 PS §8.2, removed in 2.1/2.2.
#define CTAP2_ERR_UNSUPPORTED_EXTENSION     0x16
#define CTAP2_ERR_FP_DATABASE_FULL          0x17
#define CTAP2_ERR_LARGE_BLOB_STORAGE_FULL   0x18
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19
// 0x1A-0x20 unassigned in §8.2.
#define CTAP2_ERR_PROCESSING                0x21
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22
#define CTAP2_ERR_USER_ACTION_PENDING       0x23
#define CTAP2_ERR_OPERATION_PENDING         0x24
#define CTAP2_ERR_NO_OPERATIONS             0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26
#define CTAP2_ERR_OPERATION_DENIED          0x27
#define CTAP2_ERR_KEY_STORE_FULL            0x28
// 0x29 unassigned in §8.2.
// CTAP2.0 only: present in CTAP 2.0 PS §8.2, removed in 2.1/2.2.
#define CTAP2_ERR_NO_OPERATION_PENDING      0x2A
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2B
#define CTAP2_ERR_INVALID_OPTION            0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2D
#define CTAP2_ERR_NO_CREDENTIALS            0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2F
#define CTAP2_ERR_NOT_ALLOWED               0x30
#define CTAP2_ERR_PIN_INVALID               0x31
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34
#define CTAP2_ERR_PIN_NOT_SET               0x35
// Same value in both revisions; CTAP 2.0 PS calls it CTAP2_ERR_PIN_REQUIRED,
// CTAP 2.1/2.2 §8.2 renamed it CTAP2_ERR_PUAT_REQUIRED ("A pinUvAuthToken is
// required for the selected operation"). Both names kept: we advertise FIDO_2_0.
#define CTAP2_ERR_PIN_REQUIRED              0x36
#define CTAP2_ERR_PUAT_REQUIRED             0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37
// CTAP2.0 only: CTAP 2.1/2.2 §8.2 lists 0x38 as "Reserved for Future Use".
#define CTAP2_ERR_PIN_TOKEN_EXPIRED         0x38
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39
#define CTAP2_ERR_ACTION_TIMEOUT            0x3A
// 0x3B is in CTAP 2.0 PS §8.2 as well; 0x3C-0x40 are new in CTAP 2.1.
#define CTAP2_ERR_UP_REQUIRED               0x3B
#define CTAP2_ERR_UV_BLOCKED                0x3C
#define CTAP2_ERR_INTEGRITY_FAILURE         0x3D
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3E
#define CTAP2_ERR_UV_INVALID                0x3F
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40
#define CTAP1_ERR_OTHER                     0x7F
#define CTAP2_ERR_SPEC_LAST                 0xDF
#define CTAP2_ERR_EXTENSION_FIRST           0xE0
#define CTAP2_ERR_EXTENSION_LAST            0xEF
#define CTAP2_ERR_VENDOR_FIRST              0xF0
#define CTAP2_ERR_VENDOR_LAST               0xFF
