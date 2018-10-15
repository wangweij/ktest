/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

// This library is client-side only, and only supports the default credentials.
// It only speaks krb5. SPNEGO is supported by creating its own NetTokenInit
// and parsing incoming NegTokenResp tokens. This ensures no other mechanism
// (Ex: NTLM) is chosen.
//
// This library can be built directly with the following command:
//   cl -I %OPENJDK%\src\java.security.jgss\share\native\libj2gss\ sspi.cpp
//      -link -dll -out:sspi_bridge.dll

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Strsafe.h>

#define GSS_DLL_FILE
#include <gssapi.h>

#define SECURITY_WIN32
#include <sspi.h>

#pragma comment(lib, "secur32.lib")

#define PP(fmt, ...) \
        if (trace) { \
            fprintf(stdout, "SSPI (%ld): ", __LINE__); \
            fprintf(stdout, fmt, ##__VA_ARGS__); \
            fprintf(stdout, "\n"); \
            fflush(stdout); \
        }
#define SEC_SUCCESS(Status) (*minor_status = Status, (Status) >= 0)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// When KRB5_TRACE is set, debug info goes to stdout. The value is ignored.
char* trace = getenv("KRB5_TRACE");

void
dump(LPSTR title, PBYTE data, DWORD len)
{
    if (trace) {
        printf("==== %s ====\n", title);
        for (DWORD i = 0; i < len; i++) {
            if (i != 0 && i % 16 == 0) {
                printf("\n");
            }
            printf("%02X ", *(data + i) & 0xff);
        }
        printf("\n");
    }
}

gss_OID_desc KRB5_OID = {9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};
gss_OID_desc SPNEGO_OID = {6, "\x2b\x06\x01\x05\x05\x02"};
gss_OID_desc USER_NAME_OID = {10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"};
gss_OID_desc HOST_SERVICE_NAME_OID = {10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"};
gss_OID_desc EXPORT_NAME_OID = {6, "\x2b\x06\x01\x05\x06\x04"};

// gss_name_t is Name*
typedef struct {
    SEC_WCHAR* name;
} Name;

// gss_ctx_id_t is Context*
typedef struct {
    CredHandle* phCred;
    CtxtHandle hCtxt;
    DWORD cbMaxMessage;
    SecPkgContext_Sizes SecPkgContextSizes;
    SecPkgContext_NativeNames nnames;
    BOOLEAN established;
} Context;

// gss_cred_id_t is Credential*
typedef struct {
    CredHandle* phCred;
    long time;
} Credential;

/* This section holds supporting functions that are not exported */

// Prepend ASN.1 tag+length to data.
//
// [in, out] data: the data, which already had enough allocated space before
//                 its head when called. Head moved backwards after called.
// [in, out] pLen: a counter to maintain
// [in]       len: the ASN.1 length (MUST be less than 2^16)
// [in]       tag: the ASN.1 tag
void
add_der_head(char** data, int* pLen, int len, int tag)
{
    char* pos = *data;
    int lenlen;
    if (len <= 0x7f) {
        pos[-1] = (char)len;
        lenlen = 1;
    } else if (len < 256) {
        pos[-1] = (char)len;
        pos[-2] = (char)0x81;
        lenlen = 2;
    } else {
        pos[-1] = (char)(len & 0xff);
        pos[-2] = (char)(len >> 8);
        pos[-3] = (char)0x82;
        lenlen = 3;
    }
    pos[-1-lenlen] = (char)tag;
    *pLen += 1 + lenlen;
    *data = pos - 1 - lenlen;
}

// Prepend bytes to data.
//
// [in, out] data: the data, which already had enough allocated space before
//                 its head when called. Head moved backwards after called.
// [in, out] pLen: a counter to maintain
// [in]        in: a block of bytes
// [in]       len: length of in
void
add_data(char** data, int* pLen, char* in, int len)
{
    char* pos = *data;
    memcpy_s(pos - len, len, in, len);
    *pLen += len;
    *data = pos - len;
}

// Wrap a krb5 token into NegTokenInit
// Returns 1 for success, 0 for failure
int
krb5_to_spnego(gss_buffer_t input, gss_buffer_t output)
{
    int len = (int)input->length;
    if (len > 60000) { // Too long, need 3 bytes DER length
        return 0;
    }
    // Just enough for a token with 2-bytes length
    int maxLen = len + 43;
    char* buffer = new char[maxLen];
    memcpy_s(buffer + maxLen - len, len, input->value, len);
    char* pos = buffer + maxLen - len;

    // mechToken [2] OCTET STRING  OPTIONAL,
    add_der_head(&pos, &len, len, 4);
    add_der_head(&pos, &len, len, 0xA2);
    // mechTypes [0] MechTypeList,
    add_data(&pos, &len, (char*)KRB5_OID.elements, KRB5_OID.length);
    add_der_head(&pos, &len, KRB5_OID.length, 6);
    add_der_head(&pos, &len, KRB5_OID.length + 2, 0x30);
    add_der_head(&pos, &len, KRB5_OID.length + 4, 0xA0);
    // NegTokenInit ::= SEQUENCE { ... }
    add_der_head(&pos, &len, len, 0x30);
    // negTokenInit [0] NegTokenInit,
    add_der_head(&pos, &len, len, 0xA0);
    // [APPLICATION 0] IMPLICIT SEQUENCE {
    //   thisMech MechType,
    //   innerContextToken ANY DEFINED BY thisMech
    add_data(&pos, &len, (char*)SPNEGO_OID.elements, SPNEGO_OID.length);
    add_der_head(&pos, &len, SPNEGO_OID.length, 6);
    add_der_head(&pos, &len, len, 0x60);
    if (len != maxLen) {
        char* result = new char[len];
        memcpy_s(result, len, buffer + maxLen - len, len);
        delete[] buffer;
        buffer = result;
    }
    output->value = buffer;
    output->length = len;
    return 1;
}

// Advances pass ASN.1 tag and length.
// Returns the length value
int
skip_tag_len(char** data)
{
    char* pos = *data;
    pos++;
    int n = *pos & 0xff;
    if (n < 128) {
        pos++;
    } else if (n == 0x81) {
        pos++;
        n = *pos & 0xff;
        pos++;
    } else if (n == 0x82) {
        pos++;
        n = *pos & 0xff;
        pos++;
        n = (n << 8) | (*pos & 0xff);
        pos++;
    } else {
        return -1;
    }
    *data = pos;
    return n;
}

// Extract a krb5 token from a NegTokenResp. Returns the negState,
// or -1 if there is no negState.
int
spnego_to_krb5(gss_buffer_t input, gss_buffer_t output)
{
    int result = -1;
    char* data = (char*)input->value;
    skip_tag_len(&data);
    skip_tag_len(&data);
    while (data - (char*)input->value < (int)input->length) {
        if (*data == (char)0xA2) {
            skip_tag_len(&data);
            output->length = skip_tag_len(&data);
            output->value = data;
            if (input->length - ((char*)output->value - (char*)input->value)
                    < output->length) {
                // inner token has a length field longer than outer token
                break;
            }
            return result;
        } else {
            if (*data == (char)0xA0) {
                result = data[4];
            }
            int tagAndLen = skip_tag_len(&data);
            data += tagAndLen;
        }
    }
    output->length = 0;
    output->value = NULL;
    return result;
}

void
showTime(TimeStamp* ts)
{
    if (trace) {
        SYSTEMTIME stLocal;
        FileTimeToSystemTime((FILETIME*)ts, &stLocal);

        // Build a string showing the date and time.
        PP("---------------");
        PP("TS low high %ld %ld", ts->LowPart, ts->HighPart);
        PP("Local: %02d/%02d/%d  %02d:%02d",
            stLocal.wMonth, stLocal.wDay, stLocal.wYear,
            stLocal.wHour, stLocal.wMinute);
    }
}

long
SecondsUntil(TimeStamp *time)
{
    // time is local time
    ULARGE_INTEGER uiLocal;
    FILETIME nowUTC, nowLocal;
    GetSystemTimeAsFileTime(&nowUTC);
    if (FileTimeToLocalFileTime(&nowUTC, &nowLocal) == 0) {
        return -1;
    }
    uiLocal.HighPart = nowLocal.dwHighDateTime;
    uiLocal.LowPart = nowLocal.dwLowDateTime;
    long diff = (long)((time->QuadPart - uiLocal.QuadPart) / 10000000);
    if (diff < 0 || diff > 8640000) {
        // TODO: AcquireCredentialsHandle returns a strange TimeStamp.
        PP("SecondsUntil is %ld. Change to 1 day", diff);
        diff = 86400;
    }
    return diff;
}

Context*
NewContext(OM_uint32 *minor_status)
{
    SECURITY_STATUS ss;
    PSecPkgInfo pkgInfo;

    Context* out = new Context;
    if (out == NULL) {
        return NULL;
    }
    ss = QuerySecurityPackageInfo(L"Kerberos", &pkgInfo);
    if (!SEC_SUCCESS(ss)) {
        delete out;
        return NULL;
    }
    out->phCred = NULL;
    out->cbMaxMessage = pkgInfo->cbMaxToken;
    FreeContextBuffer(pkgInfo);
    return out;
}

int
flagSspi2Gss(int fin)
{
    int fout = 0;
    if (fin & ISC_REQ_MUTUAL_AUTH) fout |= GSS_C_MUTUAL_FLAG;
    if (fin & ISC_REQ_CONFIDENTIALITY) fout |= GSS_C_CONF_FLAG;
    if (fin & ISC_REQ_DELEGATE) fout |= GSS_C_DELEG_FLAG;
    if (fin & ISC_REQ_INTEGRITY) fout |= GSS_C_INTEG_FLAG;
    if (fin & ISC_REQ_REPLAY_DETECT) fout |= GSS_C_REPLAY_FLAG;
    if (fin & ISC_REQ_SEQUENCE_DETECT) fout |= GSS_C_SEQUENCE_FLAG;
    return fout;
}

int
flagGss2Sspi(int fin)
{
    int fout = 0;
    if (fin & GSS_C_MUTUAL_FLAG) fout |= ISC_RET_MUTUAL_AUTH;
    if (fin & GSS_C_CONF_FLAG) fout |= ISC_RET_CONFIDENTIALITY;
    if (fin & GSS_C_DELEG_FLAG) fout |= ISC_RET_DELEGATE;
    if (fin & GSS_C_INTEG_FLAG) fout |= ISC_RET_INTEGRITY;
    if (fin & GSS_C_REPLAY_FLAG) fout |= ISC_RET_REPLAY_DETECT;
    if (fin & GSS_C_SEQUENCE_FLAG) fout |= ISC_RET_SEQUENCE_DETECT;
    return fout;
}

BOOLEAN
isSameOID(gss_OID o2, gss_OID o1)
{
    return o1->length == o2->length
            && !memcmp(o1->elements, o2->elements, o2->length);
}

void
displayOID(gss_OID mech)
{
    if (trace) {
        if (isSameOID(mech, &KRB5_OID)) {
            PP("Kerberos OID");
        } else if (isSameOID(mech, &SPNEGO_OID)) {
            PP("SPNEGO OID");
        } else {
            dump("UNKNOWN OID", (PBYTE)mech->elements, mech->length);
        }
    }
}

void
displayOidSet(gss_OID_set mechs)
{
    if (trace) {
        if (mechs == NULL) {
            PP("OID set is NULL");
            return;
        }
        PP("gss_OID_set.count is %d", (int)mechs->count);
        for (int i = 0; i < mechs->count; i++) {
            displayOID(&mechs->elements[i]);
        }
    }
}

// Add realm to a name if there was none.
// Returns a newly allocated name.
WCHAR*
get_full_name(WCHAR* input)
{
    // input has realm, no need to add one
    if (wcschr(input, '@')) {
        return input;
    }

    // Is this a host-based service name? Ex: service/host.domain.com.
    // Then we assume the realm is DOMAIN.COM.
    WCHAR* realm = wcsrchr(input, '/'); // /host.domain.com
    if (realm) {
        realm = wcschr(realm, '.'); // .domain.com
        if (realm != NULL) {
            realm++; // domain.com
        }
    }

    // Otherwise we use the default domain
    if (realm == NULL) {
        realm = _wgetenv(L"USERDNSDOMAIN");
        if (realm == NULL) {
            realm = L"";
        }
    }

    size_t oldlen = wcslen(input);
    WCHAR* fullname = new WCHAR[oldlen + 1 + wcslen(realm) + 1];
    if (!fullname) {
        return NULL;
    }
    wcscpy_s(fullname, oldlen + 1, input);
    fullname[oldlen] = '@';

    wcscpy_s(fullname + oldlen + 1, wcslen(realm) + 1, realm);
    _wcsupr(fullname + oldlen + 1);

    return fullname;
}

/* End support section */

/* This section holds GSS-API exported functions */

#define CHECK_OUTPUT(x)  if (!x) return GSS_S_FAILURE;
#define CHECK_BUFFER(b)  if (!b || !b->value) return GSS_S_FAILURE;
#define CHECK_OID(o)     if (!o || !o->elements) return GSS_S_FAILURE;
#define CHECK_NAME(n)    if (!n || !(((Name*)n)->name)) return GSS_S_BAD_NAME;
#define CHECK_CONTEXT(c) if (!c) return GSS_S_NO_CONTEXT;
#define CHECK_CRED(c)    if (!c || !(((Credential*)cred_handle)->phCred)) \
                                return GSS_S_NO_CRED;

__declspec(dllexport) OM_uint32
gss_release_name(OM_uint32 *minor_status,
                 gss_name_t *name)
{
    PP(">>>> Calling gss_release_name %p...", *name);
    if (name != NULL && *name != GSS_C_NO_NAME) {
        Name* name1 = (Name*)*name;
        if (name1->name != NULL) {
            delete[] name1->name;
        }
        delete name1;
        *name = GSS_C_NO_NAME;
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_import_name(OM_uint32 *minor_status,
                gss_buffer_t input_name_buffer,
                gss_OID input_name_type,
                gss_name_t *output_name)
{
    PP(">>>> Calling gss_import_name...");
    CHECK_BUFFER(input_name_buffer)
    CHECK_OID(input_name_type)
    CHECK_OUTPUT(output_name)

    int len = (int)input_name_buffer->length;
    LPSTR input = (LPSTR)input_name_buffer->value;
    BOOLEAN isNegotiate = true;
    if (isSameOID(input_name_type, &EXPORT_NAME_OID)) {
        // Skip OID and other headers
        len -= (int)input[3] + 8;
        isNegotiate = (int)input[3] == 6;
        input = input + (int)input[3] + 8;
    }

    SEC_WCHAR* value = new SEC_WCHAR[len + 1];
    if (value == NULL) {
        goto err;
    }

    len = MultiByteToWideChar(CP_ACP, 0, input, len, value, len+1);
    if (len == 0) {
        goto err;
    }
    value[len] = 0;

    if (input_name_type != NULL
            && isSameOID(input_name_type, &HOST_SERVICE_NAME_OID)) {
        // HOST_SERVICE_NAME_OID takes the form of service@host.
        for (int i = 0; i < len; i++) {
            if (value[i] == '@') {
                value[i] = '/';
                break;
            }
        }
    }
    Name* name = new Name;
    if (name == NULL) {
        goto err;
    }
    name->name = value;
    *output_name = (gss_name_t) name;
    return GSS_S_COMPLETE;
err:
    if (value != NULL) {
        delete[] value;
    }
    if (name != NULL) {
        delete name;
    }
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_compare_name(OM_uint32 *minor_status,
                 gss_name_t name1,
                 gss_name_t name2,
                 int *name_equal)
{
    PP(">>>> Calling gss_compare_name...");
    CHECK_NAME(name1)
    CHECK_NAME(name2)
    CHECK_OUTPUT(name_equal)

    SEC_WCHAR* names1 = ((Name*)name1)->name;
    SEC_WCHAR* names2 = ((Name*)name2)->name;
    if (lstrcmp(names1, names2)) {
        *name_equal = 0;
    } else {
        *name_equal = 1;
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_canonicalize_name(OM_uint32 *minor_status,
                      gss_name_t input_name,
                      gss_OID mech_type,
                      gss_name_t *output_name)
{
    PP(">>>> Calling gss_canonicalize_name...");
    CHECK_NAME(input_name)
    CHECK_OID(mech_type)
    CHECK_OUTPUT(output_name)

    Name* names1 = (Name*)input_name;
    Name* names2 = new Name;
    if (names2 == NULL) {
        return GSS_S_FAILURE;
    }
    names2->name = new SEC_WCHAR[lstrlen(names1->name) + 1];
    if (names2->name == NULL) {
        delete names2;
        return GSS_S_FAILURE;
    }
    StringCchCopy(names2->name, lstrlen(names1->name) + 1, names1->name);
    *output_name = (gss_name_t)names2;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_export_name(OM_uint32 *minor_status,
                gss_name_t input_name,
                gss_buffer_t exported_name)
{
    PP(">>>> Calling gss_export_name...");
    CHECK_NAME(input_name)
    CHECK_OUTPUT(exported_name)

    OM_uint32 result = GSS_S_FAILURE;
    SEC_WCHAR* name = ((Name*)input_name)->name;
    SEC_WCHAR* fullname = get_full_name(name);
    if (!fullname) {
        goto err;
    }
    PP("%ls -> %ls", name, fullname);
    int len = (int)wcslen(fullname);
    if (len < 256) {
        // We only deal with not-so-long names.
        // 04 01 00 ** 06 ** OID len:int32 name
        int mechLen = KRB5_OID.length;
        char* buffer = new char[10 + mechLen + len];
        if (buffer == NULL) {
            goto err;
        }
        buffer[0] = 4;
        buffer[1] = 1;
        buffer[2] = 0;
        buffer[3] = 2 + mechLen;
        buffer[4] = 6;
        buffer[5] = mechLen;
        memcpy_s(buffer + 6, mechLen, KRB5_OID.elements, mechLen);
        buffer[6 + mechLen] = buffer[7 + mechLen] = buffer[8 + mechLen] = 0;
        buffer[9 + mechLen] = (char)len;
        len = WideCharToMultiByte(CP_ACP, 0, fullname, len,
                    buffer+10+mechLen, len, NULL, NULL);
        if (len == 0) {
            delete[] buffer;
            goto err;
        }
        exported_name->length = 10 + mechLen + len;
        exported_name->value = buffer;
        result = GSS_S_COMPLETE;
    }
err:
    if (fullname != name) {
        delete[] fullname;
    }
    return result;
}

__declspec(dllexport) OM_uint32
gss_display_name(OM_uint32 *minor_status,
                 gss_name_t input_name,
                 gss_buffer_t output_name_buffer,
                 gss_OID *output_name_type)
{
    PP(">>>> Calling gss_display_name...");
    CHECK_NAME(input_name)
    CHECK_OUTPUT(output_name_buffer)

    SEC_WCHAR* names = ((Name*)input_name)->name;
    int len = (int)wcslen(names);
    char* buffer = new char[len+1];
    if (buffer == NULL) {
        return GSS_S_FAILURE;
    }
    len = WideCharToMultiByte(CP_ACP, 0, names, len, buffer, len, NULL, NULL);
    if (len == 0) {
        return GSS_S_FAILURE;
    }
    buffer[len] = 0;
    output_name_buffer->length = len;
    output_name_buffer->value = buffer;
    PP("Name found: %ls", names);
    PP("%d [%s]", len, buffer);
    if (output_name_type != NULL) {
        *output_name_type = &USER_NAME_OID;
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_acquire_cred(OM_uint32 *minor_status,
                 gss_name_t desired_name,
                 OM_uint32 time_req,
                 gss_OID_set desired_mech,
                 gss_cred_usage_t cred_usage,
                 gss_cred_id_t *output_cred_handle,
                 gss_OID_set *actual_mechs,
                 OM_uint32 *time_rec)
{
    PP(">>>> Calling gss_acquire_cred...");
    CHECK_OUTPUT(output_cred_handle)

    SECURITY_STATUS ss;
    TimeStamp ts;
    ts.QuadPart = 0;
    cred_usage = 0;
    PP("AcquireCredentialsHandle with %d %p", cred_usage, desired_mech);
    displayOidSet(desired_mech);
    Credential* cred = new Credential;
    cred->phCred = new CredHandle;
    if (cred == NULL || cred->phCred == NULL) {
        return GSS_S_FAILURE;
    }
    ts.QuadPart = 0;
    ss = AcquireCredentialsHandle(
            NULL,
            L"Kerberos",
            cred_usage == 0 ? SECPKG_CRED_BOTH :
                (cred_usage == 1 ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND),
            NULL,
            NULL,
            NULL,
            NULL,
            cred->phCred,
            &ts);
    actual_mechs = &desired_mech; // TODO: dup?
    *output_cred_handle = (void*)cred;
    showTime(&ts);
    cred->time = SecondsUntil(&ts);
    if (time_rec != NULL) {
        *time_rec = cred->time;
    }

    if (desired_name != NULL) {
        gss_name_t realname;
        if (gss_inquire_cred(minor_status, *output_cred_handle, &realname,
                NULL, NULL, NULL) != GSS_S_COMPLETE) {
            return GSS_S_FAILURE;
        }
        SEC_WCHAR* dnames = ((Name*)desired_name)->name;
        SEC_WCHAR* rnames = ((Name*)realname)->name;
        PP("comp name %ls %ls", dnames, rnames);
        int cmp = lstrcmp(dnames, rnames);
        gss_release_name(minor_status, &realname);
        return cmp ? GSS_S_FAILURE : GSS_S_COMPLETE; // Only support default cred
    }

    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_release_cred(OM_uint32 *minor_status,
                 gss_cred_id_t *cred_handle)
{
    PP(">>>> Calling gss_release_cred...");
    if (cred_handle && *cred_handle) {
        Credential* cred = (Credential*)*cred_handle;
        FreeCredentialsHandle(cred->phCred);
        delete cred->phCred;
        delete cred;
        *cred_handle = GSS_C_NO_CREDENTIAL;
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_inquire_cred(OM_uint32 *minor_status,
                 gss_cred_id_t cred_handle,
                 gss_name_t *name,
                 OM_uint32 *lifetime,
                 gss_cred_usage_t *cred_usage,
                 gss_OID_set *mechanisms)
{
    PP(">>>> Calling gss_inquire_cred...");
    CHECK_CRED(cred_handle)

    CredHandle* cred = ((Credential*)cred_handle)->phCred;
    SECURITY_STATUS ss;
    if (name) {
        SecPkgCredentials_Names snames;
        ss = QueryCredentialsAttributes(cred, SECPKG_CRED_ATTR_NAMES, &snames);
        if (!SEC_SUCCESS(ss)) {
            return GSS_S_FAILURE;
        }
        SEC_WCHAR* names = new SEC_WCHAR[lstrlen(snames.sUserName) + 1];
        if (names == NULL) {
            return GSS_S_FAILURE;
        }
        StringCchCopy(names, lstrlen(snames.sUserName) + 1, snames.sUserName);
        FreeContextBuffer(snames.sUserName);
        PP("new name at %p", names);
        Name* name1 = new Name;
        if (name1 == NULL) {
            delete[] names;
            return GSS_S_FAILURE;
        }
        name1->name = names;
        *name = (gss_name_t) name1;
    }
    if (lifetime) {
        *lifetime = ((Credential*)cred_handle)->time;
    }
    if (cred_usage) {
        *cred_usage = 1; // We only support INITIATE_ONLY now
    }
    if (mechanisms) {
        // Useless for Java
    }
    // Others inquiries not supported yet
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_import_sec_context(OM_uint32 *minor_status,
                       gss_buffer_t interprocess_token,
                       gss_ctx_id_t *context_handle)
{
    // Not transferable, return FAILURE
    PP(">>>> Calling UNIMPLEMENTED gss_import_sec_context...");
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_init_sec_context(OM_uint32 *minor_status,
                     gss_cred_id_t initiator_cred_handle,
                     gss_ctx_id_t *context_handle,
                     gss_name_t target_name,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    PP(">>>> Calling gss_init_sec_context...");
    CHECK_NAME(target_name)
    CHECK_OUTPUT(output_token)

    SECURITY_STATUS ss;
    TimeStamp Lifetime;
    SecBufferDesc InBuffDesc;
    SecBuffer InSecBuff;
    SecBufferDesc OutBuffDesc;
    SecBuffer OutSecBuff;

    Context* pc;
    if (input_token->length == 0) {
        pc = NewContext(minor_status);
        if (pc == NULL) {
            return GSS_S_FAILURE;
        }
        Credential* cred = (Credential*)initiator_cred_handle;
        if (cred != NULL) {
            pc->phCred = cred->phCred;
        }
        *context_handle = (gss_ctx_id_t) pc;
    } else {
        pc = (Context*)*context_handle;
    }

    if (pc == NULL) {
        return GSS_S_NO_CONTEXT;
    }

    output_token->length = pc->cbMaxMessage;
    output_token->value = new char[pc->cbMaxMessage];

    if (output_token->value == NULL) {
        return GSS_S_FAILURE;
    }

    DWORD outFlag;
    TCHAR outName[100];

    OM_uint32 minor;
    gss_buffer_desc tn;
    gss_display_name(&minor, target_name, &tn, NULL);
    int len = MultiByteToWideChar(CP_ACP, 0, (LPCCH)tn.value, (int)tn.length,
            outName, (int)tn.length);
    if (len == 0) {
        return GSS_S_FAILURE;
    }
    outName[len] = 0;

    BOOL pfDone;
    int flag = flagGss2Sspi(req_flags);

    OutBuffDesc.ulVersion = SECBUFFER_VERSION;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.cbBuffer = (ULONG)output_token->length;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = output_token->value;

    if (input_token->value) {
        gss_buffer_desc newBuffer;
        if (isSameOID(mech_type, &SPNEGO_OID)) {
            PP("Extract Kerberos token from Negotiate");
            int negState = spnego_to_krb5(input_token, &newBuffer);
            PP("negState is %d", negState);
            if (newBuffer.length == 0) {
                output_token->length = 0;
                output_token->value = NULL;
                return negState == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
            }
            if (negState == 2 || negState == 3) {
                return GSS_S_FAILURE;
            }
            PP("Extract complete. %d", (int)newBuffer.length);
        } else {
            newBuffer.length = input_token->length;
            newBuffer.value = input_token->value;
        }
        InBuffDesc.ulVersion = SECBUFFER_VERSION;
        InBuffDesc.cBuffers = 1;
        InBuffDesc.pBuffers = &InSecBuff;

        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.cbBuffer = (ULONG)newBuffer.length;
        InSecBuff.pvBuffer = newBuffer.value;
    } else {
        if (!pc->phCred) {
            PP("No credentials provided, acquire automatically");
            CredHandle* newCred = new CredHandle;
            ss = AcquireCredentialsHandle(
                    NULL,
                    L"Kerberos",
                    SECPKG_CRED_OUTBOUND,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    newCred,
                    &Lifetime);
            pc->phCred = newCred;
            PP("end");
            if (!(SEC_SUCCESS(ss))) {
                PP("Failed");
                return GSS_S_FAILURE;
            }
        } else {
            PP("Credentials OK");
        }
    }
    ss = InitializeSecurityContext(
            pc->phCred,
            input_token->value ? &pc->hCtxt : NULL,
            outName,
            flag,
            0,
            SECURITY_NATIVE_DREP,
            input_token->value ? &InBuffDesc : NULL,
            0,
            &pc->hCtxt,
            &OutBuffDesc,
            &outFlag,
            &Lifetime);

    if (!SEC_SUCCESS(ss)) {
        return GSS_S_FAILURE;
    }

    if ((SEC_I_COMPLETE_NEEDED == ss)
            || (SEC_I_COMPLETE_AND_CONTINUE == ss)) {
        ss = CompleteAuthToken(&pc->hCtxt, &OutBuffDesc);
        if (!SEC_SUCCESS(ss)) {
            return GSS_S_FAILURE;
        }
    }

    output_token->length = OutSecBuff.cbBuffer;

    if (output_token->length > 0 && isSameOID(mech_type, &SPNEGO_OID)) {
        PP("Wrap Kerberos token in Negotiate");
        gss_buffer_desc newBuffer;
        if (krb5_to_spnego(output_token, &newBuffer) == 0) {
            return GSS_S_CONTINUE_NEEDED;
        }
        output_token->length = newBuffer.length;
        output_token->value = newBuffer.value;
    }

    pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||
                (SEC_I_COMPLETE_AND_CONTINUE == ss));
    outFlag = flagSspi2Gss(outFlag);
    PP("Done? %d outFlag: %d", pfDone, outFlag);

    *ret_flags = (OM_uint32)outFlag;
    if (ss == SEC_I_CONTINUE_NEEDED) {
        return GSS_S_CONTINUE_NEEDED;
    } else {
        ss = QueryContextAttributes(
                &pc->hCtxt, SECPKG_ATTR_SIZES, &pc->SecPkgContextSizes);
        if (!SEC_SUCCESS(ss)) {
            return GSS_S_FAILURE;
        }
        pc->established = true;
        ss = QueryContextAttributes(&pc->hCtxt, SECPKG_ATTR_NATIVE_NAMES, &pc->nnames);
        PP("Names. %ls %ls", pc->nnames.sClientName, pc->nnames.sServerName);
        if (!SEC_SUCCESS(ss)) {
            return GSS_S_FAILURE;
        }
        // SPENGO needs another round even if Kerberos is done
        if (isSameOID(mech_type, &SPNEGO_OID) && input_token->length == 0) {
            return GSS_S_CONTINUE_NEEDED;
        } else {
            *ret_flags |= GSS_C_PROT_READY_FLAG;
            return GSS_S_COMPLETE;
        }
    }
}

__declspec(dllexport) OM_uint32
gss_accept_sec_context(OM_uint32 *minor_status,
                       gss_ctx_id_t *context_handle,
                       gss_cred_id_t acceptor_cred_handle,
                       gss_buffer_t input_token,
                       gss_channel_bindings_t input_chan_bindings,
                       gss_name_t *src_name,
                       gss_OID *mech_type,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags,
                       OM_uint32 *time_rec,
                       gss_cred_id_t *delegated_cred_handle)
{
    PP(">>>> Calling UNIMPLEMENTED gss_accept_sec_context...");
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_inquire_context(OM_uint32 *minor_status,
                    gss_ctx_id_t context_handle,
                    gss_name_t *src_name,
                    gss_name_t *targ_name,
                    OM_uint32 *lifetime_rec,
                    gss_OID *mech_type,
                    OM_uint32 *ctx_flags,
                    int *locally_initiated,
                    int *open)
{
    PP(">>>> Calling gss_inquire_context...");
    CHECK_CONTEXT(context_handle)

    Context* pc = (Context*) context_handle;
    Name* n1 = NULL;
    Name* n2 = NULL;
    if (!pc->established) {
        return GSS_S_NO_CONTEXT;
    }
    if (src_name != NULL) {
        n1 = new Name;
        if (n1 == NULL) {
            goto err;
        }
        n1->name = new SEC_WCHAR[lstrlen(pc->nnames.sClientName) + 1];
        if (n1->name == NULL) {
            goto err;
        }
        PP("new name at %p", n1->name);
        StringCchCopy(n1->name, lstrlen(pc->nnames.sClientName) + 1, pc->nnames.sClientName);
        *src_name = (gss_name_t) n1;
    }
    if (targ_name != NULL) {
        n2 = new Name;
        if (n2 == NULL) {
            goto err;
        }
        n2->name = new SEC_WCHAR[lstrlen(pc->nnames.sServerName) + 1];
        if (n2->name == NULL) {
            goto err;
        }
        PP("new name at %p", n2->name);
        StringCchCopy(n2->name, lstrlen(pc->nnames.sServerName) + 1, pc->nnames.sServerName);
        *targ_name = (gss_name_t) n2;
    }
    if (lifetime_rec != NULL) {
        SecPkgContext_Lifespan ls;
        SECURITY_STATUS ss;
        ss = QueryContextAttributes(&pc->hCtxt, SECPKG_ATTR_LIFESPAN, &ls);
        if (!SEC_SUCCESS(ss)) {
            goto err;
        }
        *lifetime_rec = SecondsUntil(&ls.tsExpiry);
    }
    // TODO: other inquiries
    return GSS_S_COMPLETE;
err:
    if (n1 != NULL) {
        if (n1->name != NULL) {
            delete[] n1->name;
        }
        delete n1;
        n1 = NULL;
    }
    if (n2 != NULL) {
        if (n2->name != NULL) {
            delete[] n2->name;
        }
        delete n2;
        n2 = NULL;
    }
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_delete_sec_context(OM_uint32 *minor_status,
                       gss_ctx_id_t *context_handle,
                       gss_buffer_t output_token)
{
    PP(">>>> Calling gss_delete_sec_context...");
    CHECK_CONTEXT(context_handle)

    Context* pc = (Context*) *context_handle;
    DeleteSecurityContext(&pc->hCtxt);
    if (pc->phCred != NULL) {
        FreeCredentialsHandle(pc->phCred);
        pc->phCred = NULL;
    }
    if (pc->nnames.sClientName != NULL) {
        FreeContextBuffer(pc->nnames.sClientName);
        pc->nnames.sClientName = NULL;
    }
    if (pc->nnames.sServerName != NULL) {
        FreeContextBuffer(pc->nnames.sServerName);
        pc->nnames.sServerName = NULL;
    }
    delete pc;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_context_time(OM_uint32 *minor_status,
                 gss_ctx_id_t context_handle,
                 OM_uint32 *time_rec)
{
    PP(">>>> Calling IMPLEMENTED gss_context_time...");
    CHECK_CONTEXT(context_handle)
    CHECK_OUTPUT(time_rec)

    SECURITY_STATUS ss;
    Context* pc = (Context*) context_handle;
    SecPkgContext_Lifespan ls;
    ss = QueryContextAttributes(&pc->hCtxt, SECPKG_ATTR_LIFESPAN, &ls);
    if (ss == SEC_E_OK) {
        *time_rec = SecondsUntil(&ls.tsExpiry);
        showTime(&ls.tsStart);
        showTime(&ls.tsExpiry);
        TimeStamp ts;
        GetSystemTimeAsFileTime((FILETIME*)&ts);
        showTime(&ts);
        return GSS_S_COMPLETE;
    } else {
        PP("QueryContextAttributes failed");
        return GSS_S_FAILURE;
    }
}

__declspec(dllexport) OM_uint32
gss_wrap_size_limit(OM_uint32 *minor_status,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    OM_uint32 req_output_size,
                    OM_uint32 *max_input_size)
{
    PP(">>>> Calling gss_wrap_size_limit...");
    CHECK_CONTEXT(context_handle)
    CHECK_OUTPUT(max_input_size)

    Context* pc = (Context*) context_handle;
    *max_input_size = pc->cbMaxMessage;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_export_sec_context(OM_uint32 *minor_status,
                       gss_ctx_id_t *context_handle,
                       gss_buffer_t interprocess_token)
{
    PP(">>>> Calling UNIMPLEMENTED gss_export_sec_context...");
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_get_mic(OM_uint32 *minor_status,
            gss_ctx_id_t context_handle,
            gss_qop_t qop_req,
            gss_buffer_t message_buffer,
            gss_buffer_t msg_token)
{
    PP(">>>> Calling gss_get_mic...");
    CHECK_CONTEXT(context_handle);
    CHECK_BUFFER(message_buffer);
    CHECK_OUTPUT(msg_token);

    Context* pc = (Context*) context_handle;

    SECURITY_STATUS ss;
    SecBufferDesc BuffDesc;
    SecBuffer SecBuff[2];

    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;
    BuffDesc.ulVersion = SECBUFFER_VERSION;

    SecBuff[0].BufferType = SECBUFFER_DATA;
    SecBuff[0].cbBuffer = (ULONG)message_buffer->length;
    SecBuff[0].pvBuffer = message_buffer->value;

    SecBuff[1].BufferType = SECBUFFER_TOKEN;
    SecBuff[1].cbBuffer = pc->SecPkgContextSizes.cbMaxSignature;
    SecBuff[1].pvBuffer = msg_token->value = malloc(SecBuff[1].cbBuffer);

    ss = MakeSignature(&pc->hCtxt, 0, &BuffDesc, 0);

    if (!SEC_SUCCESS(ss)) {
        free(SecBuff[1].pvBuffer);
        return GSS_S_FAILURE;
    }

    msg_token->length = SecBuff[1].cbBuffer;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_verify_mic(OM_uint32 *minor_status,
               gss_ctx_id_t context_handle,
               gss_buffer_t message_buffer,
               gss_buffer_t token_buffer,
               gss_qop_t *qop_state)
{
    PP(">>>> Calling gss_verify_mic...");
    CHECK_CONTEXT(context_handle);
    CHECK_BUFFER(message_buffer);
    CHECK_BUFFER(token_buffer);

    Context* pc = (Context*) context_handle;

    SECURITY_STATUS ss;
    SecBufferDesc BuffDesc;
    SecBuffer SecBuff[2];
    ULONG qop;

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].cbBuffer = (ULONG)token_buffer->length;
    SecBuff[0].pvBuffer = token_buffer->value;

    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].cbBuffer = (ULONG)message_buffer->length;
    SecBuff[1].pvBuffer = message_buffer->value;

    ss = VerifySignature(&pc->hCtxt, &BuffDesc, 0, &qop);
    *qop_state = qop;

    if (ss == SEC_E_OK) {
        return GSS_S_COMPLETE;
    } else if (ss == SEC_E_OUT_OF_SEQUENCE) {
        return GSS_S_UNSEQ_TOKEN;
    } else {
        return GSS_S_BAD_SIG;
    }
}

__declspec(dllexport) OM_uint32
gss_wrap(OM_uint32 *minor_status,
         gss_ctx_id_t context_handle,
         int conf_req_flag,
         gss_qop_t qop_req,
         gss_buffer_t input_message_buffer,
         int *conf_state,
         gss_buffer_t output_message_buffer)
{
    PP(">>>> Calling gss_wrap...");
    CHECK_CONTEXT(context_handle);
    CHECK_BUFFER(input_message_buffer);
    CHECK_OUTPUT(output_message_buffer);

    Context* pc = (Context*) context_handle;

    SECURITY_STATUS ss;
    SecBufferDesc BuffDesc;
    SecBuffer SecBuff[3];

    BuffDesc.ulVersion = SECBUFFER_VERSION;
    BuffDesc.cBuffers = 3;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].cbBuffer = pc->SecPkgContextSizes.cbSecurityTrailer;
    output_message_buffer->value = SecBuff[0].pvBuffer = malloc(
            pc->SecPkgContextSizes.cbSecurityTrailer
                    + input_message_buffer->length
                    + pc->SecPkgContextSizes.cbBlockSize);;

    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].cbBuffer = (ULONG)input_message_buffer->length;
    SecBuff[1].pvBuffer = malloc(SecBuff[1].cbBuffer);
    memcpy_s(SecBuff[1].pvBuffer, SecBuff[1].cbBuffer,
            input_message_buffer->value, input_message_buffer->length);

    SecBuff[2].BufferType = SECBUFFER_PADDING;
    SecBuff[2].cbBuffer = pc->SecPkgContextSizes.cbBlockSize;
    SecBuff[2].pvBuffer = malloc(SecBuff[2].cbBuffer);

    ss = EncryptMessage(&pc->hCtxt, conf_req_flag ? 0 : SECQOP_WRAP_NO_ENCRYPT,
            &BuffDesc, 0);
    *conf_state = conf_req_flag;

    if (!SEC_SUCCESS(ss)) {
        free(SecBuff[0].pvBuffer);
        free(SecBuff[1].pvBuffer);
        free(SecBuff[2].pvBuffer);
        return GSS_S_FAILURE;
    }

    memcpy_s((PBYTE)SecBuff[0].pvBuffer + SecBuff[0].cbBuffer,
            input_message_buffer->length + pc->SecPkgContextSizes.cbBlockSize,
            SecBuff[1].pvBuffer,
            SecBuff[1].cbBuffer);
    memcpy_s((PBYTE)SecBuff[0].pvBuffer + SecBuff[0].cbBuffer + SecBuff[1].cbBuffer,
            pc->SecPkgContextSizes.cbBlockSize,
            SecBuff[2].pvBuffer,
            SecBuff[2].cbBuffer);

    output_message_buffer->length = SecBuff[1].cbBuffer + SecBuff[0].cbBuffer
            + SecBuff[2].cbBuffer;
    free(SecBuff[1].pvBuffer);
    free(SecBuff[2].pvBuffer);

    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_unwrap(OM_uint32 *minor_status,
           gss_ctx_id_t context_handle,
           gss_buffer_t input_message_buffer,
           gss_buffer_t output_message_buffer,
           int *conf_state,
           gss_qop_t *qop_state)
{
    PP(">>>> Calling gss_unwrap...");
    CHECK_CONTEXT(context_handle);
    CHECK_BUFFER(input_message_buffer);
    CHECK_OUTPUT(output_message_buffer);

    Context* pc = (Context*) context_handle;

    SECURITY_STATUS ss;
    SecBufferDesc BuffDesc;
    SecBuffer SecBuff[2];
    ULONG ulQop = 0;

    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;
    BuffDesc.ulVersion = SECBUFFER_VERSION;

    SecBuff[0].BufferType = SECBUFFER_STREAM;
    SecBuff[0].cbBuffer = (ULONG)input_message_buffer->length;
    output_message_buffer->value = SecBuff[0].pvBuffer
            = malloc(input_message_buffer->length);
    memcpy_s(SecBuff[0].pvBuffer, input_message_buffer->length,
            input_message_buffer->value, input_message_buffer->length);

    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].cbBuffer = 0;
    SecBuff[1].pvBuffer = NULL;

    ss = DecryptMessage(&pc->hCtxt, &BuffDesc, 0, &ulQop);
    if (!SEC_SUCCESS(ss)) {
        free(SecBuff[0].pvBuffer);
        return GSS_S_FAILURE;
    }
    output_message_buffer->length = SecBuff[1].cbBuffer;
    output_message_buffer->value = SecBuff[1].pvBuffer;
    *conf_state = ulQop == SECQOP_WRAP_NO_ENCRYPT ? 0 : 1;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_indicate_mechs(OM_uint32 *minor_status,
                   gss_OID_set *mech_set)
{
    PP(">>>> Calling gss_indicate_mechs...");
    OM_uint32 minor = 0;
    OM_uint32 major = GSS_S_COMPLETE;

    ULONG ccPackages;
    PSecPkgInfo packages;
    EnumerateSecurityPackages(&ccPackages, &packages);
    PP("EnumerateSecurityPackages returns %ld", ccPackages);

    PSecPkgInfo pkgInfo;
    SECURITY_STATUS ss;
    ss = QuerySecurityPackageInfo(L"Kerberos", &pkgInfo);
    if (ss != SEC_E_OK) {
        goto done;
    }

    major = gss_create_empty_oid_set(minor_status, mech_set);
    if (major != GSS_S_COMPLETE) {
        goto done;
    }

    major = gss_add_oid_set_member(minor_status, &KRB5_OID, mech_set);
    if (major != GSS_S_COMPLETE) {
        goto done;
    }

    major = gss_add_oid_set_member(minor_status, &SPNEGO_OID, mech_set);
    if (major != GSS_S_COMPLETE) {
        goto done;
    }

done:

    if (major != GSS_S_COMPLETE) {
        gss_release_oid_set(minor_status, mech_set);
    }

    FreeContextBuffer(packages);

    return major;
}

__declspec(dllexport) OM_uint32
gss_inquire_names_for_mech(OM_uint32 *minor_status,
                           const gss_OID mechanism,
                           gss_OID_set *name_types)
{
    PP(">>>> Calling IMPLEMENTED gss_inquire_names_for_mech...");
    CHECK_OID(mechanism);

    gss_create_empty_oid_set(minor_status, name_types);
    gss_add_oid_set_member(minor_status, &USER_NAME_OID, name_types);
    gss_add_oid_set_member(minor_status, &HOST_SERVICE_NAME_OID, name_types);
    if (!isSameOID(mechanism, &SPNEGO_OID)) {
        gss_add_oid_set_member(minor_status, &EXPORT_NAME_OID, name_types);
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_add_oid_set_member(OM_uint32 *minor_status,
                       gss_OID member_oid,
                       gss_OID_set *oid_set)
{
    PP(">>>> Calling gss_add_oid_set_member...");
    CHECK_OID(member_oid);
    CHECK_OUTPUT(oid_set);


    int count = (int)(*oid_set)->count;
    for (int i = 0; i < count; i++) {
        if (isSameOID(&(*oid_set)->elements[i], member_oid)) {
            // already there
            return GSS_S_COMPLETE;
        }
    }
    gss_OID existing = (*oid_set)->elements;
    gss_OID newcopy = new gss_OID_desc[count + 1];
    if (newcopy == NULL) {
        return GSS_S_FAILURE;
    }
    if (existing) {
        memcpy_s(newcopy, (count + 1) * sizeof(gss_OID_desc),
                existing, count * sizeof(gss_OID_desc));
    }
    newcopy[count].length = member_oid->length;
    newcopy[count].elements = new char[member_oid->length];
    if (newcopy[count].elements == NULL) {
        delete[] newcopy;
        return GSS_S_FAILURE;
    }
    memcpy_s(newcopy[count].elements, member_oid->length,
            member_oid->elements, member_oid->length);
    (*oid_set)->elements = newcopy;
    (*oid_set)->count++;
    if (existing) {
        delete[] existing;
    }

    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_display_status(OM_uint32 *minor_status,
                   OM_uint32 status_value,
                   int status_type,
                   gss_OID mech_type,
                   OM_uint32 *message_context,
                   gss_buffer_t status_string)
{
    PP(">>>> Calling gss_display_status...");
    TCHAR msg[256];
    int len = FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            0, status_value,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            msg, 256, 0);
    if (len > 0) {
        status_string->value = new char[len + 20];
        status_string->length = sprintf_s(
                (LPSTR)status_string->value, len + 19,
                "(%lx) %ls", status_value, msg);
        if (status_string->length <= 0) {
            delete[] status_string->value;
            status_string->value = NULL;
        }
    } else {
        status_string->length = 0;
    }
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_create_empty_oid_set(OM_uint32 *minor_status,
                         gss_OID_set *oid_set)
{
    PP(">>>> Calling gss_create_empty_oid_set...");
    CHECK_OUTPUT(oid_set);

    if (*oid_set = new gss_OID_set_desc) {
        memset(*oid_set, 0, sizeof(gss_OID_set_desc));
        return GSS_S_COMPLETE;
    }
    return GSS_S_FAILURE;
}

__declspec(dllexport) OM_uint32
gss_release_oid_set(OM_uint32 *minor_status,
                    gss_OID_set *set)
{
    PP(">>>> Calling gss_release_oid_set...");
    if (set == NULL || *set == GSS_C_NO_OID_SET) {
        return GSS_S_COMPLETE;
    }
    for (int i = 0; i < (*set)->count; i++) {
        delete[] (*set)->elements[i].elements;
    }
    delete[] (*set)->elements;
    delete *set;
    *set = GSS_C_NO_OID_SET;
    return GSS_S_COMPLETE;
}

__declspec(dllexport) OM_uint32
gss_release_buffer(OM_uint32 *minor_status,
                   gss_buffer_t buffer)
{
    PP(">>>> Calling gss_release_buffer...");
    if (buffer == NULL) {
        return GSS_S_COMPLETE;
    }
    if (buffer->value) {
        delete[] buffer->value;
        buffer->value = NULL;
        buffer->length = 0;
    }
    return GSS_S_COMPLETE;
}

/* End implemented section */

#ifdef __cplusplus
}
#endif
