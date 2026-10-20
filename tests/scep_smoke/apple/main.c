#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef CFArrayRef (*Decode)(CFDataRef);
typedef OSStatus (*Validate)(CFArrayRef, CFDataRef, SecCertificateRef *, SecCertificateRef *, SecCertificateRef *);

int main(int argc, char **argv) {
    void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
    Decode decode = framework ? (Decode)dlsym(framework, "SecCMSCertificatesOnlyMessageCopyCertificates") : NULL;
    Validate validate = framework ? (Validate)dlsym(framework, "SecSCEPValidateCACertMessage") : NULL;
    if (argc != 2 || !decode || !validate) {
        printf("{\"cms_symbol\":%s,\"scep_symbol\":%s}\n", decode ? "true" : "false", validate ? "true" : "false");
        return 2;
    }
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return 3; }
    long size = ftell(file);
    rewind(file);
    if (size <= 0 || size > 1024 * 1024) { fclose(file); return 3; }
    unsigned char *bytes = malloc((size_t)size);
    if (!bytes || fread(bytes, 1, (size_t)size, file) != (size_t)size) { fclose(file); free(bytes); return 3; }
    fclose(file);
    CFDataRef data = CFDataCreate(NULL, bytes, size);
    free(bytes);
    if (!data) return 3;
    CFArrayRef certs = decode(data);
    if (!certs) { puts("{\"cms_decoded\":false}"); CFRelease(data); return 4; }
    SecCertificateRef ca = NULL, signing = NULL, encryption = NULL;
    OSStatus status = validate(certs, NULL, &ca, &signing, &encryption);
    printf("{\"cms_decoded\":true,\"certificate_count\":%ld,\"status\":%d,\"key_usage_incorrect\":%s,\"ca_selected\":%s,\"signing_selected\":%s,\"separate_encryption_selected\":%s}\n", (long)CFArrayGetCount(certs), (int)status, status == errSecKeyUsageIncorrect ? "true" : "false", ca ? "true" : "false", signing ? "true" : "false", encryption ? "true" : "false");
    if (ca) CFRelease(ca);
    if (signing) CFRelease(signing);
    if (encryption) CFRelease(encryption);
    CFRelease(certs);
    CFRelease(data);
    return status == errSecSuccess ? 0 : 5;
}
