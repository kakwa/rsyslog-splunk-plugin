/* test_tls.c - Simple test to verify TLS API is working */

#include <stdio.h>
#include <string.h>
#include "s2s.h"

int main(void) {
    s2s_tls_config_t tls_config;
    
    printf("Testing S2S TLS API...\n\n");
    
    /* Test 1: TLS config initialization */
    printf("1. Testing s2s_tls_config_init()...\n");
    s2s_tls_config_init(&tls_config);
    
    if (tls_config.enabled == 0 && 
        tls_config.verify_mode == S2S_TLS_VERIFY_PEER &&
        tls_config.min_version == S2S_TLS_VERSION_DEFAULT) {
        printf("   ✓ TLS config initialized correctly\n");
    } else {
        printf("   ✗ TLS config initialization failed\n");
        return 1;
    }
    
    /* Test 2: TLS init/cleanup */
    printf("\n2. Testing s2s_tls_init() and s2s_tls_cleanup()...\n");
    s2s_tls_init();
    printf("   ✓ TLS library initialized\n");
    s2s_tls_cleanup();
    printf("   ✓ TLS library cleaned up\n");
    
    /* Test 3: Error messages */
    printf("\n3. Testing TLS error messages...\n");
    const char *err1 = s2s_strerror(S2S_ERR_TLS_INIT);
    const char *err2 = s2s_strerror(S2S_ERR_TLS_HANDSHAKE);
    const char *err3 = s2s_strerror(S2S_ERR_TLS_CERT);
    
    if (strstr(err1, "TLS") && strstr(err2, "TLS") && strstr(err3, "TLS")) {
        printf("   ✓ TLS error messages: '%s', '%s', '%s'\n", err1, err2, err3);
    } else {
        printf("   ✗ TLS error messages incorrect\n");
        return 1;
    }
    
    /* Test 4: TLS version constants */
    printf("\n4. Testing TLS version constants...\n");
    printf("   TLS 1.0: 0x%04x\n", S2S_TLS_VERSION_TLS1_0);
    printf("   TLS 1.1: 0x%04x\n", S2S_TLS_VERSION_TLS1_1);
    printf("   TLS 1.2: 0x%04x\n", S2S_TLS_VERSION_TLS1_2);
    printf("   TLS 1.3: 0x%04x\n", S2S_TLS_VERSION_TLS1_3);
    
    if (S2S_TLS_VERSION_TLS1_2 == 0x0303 && S2S_TLS_VERSION_TLS1_3 == 0x0304) {
        printf("   ✓ TLS version constants correct\n");
    } else {
        printf("   ✗ TLS version constants incorrect\n");
        return 1;
    }
    
    /* Test 5: Connection without TLS (should work even without server) */
    printf("\n5. Testing plain connection API...\n");
    s2s_conn_t *conn = s2s_connect("nonexistent.example.com", 9997);
    if (conn == NULL) {
        printf("   ✓ Connection failed as expected (no server)\n");
    } else {
        printf("   ✗ Unexpected connection success\n");
        s2s_close(conn);
        return 1;
    }
    
    /* Test 6: TLS connection API (should fail without server) */
    printf("\n6. Testing TLS connection API...\n");
    tls_config.enabled = 1;
    tls_config.verify_mode = S2S_TLS_VERIFY_NONE;
    tls_config.ca_file = NULL;
    tls_config.cert_file = NULL;
    tls_config.key_file = NULL;
    
    conn = s2s_connect_tls("nonexistent.example.com", 9997, &tls_config);
    if (conn == NULL) {
        printf("   ✓ TLS connection failed as expected (no server)\n");
    } else {
        printf("   ✗ Unexpected TLS connection success\n");
        s2s_close(conn);
        return 1;
    }
    
    printf("\n=== All TLS API tests passed! ===\n");
    return 0;
}


