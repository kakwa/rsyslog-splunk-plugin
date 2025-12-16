/* s2s.c - Splunk S2S Protocol Library Implementation
 *
 * Copyright (c) 2025 Mike Dickey
 * Licensed under the Apache License, Version 2.0
 */

#include "s2s.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <pthread.h>

static int s2s_tls_initialized = 0;
static pthread_mutex_t s2s_tls_init_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* S2S Protocol Constants */
#define S2S_SIGNATURE_V3 "--splunk-cooked-mode-v3--"
#define S2S_SIGNATURE_LEN 128
#define S2S_SERVERNAME_LEN 256
#define S2S_MGMTPORT_LEN 16

/* S2S Field Keys */
#define KEY_RAW "_raw"
#define KEY_TIME "_time"
#define KEY_HOST "MetaData:Host"
#define KEY_SOURCE "MetaData:Source"
#define KEY_SOURCETYPE "MetaData:Sourcetype"
#define KEY_INDEX "_MetaData:Index"
#define KEY_DONE "_done"

/* Connection structure */
struct s2s_conn {
    int fd;
    int connected;
    char *host;
    int port;
    char guid[37];          /* Forwarder GUID (UUID) */
    uint32_t event_id;      /* Event sequence counter */
    char capabilities[128]; /* Client capabilities string */
#ifdef HAVE_OPENSSL
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int tls_enabled;
#endif
};

/* -------------------- Internal Helpers -------------------- */

/* Read exactly n bytes (plain socket) */
static int read_all_plain(int fd, void *buf, size_t n) {
    char *p = buf;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t nread = read(fd, p, remaining);
        if (nread <= 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += nread;
        remaining -= nread;
    }
    return 0;
}

/* Write exactly n bytes (plain socket) */
static int write_all_plain(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);
        if (written <= 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += written;
        remaining -= written;
    }
    return 0;
}

#ifdef HAVE_OPENSSL
/* Read exactly n bytes (TLS) */
static int read_all_tls(SSL *ssl, void *buf, size_t n) {
    char *p = buf;
    size_t remaining = n;

    while (remaining > 0) {
        int nread = SSL_read(ssl, p, (int)remaining);
        if (nread <= 0) {
            int err = SSL_get_error(ssl, nread);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            return -1;
        }
        p += nread;
        remaining -= nread;
    }
    return 0;
}

/* Write exactly n bytes (TLS) */
static int write_all_tls(SSL *ssl, const void *buf, size_t n) {
    const char *p = buf;
    size_t remaining = n;

    while (remaining > 0) {
        int written = SSL_write(ssl, p, (int)remaining);
        if (written <= 0) {
            int err = SSL_get_error(ssl, written);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                continue;
            }
            return -1;
        }
        p += written;
        remaining -= written;
    }
    return 0;
}
#endif

/* Read exactly n bytes (auto-select based on connection) */
static int conn_read_all(s2s_conn_t *conn, void *buf, size_t n) {
#ifdef HAVE_OPENSSL
    if (conn->tls_enabled && conn->ssl) {
        return read_all_tls(conn->ssl, buf, n);
    }
#endif
    return read_all_plain(conn->fd, buf, n);
}

/* Write exactly n bytes (auto-select based on connection) */
static int conn_write_all(s2s_conn_t *conn, const void *buf, size_t n) {
#ifdef HAVE_OPENSSL
    if (conn->tls_enabled && conn->ssl) {
        return write_all_tls(conn->ssl, buf, n);
    }
#endif
    return write_all_plain(conn->fd, buf, n);
}

/* Write a 32-bit big-endian integer */
/*
static int conn_write_be32(s2s_conn_t *conn, uint32_t val) {
    unsigned char buf[4];
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
    return conn_write_all(conn, buf, 4);
}
*/

/* Write a length-prefixed string (Splunk format includes null terminator) */
/*
static int conn_write_string(s2s_conn_t *conn, const char *str) {
    // Include null terminator
    uint32_t len = str ? (uint32_t)strlen(str) + 1 : 0;
    if (conn_write_be32(conn, len) != 0)
        return -1;
    if (len > 0) {
        // Write string with null terminator
        if (conn_write_all(conn, str, len) != 0)
            return -1;
    }
    return 0;
}
*/

/* Write a key-value pair */
/*
static int conn_write_kv(s2s_conn_t *conn, const char *key, const char *value) {
    if (conn_write_string(conn, key) != 0)
        return -1;
    if (conn_write_string(conn, value) != 0)
        return -1;
    return 0;
}
*/

/* Buffer writing helpers for batched sends */
static void buf_write_be32(unsigned char **buf, uint32_t val) {
    (*buf)[0] = (val >> 24) & 0xFF;
    (*buf)[1] = (val >> 16) & 0xFF;
    (*buf)[2] = (val >> 8) & 0xFF;
    (*buf)[3] = val & 0xFF;
    *buf += 4;
}

static void buf_write_string(unsigned char **buf, const char *str) {
    uint32_t len = str ? (uint32_t)strlen(str) + 1 : 0;
    buf_write_be32(buf, len);
    if (len > 0) {
        memcpy(*buf, str, len);
        *buf += len;
    }
}

static void buf_write_kv(unsigned char **buf, const char *key, const char *value) {
    buf_write_string(buf, key);
    buf_write_string(buf, value);
}

/* Generate a UUID v4 for the forwarder GUID */
static void generate_guid(char *buf, size_t size) {
    unsigned int r1, r2, r3, r4, r5;

    /* Use time and random for uniqueness */
    srand(time(NULL) ^ getpid());
    r1 = (unsigned int)rand();
    r2 = (unsigned int)rand();
    r3 = (unsigned int)rand();
    r4 = (unsigned int)rand();
    r5 = (unsigned int)rand();

    /* Format as UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx */
    snprintf(buf, size, "%08X-%04X-4%03X-%04X-%08X%04X", r1, r2 & 0xFFFF, r3 & 0xFFF, ((r4 & 0x3FFF) | 0x8000), r5,
             (unsigned int)time(NULL) & 0xFFFF);
}

/* Perform S2S handshake */
static int do_handshake(s2s_conn_t *conn) {
    char handshake[S2S_SIGNATURE_LEN + S2S_SERVERNAME_LEN + S2S_MGMTPORT_LEN];
    char hostname[256];
    char *ptr = handshake;

    /* Prepare signature */
    memset(ptr, 0, S2S_SIGNATURE_LEN);
    strncpy(ptr, S2S_SIGNATURE_V3, S2S_SIGNATURE_LEN - 1);
    ptr += S2S_SIGNATURE_LEN;

    /* Prepare server name (our hostname) */
    memset(ptr, 0, S2S_SERVERNAME_LEN);
    hostname[sizeof(hostname) - 1] = '\0';
    if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
        snprintf(ptr, S2S_SERVERNAME_LEN, "%s", hostname);
    } else {
        snprintf(ptr, S2S_SERVERNAME_LEN, "s2s-client");
    }
    ptr += S2S_SERVERNAME_LEN;

    /* Prepare management port (not used but required) */
    memset(ptr, 0, S2S_MGMTPORT_LEN);
    strncpy(ptr, "8089", S2S_MGMTPORT_LEN - 1);

    /* Send entire handshake in one write (400 bytes) */
    if (conn_write_all(conn, handshake, sizeof(handshake)) != 0)
        return -1;

    return 0;
}

/* Send S2S capabilities negotiation message and read server response */
static int send_capabilities(s2s_conn_t *conn) {
    const char *capabilities = "ack=0;compression=0";
    const char *key = "__s2s_capabilities";
    uint32_t field_count = 1;
    uint32_t msg_size;
    uint32_t total_size;
    unsigned char *buffer;
    unsigned char *ptr;
    uint32_t server_msg_size;
    unsigned char *server_buffer;

    /* Calculate message size */
    msg_size = 4;                             /* field_count field */
    msg_size += 4 + strlen(key) + 1;          /* key */
    msg_size += 4 + strlen(capabilities) + 1; /* value */
    msg_size += 4;                            /* 4-byte null padding */
    msg_size += 4 + 5;                        /* "_raw" trailer */

    total_size = 4 + msg_size;

    /* Allocate buffer */
    buffer = malloc(total_size);
    if (buffer == NULL)
        return -1;

    ptr = buffer;

    /* Build message */
    buf_write_be32(&ptr, msg_size);
    buf_write_be32(&ptr, field_count);
    buf_write_string(&ptr, key);
    buf_write_string(&ptr, capabilities);

    /* Write 4-byte null padding */
    buf_write_be32(&ptr, 0);

    /* Write "_raw" trailer */
    buf_write_string(&ptr, "_raw");

    /* Send client capabilities */
    if (conn_write_all(conn, buffer, total_size) != 0) {
        free(buffer);
        return -1;
    }
    free(buffer);

    /* Read server's capabilities response - this is REQUIRED */
    if (conn_read_all(conn, &server_msg_size, 4) != 0) {
        return -1;
    }
    server_msg_size = ntohl(server_msg_size);

    server_buffer = malloc(server_msg_size);
    if (server_buffer == NULL) {
        return -1;
    }

    if (conn_read_all(conn, server_buffer, server_msg_size) != 0) {
        free(server_buffer);
        return -1;
    }

    free(server_buffer);
    return 0;
}

#ifdef HAVE_OPENSSL
/* Initialize OpenSSL library */
static void ensure_tls_initialized(void) {
    pthread_mutex_lock(&s2s_tls_init_mutex);
    if (!s2s_tls_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        s2s_tls_initialized = 1;
    }
    pthread_mutex_unlock(&s2s_tls_init_mutex);
}

/* Create SSL context from config */
static SSL_CTX *create_ssl_context(const s2s_tls_config_t *config) {
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    ensure_tls_initialized();

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        return NULL;
    }

    /* Set minimum TLS version */
    if (config->min_version > 0) {
        SSL_CTX_set_min_proto_version(ctx, config->min_version);
    } else {
        /* Default to TLS 1.2 minimum */
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    }

    /* Set cipher suites */
    if (config->ciphers) {
        if (SSL_CTX_set_cipher_list(ctx, config->ciphers) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Configure verification */
    switch (config->verify_mode) {
    case S2S_TLS_VERIFY_NONE:
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        break;
    case S2S_TLS_VERIFY_PEER:
    case S2S_TLS_VERIFY_REQUIRED:
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        break;
    }

    /* Load CA certificates */
    if (config->ca_file || config->ca_path) {
        if (SSL_CTX_load_verify_locations(ctx, config->ca_file, config->ca_path) != 1) {
            if (config->verify_mode != S2S_TLS_VERIFY_NONE) {
                SSL_CTX_free(ctx);
                return NULL;
            }
        }
    } else if (config->verify_mode != S2S_TLS_VERIFY_NONE) {
        /* Use default CA store */
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Load client certificate */
    if (config->cert_file) {
        if (SSL_CTX_use_certificate_file(ctx, config->cert_file, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Load client private key */
    if (config->key_file) {
        if (SSL_CTX_use_PrivateKey_file(ctx, config->key_file, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
        /* Verify key matches certificate */
        if (SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

/* Perform TLS handshake */
static int do_tls_handshake(s2s_conn_t *conn, const char *hostname) {
    int ret;

    conn->ssl = SSL_new(conn->ssl_ctx);
    if (conn->ssl == NULL) {
        return -1;
    }

    /* Set socket */
    if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return -1;
    }

    /* Set hostname for SNI */
    SSL_set_tlsext_host_name(conn->ssl, hostname);

    /* Set hostname for certificate verification */
    SSL_set1_host(conn->ssl, hostname);

    /* Perform handshake */
    ret = SSL_connect(conn->ssl);
    if (ret != 1) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return -1;
    }

    conn->tls_enabled = 1;
    return 0;
}
#endif /* HAVE_OPENSSL */

/* -------------------- Public API -------------------- */

void s2s_tls_init(void) {
#ifdef HAVE_OPENSSL
    ensure_tls_initialized();
#endif
}

void s2s_tls_cleanup(void) {
#ifdef HAVE_OPENSSL
    pthread_mutex_lock(&s2s_tls_init_mutex);
    if (s2s_tls_initialized) {
        EVP_cleanup();
        ERR_free_strings();
        s2s_tls_initialized = 0;
    }
    pthread_mutex_unlock(&s2s_tls_init_mutex);
#endif
}

void s2s_tls_config_init(s2s_tls_config_t *config) {
    if (config == NULL)
        return;
    memset(config, 0, sizeof(*config));
    config->enabled = 0;
    config->verify_mode = S2S_TLS_VERIFY_PEER;
    config->min_version = S2S_TLS_VERSION_DEFAULT;
}

/* Internal: establish TCP connection */
static int establish_tcp_connection(s2s_conn_t *conn, const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    char portstr[16];
    int fd = -1;

    /* Resolve address */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        return -1;
    }

    /* Try each address */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        /* Set TCP_NODELAY for better latency */
        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* Success */
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd == -1) {
        return -1;
    }

    conn->fd = fd;
    return 0;
}

s2s_conn_t *s2s_connect(const char *host, int port) {
    return s2s_connect_tls(host, port, NULL);
}

s2s_conn_t *s2s_connect_tls(const char *host, int port, const s2s_tls_config_t *tls_config) {
    s2s_conn_t *conn;

    if (host == NULL || port <= 0) {
        return NULL;
    }

    /* Allocate connection structure */
    conn = calloc(1, sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->host = strdup(host);
    conn->port = port;
    conn->fd = -1;
    conn->connected = 0;
    conn->event_id = 0;

    /* Generate forwarder GUID */
    generate_guid(conn->guid, sizeof(conn->guid));

    /* Set client capabilities */
    snprintf(conn->capabilities, sizeof(conn->capabilities),
             "cli_can_rcv_hb=1;compression=0;pl=7;request_certificate=1;v4=1");

#ifdef HAVE_OPENSSL
    conn->ssl_ctx = NULL;
    conn->ssl = NULL;
    conn->tls_enabled = 0;
#endif

    if (conn->host == NULL) {
        free(conn);
        return NULL;
    }

    /* Establish TCP connection */
    if (establish_tcp_connection(conn, host, port) != 0) {
        free(conn->host);
        free(conn);
        return NULL;
    }

#ifdef HAVE_OPENSSL
    /* Setup TLS if configured */
    if (tls_config != NULL && tls_config->enabled) {
        conn->ssl_ctx = create_ssl_context(tls_config);
        if (conn->ssl_ctx == NULL) {
            close(conn->fd);
            free(conn->host);
            free(conn);
            return NULL;
        }

        if (do_tls_handshake(conn, host) != 0) {
            SSL_CTX_free(conn->ssl_ctx);
            close(conn->fd);
            free(conn->host);
            free(conn);
            return NULL;
        }
    }
#else
    /* TLS requested but not compiled in */
    if (tls_config != NULL && tls_config->enabled) {
        close(conn->fd);
        free(conn->host);
        free(conn);
        return NULL;
    }
#endif

    /* Perform S2S handshake */
    if (do_handshake(conn) != 0) {
#ifdef HAVE_OPENSSL
        if (conn->ssl) {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
        }
        if (conn->ssl_ctx) {
            SSL_CTX_free(conn->ssl_ctx);
        }
#endif
        close(conn->fd);
        free(conn->host);
        free(conn);
        return NULL;
    }

    /* Send capabilities negotiation */
    if (send_capabilities(conn) != 0) {
#ifdef HAVE_OPENSSL
        if (conn->ssl) {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
        }
        if (conn->ssl_ctx) {
            SSL_CTX_free(conn->ssl_ctx);
        }
#endif
        close(conn->fd);
        free(conn->host);
        free(conn);
        return NULL;
    }

    conn->connected = 1;
    return conn;
}

void s2s_close(s2s_conn_t *conn) {
    if (conn == NULL)
        return;

#ifdef HAVE_OPENSSL
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
    }
#endif

    if (conn->fd >= 0) {
        close(conn->fd);
    }
    free(conn->host);
    free(conn);
}

int s2s_is_tls(s2s_conn_t *conn) {
#ifdef HAVE_OPENSSL
    return conn != NULL && conn->tls_enabled;
#else
    (void)conn;
    return 0;
#endif
}

int s2s_is_connected(s2s_conn_t *conn) {
    return conn != NULL && conn->connected;
}

int s2s_get_fd(s2s_conn_t *conn) {
    if (conn == NULL)
        return -1;
    return conn->fd;
}

int s2s_event_add_field(s2s_event_t *event, const char *key, const char *value) {
    if (event == NULL || key == NULL || value == NULL) {
        return -1;
    }
    if (event->field_count >= S2S_MAX_FIELDS) {
        return -1; /* Field array is full */
    }
    event->fields[event->field_count].key = key;
    event->fields[event->field_count].value = value;
    event->field_count++;
    return 0;
}

s2s_error_t s2s_send(s2s_conn_t *conn, const s2s_event_t *event) {
    uint32_t field_count = 0;
    uint32_t msg_size = 0;
    uint32_t total_size = 0;
    char timebuf[32];
    char eventid_buf[32];
    char hostbuf[512];
    char sourcebuf[512];
    char sourcetypebuf[512];
    time_t ts;
    unsigned char *buffer = NULL;
    unsigned char *ptr;
    const char *lat_chained = "{\"green\":{\"count\":0}}";
    const char *lat_color = "green";

    if (conn == NULL || !conn->connected) {
        return S2S_ERR_DISCONNECTED;
    }

    if (event == NULL || event->raw == NULL) {
        return S2S_ERR_INVALID;
    }

    /* Count fields we'll send */
    field_count = 2; /* _raw and _time are always sent */
    field_count++;   /* _done marker */
    field_count++;   /* _guid */
    field_count++;   /* __s2s_capabilities */
    field_count++;   /* __s2s_eventId */
    field_count++;   /* _ingLatColor */
    field_count++;   /* _ingLatChained */

    if (event->index && event->index[0])
        field_count++;
    if (event->host && event->host[0])
        field_count++;
    if (event->source && event->source[0])
        field_count++;
    if (event->sourcetype && event->sourcetype[0])
        field_count++;

    /* Count custom fields */
    for (int i = 0; i < event->field_count; i++) {
        if (event->fields[i].key && event->fields[i].key[0] && event->fields[i].value && event->fields[i].value[0]) {
            field_count++;
        }
    }

    /* Prepare timestamp and event ID */
    ts = event->timestamp > 0 ? event->timestamp : time(NULL);
    snprintf(timebuf, sizeof(timebuf), "%ld", (long)ts);
    snprintf(eventid_buf, sizeof(eventid_buf), "%u", conn->event_id);

    /* Calculate message size (all bytes after the size field itself) */
    msg_size = 4; /* field_count field */

    /* _raw field (always first) */
    msg_size += 4 + strlen(KEY_RAW) + 1;    /* key length + key + null */
    msg_size += 4 + strlen(event->raw) + 1; /* val length + val + null */

    /* _done marker */
    msg_size += 4 + strlen(KEY_DONE) + 1; /* key length + key + null */
    msg_size += 4 + strlen(KEY_DONE) + 1; /* val length + val + null */

    /* _time field */
    msg_size += 4 + strlen(KEY_TIME) + 1; /* key length + key + null */
    msg_size += 4 + strlen(timebuf) + 1;  /* val length + val + null */

    /* _guid field */
    msg_size += 4 + 6; /* "_guid" + null */
    msg_size += 4 + strlen(conn->guid) + 1;

    /* Optional metadata fields - format with proper prefixes */
    hostbuf[0] = '\0';
    sourcebuf[0] = '\0';
    sourcetypebuf[0] = '\0';

    if (event->index && event->index[0]) {
        msg_size += 4 + strlen(KEY_INDEX) + 1;
        msg_size += 4 + strlen(event->index) + 1;
    }

    if (event->host && event->host[0]) {
        snprintf(hostbuf, sizeof(hostbuf), "host::%s", event->host);
        msg_size += 4 + strlen(KEY_HOST) + 1;
        msg_size += 4 + strlen(hostbuf) + 1;
    }

    if (event->source && event->source[0]) {
        snprintf(sourcebuf, sizeof(sourcebuf), "source::%s", event->source);
        msg_size += 4 + strlen(KEY_SOURCE) + 1;
        msg_size += 4 + strlen(sourcebuf) + 1;
    }

    if (event->sourcetype && event->sourcetype[0]) {
        snprintf(sourcetypebuf, sizeof(sourcetypebuf), "sourcetype::%s", event->sourcetype);
        msg_size += 4 + strlen(KEY_SOURCETYPE) + 1;
        msg_size += 4 + strlen(sourcetypebuf) + 1;
    }

    /* Custom fields */
    for (int i = 0; i < event->field_count; i++) {
        if (event->fields[i].key && event->fields[i].key[0] && event->fields[i].value && event->fields[i].value[0]) {
            msg_size += 4 + strlen(event->fields[i].key) + 1;
            msg_size += 4 + strlen(event->fields[i].value) + 1;
        }
    }

    /* __s2s_capabilities */
    msg_size += 4 + 20; /* "__s2s_capabilities" + null */
    msg_size += 4 + strlen(conn->capabilities) + 1;

    /* _ingLatChained */
    msg_size += 4 + 16; /* "_ingLatChained" + null */
    msg_size += 4 + strlen(lat_chained) + 1;

    /* _ingLatColor */
    msg_size += 4 + 14; /* "_ingLatColor" + null */
    msg_size += 4 + strlen(lat_color) + 1;

    /* __s2s_eventId */
    msg_size += 4 + 15; /* "__s2s_eventId" + null */
    msg_size += 4 + strlen(eventid_buf) + 1;

    /* 4-byte null padding */
    msg_size += 4;

    /* "_raw" trailer string */
    msg_size += 4 + strlen(KEY_RAW) + 1; /* length + "_raw" + null */

    /* Total buffer size = size field + message */
    total_size = 4 + msg_size;

    /* Allocate buffer for entire message */
    buffer = malloc(total_size);
    if (buffer == NULL) {
        return S2S_ERR_MEMORY;
    }

    ptr = buffer;

    /* Write message size */
    buf_write_be32(&ptr, msg_size);

    /* Write field count */
    buf_write_be32(&ptr, field_count);

    /* Write _raw FIRST (matches actual Splunk pcap) */
    buf_write_kv(&ptr, KEY_RAW, event->raw);

    /* Write _done marker immediately after _raw */
    buf_write_kv(&ptr, KEY_DONE, KEY_DONE);

    /* Write _time */
    buf_write_kv(&ptr, KEY_TIME, timebuf);

    /* Write _guid */
    buf_write_kv(&ptr, "_guid", conn->guid);

    /* Write index (BEFORE capabilities in pcap order) */
    if (event->index && event->index[0]) {
        buf_write_kv(&ptr, KEY_INDEX, event->index);
    }

    /* Write __s2s_capabilities (BEFORE sourcetype in pcap order) */
    buf_write_kv(&ptr, "__s2s_capabilities", conn->capabilities);

    /* Write sourcetype (BEFORE source in pcap order) */
    if (event->sourcetype && event->sourcetype[0]) {
        buf_write_kv(&ptr, KEY_SOURCETYPE, sourcetypebuf);
    }

    /* Write _ingLatChained (BEFORE source in pcap order) */
    buf_write_kv(&ptr, "_ingLatChained", lat_chained);

    /* Write source (BEFORE host in pcap order) */
    if (event->source && event->source[0]) {
        buf_write_kv(&ptr, KEY_SOURCE, sourcebuf);
    }

    /* Write host */
    if (event->host && event->host[0]) {
        buf_write_kv(&ptr, KEY_HOST, hostbuf);
    }

    /* Write custom fields */
    for (int i = 0; i < event->field_count; i++) {
        if (event->fields[i].key && event->fields[i].key[0] && event->fields[i].value && event->fields[i].value[0]) {
            buf_write_kv(&ptr, event->fields[i].key, event->fields[i].value);
        }
    }

    /* Write _ingLatColor */
    buf_write_kv(&ptr, "_ingLatColor", lat_color);

    /* Write __s2s_eventId */
    buf_write_kv(&ptr, "__s2s_eventId", eventid_buf);

    /* Write 4-byte null padding */
    buf_write_be32(&ptr, 0);

    /* Write "_raw" trailer string */
    buf_write_string(&ptr, KEY_RAW);

    /* Increment event ID for next message */
    conn->event_id++;

    /* Send entire message in one write */
    if (conn_write_all(conn, buffer, total_size) != 0) {
        free(buffer);
        conn->connected = 0;
        return S2S_ERR_SEND;
    }

    free(buffer);
    return S2S_OK;
}

s2s_error_t s2s_send_raw(s2s_conn_t *conn, const char *raw, const char *index, const char *sourcetype) {
    s2s_event_t event = {0};

    event.raw = raw;
    event.timestamp = 0; /* Use current time */
    event.index = index;
    event.sourcetype = sourcetype ? sourcetype : "syslog";

    return s2s_send(conn, &event);
}

const char *s2s_strerror(s2s_error_t err) {
    switch (err) {
    case S2S_OK:
        return "Success";
    case S2S_ERR_CONNECT:
        return "Connection failed";
    case S2S_ERR_HANDSHAKE:
        return "Handshake failed";
    case S2S_ERR_SEND:
        return "Send failed";
    case S2S_ERR_MEMORY:
        return "Memory allocation failed";
    case S2S_ERR_INVALID:
        return "Invalid parameter";
    case S2S_ERR_DISCONNECTED:
        return "Not connected";
    case S2S_ERR_TLS_INIT:
        return "TLS initialization failed";
    case S2S_ERR_TLS_HANDSHAKE:
        return "TLS handshake failed";
    case S2S_ERR_TLS_CERT:
        return "TLS certificate error";
    default:
        return "Unknown error";
    }
}
