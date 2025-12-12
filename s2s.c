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
#define KEY_HOST "host"
#define KEY_SOURCE "source"
#define KEY_SOURCETYPE "sourcetype"
#define KEY_INDEX "_MetaData:Index"
#define KEY_DONE "_done"

/* Connection structure */
struct s2s_conn {
    int fd;
    int connected;
    char *host;
    int port;
#ifdef HAVE_OPENSSL
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int tls_enabled;
#endif
};

/* -------------------- Internal Helpers -------------------- */

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
static int conn_write_be32(s2s_conn_t *conn, uint32_t val) {
    unsigned char buf[4];
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
    return conn_write_all(conn, buf, 4);
}

/* Write a length-prefixed string */
static int conn_write_string(s2s_conn_t *conn, const char *str) {
    uint32_t len = str ? (uint32_t)strlen(str) : 0;
    if (conn_write_be32(conn, len) != 0)
        return -1;
    if (len > 0) {
        if (conn_write_all(conn, str, len) != 0)
            return -1;
    }
    return 0;
}

/* Write a key-value pair */
static int conn_write_kv(s2s_conn_t *conn, const char *key, const char *value) {
    if (conn_write_string(conn, key) != 0)
        return -1;
    if (conn_write_string(conn, value) != 0)
        return -1;
    return 0;
}

/* Perform S2S handshake */
static int do_handshake(s2s_conn_t *conn) {
    char signature[S2S_SIGNATURE_LEN];
    char servername[S2S_SERVERNAME_LEN];
    char mgmtport[S2S_MGMTPORT_LEN];
    char hostname[256];

    /* Prepare signature */
    memset(signature, 0, S2S_SIGNATURE_LEN);
    strncpy(signature, S2S_SIGNATURE_V3, S2S_SIGNATURE_LEN - 1);

    /* Prepare server name (our hostname) */
    memset(servername, 0, S2S_SERVERNAME_LEN);
    hostname[sizeof(hostname) - 1] = '\0';
    if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
        snprintf(servername, S2S_SERVERNAME_LEN, "%s", hostname);
    } else {
        snprintf(servername, S2S_SERVERNAME_LEN, "s2s-client");
    }

    /* Prepare management port (not used but required) */
    memset(mgmtport, 0, S2S_MGMTPORT_LEN);
    strncpy(mgmtport, "8089", S2S_MGMTPORT_LEN - 1);

    /* Send handshake */
    if (conn_write_all(conn, signature, S2S_SIGNATURE_LEN) != 0)
        return -1;
    if (conn_write_all(conn, servername, S2S_SERVERNAME_LEN) != 0)
        return -1;
    if (conn_write_all(conn, mgmtport, S2S_MGMTPORT_LEN) != 0)
        return -1;

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

s2s_error_t s2s_send(s2s_conn_t *conn, const s2s_event_t *event) {
    uint32_t field_count = 0;
    char timebuf[32];
    time_t ts;

    if (conn == NULL || !conn->connected) {
        return S2S_ERR_DISCONNECTED;
    }

    if (event == NULL || event->raw == NULL) {
        return S2S_ERR_INVALID;
    }

    /* Count fields we'll send */
    field_count = 2; /* _raw and _time are always sent */
    if (event->host && event->host[0])
        field_count++;
    if (event->source && event->source[0])
        field_count++;
    if (event->sourcetype && event->sourcetype[0])
        field_count++;
    if (event->index && event->index[0])
        field_count++;
    field_count++; /* _done marker */

    /* Write channel ID (0) */
    if (conn_write_be32(conn, 0) != 0)
        goto send_error;

    /* Write field count */
    if (conn_write_be32(conn, field_count) != 0)
        goto send_error;

    /* Write _raw */
    if (conn_write_kv(conn, KEY_RAW, event->raw) != 0)
        goto send_error;

    /* Write _time */
    ts = event->timestamp > 0 ? event->timestamp : time(NULL);
    snprintf(timebuf, sizeof(timebuf), "%ld", (long)ts);
    if (conn_write_kv(conn, KEY_TIME, timebuf) != 0)
        goto send_error;

    /* Write optional fields */
    if (event->host && event->host[0]) {
        if (conn_write_kv(conn, KEY_HOST, event->host) != 0)
            goto send_error;
    }

    if (event->source && event->source[0]) {
        if (conn_write_kv(conn, KEY_SOURCE, event->source) != 0)
            goto send_error;
    }

    if (event->sourcetype && event->sourcetype[0]) {
        if (conn_write_kv(conn, KEY_SOURCETYPE, event->sourcetype) != 0)
            goto send_error;
    }

    if (event->index && event->index[0]) {
        if (conn_write_kv(conn, KEY_INDEX, event->index) != 0)
            goto send_error;
    }

    /* Write _done marker (empty value) */
    if (conn_write_kv(conn, KEY_DONE, "") != 0)
        goto send_error;

    return S2S_OK;

send_error:
    conn->connected = 0;
    return S2S_ERR_SEND;
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
