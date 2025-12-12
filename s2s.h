/* s2s.h - Splunk S2S Protocol Library
 *
 * A C implementation of the Splunk-to-Splunk (S2S) protocol for
 * forwarding events to Splunk indexers.
 *
 * Copyright (c) 2025 Mike Dickey
 * Licensed under the Apache License, Version 2.0
 */

#ifndef S2S_H
#define S2S_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* S2S Protocol version */
#define S2S_VERSION 3

/* S2S connection handle */
typedef struct s2s_conn s2s_conn_t;

/* S2S message/event */
typedef struct s2s_event {
    const char *raw;        /* Raw event data */
    time_t timestamp;       /* Event timestamp (0 = current time) */
    const char *host;       /* Host field (optional) */
    const char *source;     /* Source field (optional) */
    const char *sourcetype; /* Sourcetype field (optional) */
    const char *index;      /* Target index (optional) */
} s2s_event_t;

/* TLS verification mode */
typedef enum {
    S2S_TLS_VERIFY_NONE = 0,     /* No certificate verification */
    S2S_TLS_VERIFY_PEER = 1,     /* Verify server certificate */
    S2S_TLS_VERIFY_REQUIRED = 2, /* Require valid certificate */
} s2s_tls_verify_t;

/* TLS configuration */
typedef struct s2s_tls_config {
    int enabled;                  /* Enable TLS (0 = disabled) */
    s2s_tls_verify_t verify_mode; /* Certificate verification mode */
    const char *ca_file;          /* CA certificate file (PEM) */
    const char *ca_path;          /* CA certificate directory */
    const char *cert_file;        /* Client certificate file (PEM) */
    const char *key_file;         /* Client private key file (PEM) */
    const char *ciphers;          /* Cipher suite list (NULL = default) */
    int min_version;              /* Minimum TLS version (0 = default) */
} s2s_tls_config_t;

/* TLS version constants */
#define S2S_TLS_VERSION_DEFAULT 0
#define S2S_TLS_VERSION_TLS1_0 0x0301
#define S2S_TLS_VERSION_TLS1_1 0x0302
#define S2S_TLS_VERSION_TLS1_2 0x0303
#define S2S_TLS_VERSION_TLS1_3 0x0304

/* Error codes */
typedef enum {
    S2S_OK = 0,
    S2S_ERR_CONNECT = -1,
    S2S_ERR_HANDSHAKE = -2,
    S2S_ERR_SEND = -3,
    S2S_ERR_MEMORY = -4,
    S2S_ERR_INVALID = -5,
    S2S_ERR_DISCONNECTED = -6,
    S2S_ERR_TLS_INIT = -7,
    S2S_ERR_TLS_HANDSHAKE = -8,
    S2S_ERR_TLS_CERT = -9,
} s2s_error_t;

/**
 * Initialize TLS library (call once at startup).
 * This is optional - will be called automatically on first TLS connection.
 */
void s2s_tls_init(void);

/**
 * Cleanup TLS library (call once at shutdown).
 */
void s2s_tls_cleanup(void);

/**
 * Initialize a TLS config structure with defaults.
 *
 * @param config  Configuration structure to initialize
 */
void s2s_tls_config_init(s2s_tls_config_t *config);

/**
 * Create a new S2S connection to a Splunk indexer.
 *
 * @param host   Splunk indexer hostname or IP address
 * @param port   Splunk S2S port (usually 9997)
 * @return       Connection handle, or NULL on failure
 */
s2s_conn_t *s2s_connect(const char *host, int port);

/**
 * Create a new S2S connection with TLS support.
 *
 * @param host       Splunk indexer hostname or IP address
 * @param port       Splunk S2S port (usually 9997)
 * @param tls_config TLS configuration (NULL for no TLS)
 * @return           Connection handle, or NULL on failure
 */
s2s_conn_t *s2s_connect_tls(const char *host, int port, const s2s_tls_config_t *tls_config);

/**
 * Close an S2S connection and free resources.
 *
 * @param conn   Connection handle
 */
void s2s_close(s2s_conn_t *conn);

/**
 * Check if connection uses TLS.
 *
 * @param conn   Connection handle
 * @return       1 if TLS enabled, 0 if not
 */
int s2s_is_tls(s2s_conn_t *conn);

/**
 * Check if connection is active.
 *
 * @param conn   Connection handle
 * @return       1 if connected, 0 if not
 */
int s2s_is_connected(s2s_conn_t *conn);

/**
 * Send an event to Splunk.
 *
 * @param conn   Connection handle
 * @param event  Event to send
 * @return       S2S_OK on success, error code on failure
 */
s2s_error_t s2s_send(s2s_conn_t *conn, const s2s_event_t *event);

/**
 * Send a simple string event to Splunk.
 *
 * @param conn       Connection handle
 * @param raw        Raw event string
 * @param index      Target index (can be NULL)
 * @param sourcetype Sourcetype (can be NULL, defaults to "syslog")
 * @return           S2S_OK on success, error code on failure
 */
s2s_error_t s2s_send_raw(s2s_conn_t *conn, const char *raw, const char *index, const char *sourcetype);

/**
 * Get error message for an error code.
 *
 * @param err    Error code
 * @return       Error message string
 */
const char *s2s_strerror(s2s_error_t err);

/**
 * Get the file descriptor for the connection (for select/poll).
 *
 * @param conn   Connection handle
 * @return       File descriptor, or -1 if not connected
 */
int s2s_get_fd(s2s_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* S2S_H */
