/* splunk-logger.c - Simple CLI utility to send messages to Splunk via S2S protocol
 *
 * Usage: splunk-logger [options] <message>
 *
 * Copyright (c) 2025 Mike Dickey
 * Licensed under the Apache License, Version 2.0
 */

#include "s2s.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>

static void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [OPTIONS] <message>\n", progname);
    fprintf(stderr, "\nSend a single message to Splunk indexer via S2S protocol.\n");
    fprintf(stderr, "\nRequired:\n");
    fprintf(stderr, "  -H, --host=HOST          Splunk indexer hostname or IP\n");
    fprintf(stderr, "\nOptional:\n");
    fprintf(stderr, "  -p, --port=PORT          Splunk S2S port (default: 9997)\n");
    fprintf(stderr, "  -i, --index=INDEX        Target Splunk index\n");
    fprintf(stderr, "  -s, --source=SOURCE      Source field\n");
    fprintf(stderr, "  -t, --sourcetype=TYPE    Sourcetype field (default: syslog)\n");
    fprintf(stderr, "  -f, --field=KEY=VALUE    Add custom field (can be used multiple times)\n");
    fprintf(stderr, "  -T, --tls                Enable TLS encryption\n");
    fprintf(stderr, "  -V, --tls-verify         Enable TLS certificate verification\n");
    fprintf(stderr, "      --tls-no-verify      Disable TLS certificate verification\n");
    fprintf(stderr, "      --ca-file=FILE       CA certificate file (PEM)\n");
    fprintf(stderr, "      --cert-file=FILE     Client certificate file (PEM)\n");
    fprintf(stderr, "      --key-file=FILE      Client private key file (PEM)\n");
    fprintf(stderr, "  -h, --help               Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -H splunk.example.com \"Test message\"\n", progname);
    fprintf(stderr, "  %s -H 192.168.1.100 -i main -t syslog \"Error occurred\"\n", progname);
    fprintf(stderr, "  %s -H splunk.local -f severity=high -f app=myapp \"Alert message\"\n", progname);
    fprintf(stderr, "  %s -H splunk.local -T -V --ca-file=/etc/ssl/ca.pem \"Secure message\"\n", progname);
    fprintf(stderr, "  echo \"Log entry\" | %s -H splunk.local\n", progname);
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
    const char *host = NULL;
    int port = 9997;
    const char *index = NULL;
    const char *source = NULL;
    const char *sourcetype = "syslog";
    const char *message = NULL;

    int use_tls = 0;
    int tls_verify = 0; /* 0 = no verify, 1 = verify peer, 2 = verify required */
    const char *ca_file = NULL;
    const char *cert_file = NULL;
    const char *key_file = NULL;

    /* Storage for custom fields */
    const char *custom_fields[S2S_MAX_FIELDS];
    int custom_field_count = 0;

    s2s_tls_config_t tls_config;
    s2s_conn_t *conn = NULL;
    s2s_event_t event = {0};
    s2s_error_t err;
    char hostname[256];

    static struct option long_options[] = {{"host", required_argument, 0, 'H'},
                                           {"port", required_argument, 0, 'p'},
                                           {"index", required_argument, 0, 'i'},
                                           {"source", required_argument, 0, 's'},
                                           {"sourcetype", required_argument, 0, 't'},
                                           {"field", required_argument, 0, 'f'},
                                           {"tls", no_argument, 0, 'T'},
                                           {"tls-verify", no_argument, 0, 'V'},
                                           {"tls-no-verify", no_argument, 0, 'N'},
                                           {"ca-file", required_argument, 0, 'C'},
                                           {"cert-file", required_argument, 0, 'E'},
                                           {"key-file", required_argument, 0, 'K'},
                                           {"help", no_argument, 0, 'h'},
                                           {0, 0, 0, 0}};

    /* Parse command line options */
    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "H:p:i:s:t:f:TVh", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'H':
            host = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
                return 1;
            }
            break;
        case 'i':
            index = optarg;
            break;
        case 's':
            source = optarg;
            break;
        case 't':
            sourcetype = optarg;
            break;
        case 'f':
            if (custom_field_count >= S2S_MAX_FIELDS) {
                fprintf(stderr, "Error: Too many custom fields (max: %d)\n", S2S_MAX_FIELDS);
                return 1;
            }
            /* Validate field format (key=value) */
            if (strchr(optarg, '=') == NULL) {
                fprintf(stderr, "Error: Invalid field format '%s' (expected: key=value)\n", optarg);
                return 1;
            }
            custom_fields[custom_field_count++] = optarg;
            break;
        case 'T':
            use_tls = 1;
            break;
        case 'V':
            tls_verify = 1;
            break;
        case 'N':
            tls_verify = 0;
            break;
        case 'C':
            ca_file = optarg;
            break;
        case 'E':
            cert_file = optarg;
            break;
        case 'K':
            key_file = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Check required arguments */
    if (host == NULL) {
        fprintf(stderr, "Error: --host is required\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Get message from command line or stdin */
    if (optind < argc) {
        /* Message from command line arguments */
        message = argv[optind];
    } else {
        /* Read message from stdin */
        static char buffer[65536];
        size_t len = 0;
        ssize_t nread;

        while (len < sizeof(buffer) - 1 && (nread = read(STDIN_FILENO, buffer + len, sizeof(buffer) - len - 1)) > 0) {
            len += nread;
        }

        if (len == 0) {
            fprintf(stderr, "Error: No message provided (use argument or stdin)\n");
            return 1;
        }

        buffer[len] = '\0';
        /* Remove trailing newline if present */
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        message = buffer;
    }

    /* Get hostname for source if not specified */
    if (source == NULL) {
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            hostname[sizeof(hostname) - 1] = '\0';
            source = hostname;
        } else {
            source = "unknown";
        }
    }

    /* Setup TLS if requested */
    if (use_tls) {
        s2s_tls_config_init(&tls_config);
        tls_config.enabled = 1;

        if (tls_verify) {
            tls_config.verify_mode = S2S_TLS_VERIFY_PEER;
        } else {
            tls_config.verify_mode = S2S_TLS_VERIFY_NONE;
        }

        tls_config.ca_file = ca_file;
        tls_config.cert_file = cert_file;
        tls_config.key_file = key_file;

        /* Initialize TLS library */
        s2s_tls_init();
    }

    /* Connect to Splunk */
    fprintf(stderr, "Connecting to %s:%d...\n", host, port);

    if (use_tls) {
        conn = s2s_connect_tls(host, port, &tls_config);
    } else {
        conn = s2s_connect(host, port);
    }

    if (conn == NULL) {
        fprintf(stderr, "Error: Failed to connect to %s:%d\n", host, port);
        if (use_tls) {
            s2s_tls_cleanup();
        }
        return 1;
    }

    fprintf(stderr, "Connected%s\n", s2s_is_tls(conn) ? " (TLS)" : "");

    /* Setup event */
    event.raw = message;
    event.timestamp = time(NULL);
    event.host = source;
    event.source = source;
    event.sourcetype = sourcetype;
    event.index = index;

    /* Add custom fields */
    for (int i = 0; i < custom_field_count; i++) {
        /* Parse field (format: key=value) */
        char *field_copy = strdup(custom_fields[i]);
        if (field_copy == NULL) {
            fprintf(stderr, "Error: Out of memory\n");
            s2s_close(conn);
            if (use_tls) {
                s2s_tls_cleanup();
            }
            return 1;
        }

        char *equals = strchr(field_copy, '=');
        if (equals == NULL) {
            /* Should not happen as we validated earlier */
            fprintf(stderr, "Error: Invalid field format\n");
            free(field_copy);
            s2s_close(conn);
            if (use_tls) {
                s2s_tls_cleanup();
            }
            return 1;
        }

        *equals = '\0';
        const char *key = field_copy;
        const char *value = equals + 1;

        fprintf(stderr, "Adding field '%s' with value '%s'\n", key, value);
        if (s2s_event_add_field(&event, key, value) != 0) {
            s2s_close(conn);
            if (use_tls) {
                s2s_tls_cleanup();
            }
            return 1;
        }

    }

    /* Send event */
    fprintf(stderr, "Sending message...\n");
    err = s2s_send(conn, &event);

    if (err != S2S_OK) {
        fprintf(stderr, "Error: Failed to send message: %s\n", s2s_strerror(err));
        s2s_close(conn);
        if (use_tls) {
            s2s_tls_cleanup();
        }
        return 1;
    }

    fprintf(stderr, "Message sent successfully!\n");

    /* Print event details */
    fprintf(stderr, "\nEvent details:\n");
    fprintf(stderr, "  Host:       %s\n", event.host);
    fprintf(stderr, "  Source:     %s\n", event.source);
    fprintf(stderr, "  Sourcetype: %s\n", event.sourcetype);
    if (event.index) {
        fprintf(stderr, "  Index:      %s\n", event.index);
    }
    fprintf(stderr, "  Timestamp:  %ld\n", (long)event.timestamp);
    if (event.field_count > 0) {
        fprintf(stderr, "  Fields:\n");
        for (int i = 0; i < event.field_count; i++) {
            fprintf(stderr, "    %s: %s\n", event.fields[i].key, event.fields[i].value);
        }
    }
    fprintf(stderr, "  Message:    %s\n", event.raw);

    /* Cleanup */
    s2s_close(conn);
    if (use_tls) {
        s2s_tls_cleanup();
    }

    return 0;
}
