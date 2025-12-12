/* s2s_test.c - Test program for S2S library
 *
 * Usage: ./s2s_test <splunk-host> [port]
 *
 * Copyright (c) 2025 Mike Dickey
 * Licensed under the Apache License, Version 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "s2s.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <splunk-host> [port] [count]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  splunk-host  Splunk indexer hostname or IP\n");
    fprintf(stderr, "  port         S2S port (default: 9997)\n");
    fprintf(stderr, "  count        Number of test messages to send (default: 10)\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *host;
    int port = 9997;
    int count = 10;
    s2s_conn_t *conn;
    s2s_error_t err;
    int i;
    char msgbuf[256];

    if (argc < 2) {
        usage(argv[0]);
    }

    host = argv[1];
    if (argc >= 3) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[2]);
            return 1;
        }
    }
    if (argc >= 4) {
        count = atoi(argv[3]);
        if (count <= 0) {
            fprintf(stderr, "Invalid count: %s\n", argv[3]);
            return 1;
        }
    }

    printf("Connecting to %s:%d...\n", host, port);

    conn = s2s_connect(host, port);
    if (conn == NULL) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        return 1;
    }

    printf("Connected! Sending %d test messages...\n", count);

    for (i = 0; i < count; i++) {
        s2s_event_t event = {0};
        time_t now = time(NULL);

        snprintf(msgbuf, sizeof(msgbuf), "Test message %d/%d from s2s_test at %s", i + 1, count, ctime(&now));
        /* Remove trailing newline from ctime */
        char *nl = strchr(msgbuf, '\n');
        if (nl)
            *nl = '\0';

        event.raw = msgbuf;
        event.timestamp = now;
        event.host = "s2s-test-host";
        event.source = "s2s_test";
        event.sourcetype = "s2s:test";
        event.index = "main";

        err = s2s_send(conn, &event);
        if (err != S2S_OK) {
            fprintf(stderr, "Send failed: %s\n", s2s_strerror(err));
            s2s_close(conn);
            return 1;
        }

        printf("  Sent message %d/%d\n", i + 1, count);

        /* Small delay between messages */
        if (i < count - 1) {
            usleep(100000); /* 100ms */
        }
    }

    printf("Done! Closing connection.\n");
    s2s_close(conn);

    printf("\nCheck Splunk for messages:\n");
    printf("  index=main sourcetype=\"s2s:test\" source=\"s2s_test\"\n");

    return 0;
}
