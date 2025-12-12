/* omsplunks2s.c
 *
 * Rsyslog output module for Splunk S2S (Splunk-to-Splunk) protocol.
 * Forwards syslog messages to a Splunk indexer using the native S2S protocol.
 *
 * Copyright (c) 2025 Mike Dickey
 * Licensed under the Apache License, Version 2.0
 *
 * Build requirements:
 *   - rsyslog >= 8.x with development headers
 *   - libestr
 *   - OpenSSL (optional, for TLS support)
 *
 * Configuration example (plain):
 *   module(load="omsplunks2s")
 *   *.* action(type="omsplunks2s" server="splunk.local" port="9997" index="main")
 *
 * Configuration example (TLS):
 *   module(load="omsplunks2s")
 *   *.* action(type="omsplunks2s"
 *              server="splunk.local"
 *              port="9997"
 *              index="main"
 *              tls="on"
 *              tls.verify="on"
 *              tls.cacert="/etc/ssl/certs/splunk-ca.pem"
 *              tls.cert="/etc/ssl/certs/client.pem"
 *              tls.key="/etc/ssl/private/client-key.pem")
 */

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"

#include "s2s.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omsplunks2s")

/* Module static data */
DEF_OMOD_STATIC_DATA

/* Instance configuration */
typedef struct _instanceData {
    char *server;
    int port;
    char *index;
    char *host;
    char *source;
    char *sourcetype;
    int reconnect_interval;
    s2s_conn_t *conn;
    pthread_mutex_t mtx;
    time_t last_reconnect;
    /* TLS configuration */
    int tls_enabled;
    int tls_verify;
    char *tls_ca_file;
    char *tls_cert_file;
    char *tls_key_file;
} instanceData;

/* Worker instance data */
typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

/* Configuration parameters */
static struct cnfparamdescr actpdescr[] = {
    {"server", eCmdHdlrGetWord, 0},         {"port", eCmdHdlrInt, 0},         {"index", eCmdHdlrGetWord, 0},
    {"host", eCmdHdlrGetWord, 0},           {"source", eCmdHdlrGetWord, 0},   {"sourcetype", eCmdHdlrGetWord, 0},
    {"reconnect.interval", eCmdHdlrInt, 0}, {"tls", eCmdHdlrBinary, 0},       {"tls.verify", eCmdHdlrBinary, 0},
    {"tls.cacert", eCmdHdlrGetWord, 0},     {"tls.cert", eCmdHdlrGetWord, 0}, {"tls.key", eCmdHdlrGetWord, 0},
};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

/* -------------------- Helper Functions -------------------- */

/* Attempt to connect/reconnect to Splunk */
static int do_connect(instanceData *pData) {
    s2s_tls_config_t tls_config;

    if (pData->conn != NULL) {
        s2s_close(pData->conn);
        pData->conn = NULL;
    }

    /* Setup TLS configuration if enabled */
    if (pData->tls_enabled) {
        s2s_tls_config_init(&tls_config);
        tls_config.enabled = 1;
        tls_config.verify_mode = pData->tls_verify ? S2S_TLS_VERIFY_PEER : S2S_TLS_VERIFY_NONE;
        tls_config.ca_file = pData->tls_ca_file;
        tls_config.cert_file = pData->tls_cert_file;
        tls_config.key_file = pData->tls_key_file;

        pData->conn = s2s_connect_tls(pData->server, pData->port, &tls_config);
    } else {
        pData->conn = s2s_connect(pData->server, pData->port);
    }

    if (pData->conn == NULL) {
        LogError(0, RS_RET_SUSPENDED, "omsplunks2s: failed to connect to %s:%d%s", pData->server, pData->port,
                 pData->tls_enabled ? " (TLS)" : "");
        return -1;
    }

    LogMsg(0, RS_RET_OK, LOG_INFO, "omsplunks2s: connected to %s:%d%s", pData->server, pData->port,
           pData->tls_enabled ? " (TLS)" : "");
    return 0;
}

/* Check connection and reconnect if needed */
static int ensure_connected(instanceData *pData) {
    if (s2s_is_connected(pData->conn)) {
        return 0;
    }

    time_t now = time(NULL);
    if (now - pData->last_reconnect < pData->reconnect_interval) {
        return -1; /* Too soon to retry */
    }

    pData->last_reconnect = now;
    return do_connect(pData);
}

/* -------------------- Rsyslog Module Interface -------------------- */

BEGINcreateInstance CODESTARTcreateInstance pData->server = NULL;
pData->port = 9997;
pData->index = NULL;
pData->host = NULL;
pData->source = NULL;
pData->sourcetype = NULL;
pData->reconnect_interval = 30;
pData->conn = NULL;
pData->last_reconnect = 0;
pData->tls_enabled = 0;
pData->tls_verify = 1;
pData->tls_ca_file = NULL;
pData->tls_cert_file = NULL;
pData->tls_key_file = NULL;
pthread_mutex_init(&pData->mtx, NULL);
ENDcreateInstance

    BEGINcreateWrkrInstance CODESTARTcreateWrkrInstance ENDcreateWrkrInstance

        BEGINfreeInstance CODESTARTfreeInstance pthread_mutex_lock(&pData->mtx);
if (pData->conn != NULL) {
    s2s_close(pData->conn);
    pData->conn = NULL;
}
pthread_mutex_unlock(&pData->mtx);
pthread_mutex_destroy(&pData->mtx);
free(pData->server);
free(pData->index);
free(pData->host);
free(pData->source);
free(pData->sourcetype);
free(pData->tls_ca_file);
free(pData->tls_cert_file);
free(pData->tls_key_file);
ENDfreeInstance

    BEGINfreeWrkrInstance CODESTARTfreeWrkrInstance ENDfreeWrkrInstance

        BEGINdbgPrintInstInfo CODESTARTdbgPrintInstInfo dbgprintf("omsplunks2s:\n");
dbgprintf("\tserver='%s'\n", pData->server ? pData->server : "(null)");
dbgprintf("\tport=%d\n", pData->port);
dbgprintf("\tindex='%s'\n", pData->index ? pData->index : "(null)");
dbgprintf("\tsourcetype='%s'\n", pData->sourcetype ? pData->sourcetype : "(null)");
dbgprintf("\ttls=%d\n", pData->tls_enabled);
dbgprintf("\ttls.verify=%d\n", pData->tls_verify);
dbgprintf("\ttls.cacert='%s'\n", pData->tls_ca_file ? pData->tls_ca_file : "(null)");
dbgprintf("\ttls.cert='%s'\n", pData->tls_cert_file ? pData->tls_cert_file : "(null)");
dbgprintf("\ttls.key='%s'\n", pData->tls_key_file ? pData->tls_key_file : "(null)");
ENDdbgPrintInstInfo

    BEGINtryResume CODESTARTtryResume pthread_mutex_lock(&pWrkrData->pData->mtx);
iRet = ensure_connected(pWrkrData->pData) == 0 ? RS_RET_OK : RS_RET_SUSPENDED;
pthread_mutex_unlock(&pWrkrData->pData->mtx);
ENDtryResume

    BEGINdoAction instanceData *pData;
s2s_event_t event;
s2s_error_t err;
CODESTARTdoAction pData = pWrkrData->pData;

pthread_mutex_lock(&pData->mtx);

/* Ensure we have a connection */
if (ensure_connected(pData) != 0) {
    pthread_mutex_unlock(&pData->mtx);
    ABORT_FINALIZE(RS_RET_SUSPENDED);
}

/* Build event */
memset(&event, 0, sizeof(event));
event.raw = (const char *)ppString[0];
event.timestamp = 0; /* Use current time */
event.host = pData->host;
event.source = pData->source;
event.sourcetype = pData->sourcetype;
event.index = pData->index;

/* Send event */
err = s2s_send(pData->conn, &event);
if (err != S2S_OK) {
    LogError(0, RS_RET_SUSPENDED, "omsplunks2s: send failed: %s", s2s_strerror(err));
    s2s_close(pData->conn);
    pData->conn = NULL;
    pthread_mutex_unlock(&pData->mtx);
    ABORT_FINALIZE(RS_RET_SUSPENDED);
}

pthread_mutex_unlock(&pData->mtx);

finalize_it
    : ENDdoAction

          BEGINisCompatibleWithFeature CODESTARTisCompatibleWithFeature if (eFeat == sFEATURERepeatedMsgReduction)
              iRet = RS_RET_OK;
ENDisCompatibleWithFeature

    BEGINnewActInst struct cnfparamvals *pvals;
int i;
CODESTARTnewActInst if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
}

CODE_STD_STRING_REQUESTnewActInst(1) CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_NO_RQD_TPL_OPTS));
CHKiRet(createInstance(&pData));

for (i = 0; i < actpblk.nParams; ++i) {
    if (!pvals[i].bUsed)
        continue;
    if (!strcmp(actpblk.descr[i].name, "server")) {
        pData->server = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "port")) {
        pData->port = pvals[i].val.d.n;
    } else if (!strcmp(actpblk.descr[i].name, "index")) {
        pData->index = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "host")) {
        pData->host = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "source")) {
        pData->source = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "sourcetype")) {
        pData->sourcetype = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "reconnect.interval")) {
        pData->reconnect_interval = pvals[i].val.d.n;
    } else if (!strcmp(actpblk.descr[i].name, "tls")) {
        pData->tls_enabled = pvals[i].val.d.n;
    } else if (!strcmp(actpblk.descr[i].name, "tls.verify")) {
        pData->tls_verify = pvals[i].val.d.n;
    } else if (!strcmp(actpblk.descr[i].name, "tls.cacert")) {
        pData->tls_ca_file = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "tls.cert")) {
        pData->tls_cert_file = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if (!strcmp(actpblk.descr[i].name, "tls.key")) {
        pData->tls_key_file = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else {
        LogError(0, RS_RET_INTERNAL_ERROR, "omsplunks2s: unknown param '%s'", actpblk.descr[i].name);
    }
}

/* Validate required parameters */
if (pData->server == NULL || pData->server[0] == '\0') {
    LogError(0, RS_RET_CONFIG_ERROR, "omsplunks2s: 'server' parameter is required");
    ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
}

/* Set defaults */
if (pData->sourcetype == NULL) {
    pData->sourcetype = strdup("syslog");
}

/* Attempt initial connection */
if (do_connect(pData) != 0) {
    LogMsg(0, RS_RET_OK, LOG_WARNING, "omsplunks2s: initial connection failed, will retry");
}

CODE_STD_FINALIZERnewActInst cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

    BEGINparseSelectorAct CODESTARTparseSelectorAct CODE_STD_STRING_REQUESTparseSelectorAct(1)
    /* Legacy config not supported - use new-style config only */
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct ENDparseSelectorAct

    BEGINmodExit CODESTARTmodExit ENDmodExit

        BEGINqueryEtryPt CODESTARTqueryEtryPt CODEqueryEtryPt_STD_OMOD_QUERIES CODEqueryEtryPt_STD_OMOD8_QUERIES
            CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES ENDqueryEtryPt

            BEGINmodInit() CODESTARTmodInit *ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr ENDmodInit
