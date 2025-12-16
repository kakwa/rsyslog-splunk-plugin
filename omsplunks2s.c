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
#include "parserif.h"

#include "s2s.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omsplunks2s")

/* Module static data */
DEF_OMOD_STATIC_DATA

/* Custom templates for S2S */
#define SPLUNK_S2S_RAWMSG "\"%msg:2:$%\""
#define SPLUNK_S2S_FACILITY "\"%syslogfacility-text%\""
#define SPLUNK_S2S_SEVERITY "\"%syslogseverity-text%\""
#define SPLUNK_S2S_HOSTNAME "\"%hostname%\""
#define SPLUNK_S2S_PROGRAM "\"%programname%\""
#define SPLUNK_S2S_PROCID "\"%procid%\""

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
static int do_connect(instanceData *pData, int bInitializing) {
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
        if (bInitializing) {
            /* During initialization, use dbgprintf to avoid message property issues */
            dbgprintf("omsplunks2s: failed to connect to %s:%d%s\n", pData->server, pData->port,
                      pData->tls_enabled ? " (TLS)" : "");
        } else {
            LogError(0, RS_RET_SUSPENDED, "omsplunks2s: failed to connect to %s:%d%s", pData->server, pData->port,
                     pData->tls_enabled ? " (TLS)" : "");
        }
        return -1;
    }

    if (!bInitializing) {
        LogMsg(0, RS_RET_OK, LOG_INFO, "omsplunks2s: connected to %s:%d%s", pData->server, pData->port,
               pData->tls_enabled ? " (TLS)" : "");
    } else {
        dbgprintf("omsplunks2s: connected to %s:%d%s\n", pData->server, pData->port,
                  pData->tls_enabled ? " (TLS)" : "");
    }
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
    return do_connect(pData, 0);
}

/* -------------------- Rsyslog Module Interface -------------------- */

/* BEGINcreateInstance - Creates function: static rsRetVal createInstance(instanceData **ppData) */
static rsRetVal createInstance(instanceData **ppData) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    instanceData *pData;
    /* CODESTARTcreateInstance */

    if ((pData = calloc(1, sizeof(instanceData))) == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }

    pData->server = NULL;
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

    /* ENDcreateInstance */
    *ppData = pData;
    return iRet;
}

/* BEGINcreateWrkrInstance - Creates function: static rsRetVal createWrkrInstance(wrkrInstanceData_t **ppWrkrData,
 * instanceData *pData) */
static rsRetVal createWrkrInstance(wrkrInstanceData_t **ppWrkrData, instanceData *pData) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    wrkrInstanceData_t *pWrkrData;
    /* CODESTARTcreateWrkrInstance */

    if ((pWrkrData = calloc(1, sizeof(wrkrInstanceData_t))) == NULL) {
        *ppWrkrData = NULL;
        return RS_RET_OUT_OF_MEMORY;
    }
    pWrkrData->pData = pData;

    /* ENDcreateWrkrInstance */
    *ppWrkrData = pWrkrData;
    return iRet;
}

/* BEGINfreeInstance - Creates function: static rsRetVal freeInstance(void* pModData) */
static rsRetVal freeInstance(void *pModData) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    instanceData *pData;
    /* CODESTARTfreeInstance */
    pData = (instanceData *)pModData;

    pthread_mutex_lock(&pData->mtx);
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

    /* ENDfreeInstance */
    if (pData != NULL)
        free(pData);
    return iRet;
}

/* BEGINfreeWrkrInstance - Creates function: static rsRetVal freeWrkrInstance(void* pd) */
static rsRetVal freeWrkrInstance(void *pd) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    wrkrInstanceData_t *pWrkrData;
    /* CODESTARTfreeWrkrInstance */
    pWrkrData = (wrkrInstanceData_t *)pd;

    /* ENDfreeWrkrInstance */
    if (pWrkrData != NULL)
        free(pWrkrData);
    return iRet;
}

/* BEGINdbgPrintInstInfo - Creates function: static rsRetVal dbgPrintInstInfo(void *pModData) */
static rsRetVal dbgPrintInstInfo(void *pModData) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    instanceData *pData = NULL;
    /* CODESTARTdbgPrintInstInfo */
    pData = (instanceData *)pModData;
    (void)pData; /* prevent compiler warning if unused! */

    dbgprintf("omsplunks2s:\n");
    dbgprintf("\tserver='%s'\n", pData->server ? pData->server : "(null)");
    dbgprintf("\tport=%d\n", pData->port);
    dbgprintf("\tindex='%s'\n", pData->index ? pData->index : "(null)");
    dbgprintf("\tsourcetype='%s'\n", pData->sourcetype ? pData->sourcetype : "(null)");
    dbgprintf("\ttls=%d\n", pData->tls_enabled);
    dbgprintf("\ttls.verify=%d\n", pData->tls_verify);
    dbgprintf("\ttls.cacert='%s'\n", pData->tls_ca_file ? pData->tls_ca_file : "(null)");
    dbgprintf("\ttls.cert='%s'\n", pData->tls_cert_file ? pData->tls_cert_file : "(null)");
    dbgprintf("\ttls.key='%s'\n", pData->tls_key_file ? pData->tls_key_file : "(null)");

    /* ENDdbgPrintInstInfo */
    return iRet;
}

/* BEGINtryResume - Creates function: static rsRetVal tryResume(wrkrInstanceData_t *pWrkrData) */
static rsRetVal tryResume(wrkrInstanceData_t *pWrkrData) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    /* CODESTARTtryResume */
    assert(pWrkrData != NULL);

    pthread_mutex_lock(&pWrkrData->pData->mtx);
    iRet = ensure_connected(pWrkrData->pData) == 0 ? RS_RET_OK : RS_RET_SUSPENDED;
    pthread_mutex_unlock(&pWrkrData->pData->mtx);

    /* ENDtryResume */
    return iRet;
}

/* BEGINdoAction - Creates function: static rsRetVal doAction(void * pMsgData, wrkrInstanceData_t *pWrkrData) */
static rsRetVal doAction(void *pMsgData, wrkrInstanceData_t *pWrkrData) {
    uchar **ppString = (uchar **)pMsgData;
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    instanceData *pData;
    s2s_event_t event;
    s2s_error_t err;
    /* CODESTARTdoAction - ppString may be NULL if the output module requested no strings */

    pData = pWrkrData->pData;

    /* Validate message */
    if (ppString[0] == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

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
    event.field_count = 0;

    /* Add custom metadata fields from syslog */
    if (ppString[1] && ppString[1][0]) {
        s2s_event_add_field(&event, "syslog_facility", (const char *)ppString[1]);
    }
    if (ppString[2] && ppString[2][0]) {
        s2s_event_add_field(&event, "syslog_severity", (const char *)ppString[2]);
    }
    if (ppString[3] && ppString[3][0]) {
        s2s_event_add_field(&event, "syslog_hostname", (const char *)ppString[3]);
    }
    if (ppString[4] && ppString[4][0]) {
        s2s_event_add_field(&event, "syslog_program", (const char *)ppString[4]);
    }

    /* Debug: log event details */
    dbgprintf(
        "omsplunks2s: sending event: msg='%.100s', host='%s', source='%s', sourcetype='%s', index='%s', fields=%d\n",
        event.raw ? event.raw : "(null)", event.host ? event.host : "(null)", event.source ? event.source : "(null)",
        event.sourcetype ? event.sourcetype : "(null)", event.index ? event.index : "(null)", event.field_count);

    /* Send event */
    err = s2s_send(pData->conn, &event);
    dbgprintf("omsplunks2s: s2s_send returned: %d (%s)\n", err, s2s_strerror(err));

    if (err != S2S_OK) {
        LogError(0, RS_RET_SUSPENDED, "omsplunks2s: send failed: %s", s2s_strerror(err));
        s2s_close(pData->conn);
        pData->conn = NULL;
        pthread_mutex_unlock(&pData->mtx);
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    pthread_mutex_unlock(&pData->mtx);

finalize_it: /* ENDdoAction */
    return iRet;
}

/* BEGINisCompatibleWithFeature - Creates function: static rsRetVal isCompatibleWithFeature(syslogFeature eFeat) */
static rsRetVal isCompatibleWithFeature(syslogFeature eFeat) {
    rsRetVal iRet = RS_RET_INCOMPATIBLE;
    /* CODESTARTisCompatibleWithFeature */

    if (eFeat == sFEATURERepeatedMsgReduction)
        iRet = RS_RET_OK;

    /* ENDisCompatibleWithFeature */
    return iRet;
}

/* BEGINnewActInst - Creates function: static rsRetVal newActInst(uchar *modName, struct nvlst *lst, void **ppModData,
 * omodStringRequest_t **ppOMSR) */
static rsRetVal newActInst(uchar __attribute__((unused)) * modName, struct nvlst __attribute__((unused)) * lst,
                           void **ppModData, omodStringRequest_t **ppOMSR) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    instanceData *pData = NULL;
    *ppOMSR = NULL;
    struct cnfparamvals *pvals;
    int i;
    /* CODESTARTnewActInst */

    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        iRet = RS_RET_MISSING_CNFPARAMS; /* ABORT_FINALIZE */
        goto finalize_it;
    }

    if ((iRet = createInstance(&pData)) != RS_RET_OK) /* CHKiRet */
        goto finalize_it;

    /* CODE_STD_STRING_REQUESTnewActInst(5) - Constructs OMSR with 5 template slots */
    if ((iRet = OMSRconstruct(ppOMSR, 5)) != RS_RET_OK)
        goto finalize_it;

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
            dbgprintf("omsplunks2s: program error, non-handled param '%s'\n", actpblk.descr[i].name);
        }
    }

    /* Validate required parameters */
    if (pData->server == NULL || pData->server[0] == '\0') {
        parser_errmsg("omsplunks2s: 'server' parameter is required");
        ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
    }

    /* Set defaults */
    if (pData->sourcetype == NULL) {
        pData->sourcetype = strdup("syslog");
    }

    /* Setup templates - message + metadata fields (max 5 due to rsyslog limit) */
    /* Template 0: Raw message */
    if ((iRet = OMSRsetEntry(*ppOMSR, 0, (uchar *)strdup(" SPLUNK_S2S_RAWMSG"), OMSR_NO_RQD_TPL_OPTS)) != RS_RET_OK)
        goto finalize_it;
    /* Template 1: syslog facility */
    if ((iRet = OMSRsetEntry(*ppOMSR, 1, (uchar *)strdup(" SPLUNK_S2S_FACILITY"), OMSR_NO_RQD_TPL_OPTS)) != RS_RET_OK)
        goto finalize_it;
    /* Template 2: syslog severity */
    if ((iRet = OMSRsetEntry(*ppOMSR, 2, (uchar *)strdup(" SPLUNK_S2S_SEVERITY"), OMSR_NO_RQD_TPL_OPTS)) != RS_RET_OK)
        goto finalize_it;
    /* Template 3: hostname */
    if ((iRet = OMSRsetEntry(*ppOMSR, 3, (uchar *)strdup(" SPLUNK_S2S_HOSTNAME"), OMSR_NO_RQD_TPL_OPTS)) != RS_RET_OK)
        goto finalize_it;
    /* Template 4: program name */
    if ((iRet = OMSRsetEntry(*ppOMSR, 4, (uchar *)strdup(" SPLUNK_S2S_PROGRAM"), OMSR_NO_RQD_TPL_OPTS)) != RS_RET_OK)
        goto finalize_it;

/* CODE_STD_FINALIZERnewActInst - Cleanup and return logic */
finalize_it:
    if (iRet == RS_RET_OK || iRet == RS_RET_SUSPENDED) {
        *ppModData = pData;
    } else {
        /* cleanup, we failed */
        if (*ppOMSR != NULL) {
            OMSRdestruct(*ppOMSR);
            *ppOMSR = NULL;
        }
        if (pData != NULL) {
            freeInstance(pData);
        }
    }
    cnfparamvalsDestruct(pvals, &actpblk);
    /* ENDnewActInst */
    return iRet;
}

/* BEGINparseSelectorAct - Creates function: static rsRetVal parseSelectorAct(uchar **pp, void **ppModData,
 * omodStringRequest_t **ppOMSR) Legacy configuration is not supported - only new-style RainerScript config */
static rsRetVal parseSelectorAct(uchar **pp, void **ppModData, omodStringRequest_t **ppOMSR) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    uchar *p;
    instanceData *pData = NULL;
    /* CODESTARTparseSelectorAct */
    assert(pp != NULL);
    assert(ppModData != NULL);
    assert(ppOMSR != NULL);
    p = *pp;

    /* CODE_STD_STRING_REQUESTparseSelectorAct(1) */
    if ((iRet = OMSRconstruct(ppOMSR, 1)) != RS_RET_OK)
        goto finalize_it;

    /* Legacy config not supported - use new-style config only */
    iRet = RS_RET_CONFLINE_UNPROCESSED; /* ABORT_FINALIZE */
    goto finalize_it;

/* CODE_STD_FINALIZERparseSelectorAct */
finalize_it:
    __attribute__((unused));
    if (iRet == RS_RET_OK || iRet == RS_RET_OK_WARN || iRet == RS_RET_SUSPENDED) {
        *ppModData = pData;
        *pp = p;
    } else {
        /* cleanup, we failed */
        if (*ppOMSR != NULL) {
            OMSRdestruct(*ppOMSR);
            *ppOMSR = NULL;
        }
        if (pData != NULL) {
            freeInstance(pData);
        }
    }
    /* ENDparseSelectorAct */
    return iRet;
}

/* BEGINmodExit - Creates function: static rsRetVal modExit(void) */
static rsRetVal modExit(void) {
    rsRetVal iRet = RS_RET_OK; /* DEFiRet */
    /* CODESTARTmodExit */
    /* No cleanup needed */
    /* ENDmodExit */
    return iRet;
}

/* BEGINqueryEtryPt - Standard module entry point query function */
BEGINqueryEtryPt CODESTARTqueryEtryPt CODEqueryEtryPt_STD_OMOD_QUERIES CODEqueryEtryPt_STD_OMOD8_QUERIES
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES ENDqueryEtryPt

    BEGINmodInit() CODESTARTmodInit uchar *pTmp;
*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr

    /* Register custom templates */
    DBGPRINTF("omsplunks2s: registering custom templates\n");

pTmp = (uchar *)SPLUNK_S2S_RAWMSG;
tplAddLine(ourConf, " SPLUNK_S2S_RAWMSG", &pTmp);

pTmp = (uchar *)SPLUNK_S2S_FACILITY;
tplAddLine(ourConf, " SPLUNK_S2S_FACILITY", &pTmp);

pTmp = (uchar *)SPLUNK_S2S_SEVERITY;
tplAddLine(ourConf, " SPLUNK_S2S_SEVERITY", &pTmp);

pTmp = (uchar *)SPLUNK_S2S_HOSTNAME;
tplAddLine(ourConf, " SPLUNK_S2S_HOSTNAME", &pTmp);

pTmp = (uchar *)SPLUNK_S2S_PROGRAM;
tplAddLine(ourConf, " SPLUNK_S2S_PROGRAM", &pTmp);

pTmp = (uchar *)SPLUNK_S2S_PROCID;
tplAddLine(ourConf, " SPLUNK_S2S_PROCID", &pTmp);
ENDmodInit
