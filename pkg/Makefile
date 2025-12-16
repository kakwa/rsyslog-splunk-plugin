NAME=rsyslog-splunk-plugin
VERSION=$(shell git describe --tags --dirty)
#VERSION=0.0.0
RELEASE=1
URL=https://github.com/kakwa/rsyslog-splunk-plugin
SUMMARY=$(NAME)
DESCRIPTION=$(SUMMARY)
LICENSE=MIT
#SKIP=<=:deb:8 <=:el:6 <=:fc:29 <=:ubu:18.4
COWBUILD_BUILD_ADDITIONAL_ARGS=--use-network yes

# Including common rules and targets
include buildenv/Makefile.common

# Rsyslog version based on distribution
ifeq ($(DIST),trixie)
    RSYSLOG_VERSION=8.2512.0
else ifeq ($(DIST),forky)
    RSYSLOG_VERSION=8.2510.0
else ifeq ($(DIST),bookworm)
    RSYSLOG_VERSION=8.2302.0
else
    # Default to most recent version if DIST is unknown
    RSYSLOG_VERSION=8.2512.0
endif

RSYSLOG_URL=http://deb.debian.org/debian/pool/main/r/rsyslog/rsyslog_$(RSYSLOG_VERSION).orig.tar.gz

# Source Preparation
$(SOURCE_ARCHIVE): $(SOURCE_DIR) $(CACHE) Makefile MANIFEST
	@rm -rf -- $(SOURCE_DIR)
	@rsync -ap --ignore-errors --force --exclude pkg --exclude .git --exclude deps --exclude build ../ $(SOURCE_DIR)
	@$(WGS) -u $(RSYSLOG_URL) -O rsyslog-$(RSYSLOG_VERSION).tar.gz
	@mkdir -p $(SOURCE_DIR)/deps/rsyslog
	@tar -xzf $(CACHE_DIR)/rsyslog-$(RSYSLOG_VERSION).tar.gz -C $(SOURCE_DIR)/deps/rsyslog --strip-components=1
	@$(SOURCE_TAR_CMD)