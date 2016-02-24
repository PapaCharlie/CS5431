SHELL := /bin/bash

SBT_URL := https://dl.bintray.com/sbt/native-packages/sbt/0.13.9/sbt-0.13.9.tgz
SBT_TAR := sbt-0.13.9.tgz
SBT := $(shell which sbt 2> /dev/null || echo sbt/bin/sbt)

BOUNCY_CASTLE_JAR := bcprov-jdk15on-154.jar
BOUNCY_CASTLE_LINK := https://www.bouncycastle.org/download/$(BOUNCY_CASTLE_JAR)
BOUNCY_CASTLE_SHA1_SIG = 1acdedeb89f1d950d67b73d481eb7736df65eedb

INSTALLED := \e[0;31msbt is already installed!$<\e[0m
INSTALLING := Fetching and installing sbt.

SBT_TASKS := compile test run clean

.PHONY: all

all: compile

start:
	$(SBT) "~re-start"

install:
	test -x $(SBT) && echo -e "$(INSTALLED)" && exit 1 || echo "$(INSTALLING)"
	test -e $(SBT_TAR) || wget $(SBT_URL)
	tar xzf $(SBT_TAR)

$(SBT_TASKS):
	$(SBT) "$@"

verify:
	test -d "lib" || mkdir "lib"
	test -e "lib/$(BOUNCY_CASTLE_JAR)" || wget -O "lib/$(BOUNCY_CASTLE_JAR)" $(BOUNCY_CASTLE_LINK)
	test $(shell sha1sum lib/$(BOUNCY_CASTLE_JAR) | cut -d' ' -f 1) = $(BOUNCY_CASTLE_SHA1_SIG)
