SHELL := /bin/bash

SBT_URL := https://dl.bintray.com/sbt/native-packages/sbt/0.13.9/sbt-0.13.9.tgz
SBT_TAR := sbt-0.13.9.tgz
SBT := $(shell which sbt 2> /dev/null || echo sbt/bin/sbt)

INSTALLED := \e[0;31msbt is already installed!$<\e[0m
INSTALLING := Fetching and installing sbt.

SBT_TASKS := compile test run clean

.PHONY: all

all: compile

install:
	test -x $(SBT) && echo -e "$(INSTALLED)" && exit 1 || echo "$(INSTALLING)"
	test -e $(SBT_TAR) || wget $(SBT_URL)
	tar xzf $(SBT_TAR)

$(SBT_TASKS):
	$(SBT) "$@"
