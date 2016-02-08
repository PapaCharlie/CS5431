SHELL := /bin/sh

SBT_TASKS := compile test run clean

.PHONY: all

all: compile

$(SBT_TASKS):
	sbt "$@"
