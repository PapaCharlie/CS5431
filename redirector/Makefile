SHELL := /bin/bash

SBT_TASKS := compile run clean assembly

.PHONY: all

all: compile

$(SBT_TASKS):
	sbt "$@"

deploy: assembly
	rsync -vrc --progress target/scala-2.10/vault5431-redirector-assembly-0.2.jar root@vault5431.com:.
