SHELL := /bin/bash

SBT_URL := https://dl.bintray.com/sbt/native-packages/sbt/0.13.9/sbt-0.13.9.tgz
SBT_TAR := sbt-0.13.9.tgz
SBT_SHA512_SUM := cf0deb1a5a07ce3690a831a2ee0f499a5c904cd9a9038873ab78773717a12ce4dec668e00c3dd6b89e7919357c32b26ff97a78613de5c6252b495bc7fdc763f3
SBT := $(shell which sbt 2> /dev/null || echo sbt/bin/sbt)

BOUNCY_CASTLE_JAR := bcprov-jdk15on-154.jar
BOUNCY_CASTLE_LINK := https://www.bouncycastle.org/download/$(BOUNCY_CASTLE_JAR)
BOUNCY_CASTLE_SHA1_SUM = 1acdedeb89f1d950d67b73d481eb7736df65eedb

INSTALLED := \e[0;31msbt is already installed!$<\e[0m
INSTALLING := Fetching and installing sbt.

MAIN := src/main/java/vault5431/Vault.java

SBT_TASKS := compile test run clean

.PHONY: all

all: compile

start:
	"$(SBT)" "~re-start"

$(SBT_TASKS):
	test -d ~/.vault5431 || mkdir ~/.vault5431
	"$(SBT)" "$@"

install:
	echo $(SBT_SHA512_SUM)  $(SBT_TAR) > $(SBT_TAR).checksum
	test -x $(SBT) && echo -e "$(INSTALLED)" && exit 1 || echo "$(INSTALLING)"
	test -e $(SBT_TAR) || wget $(SBT_URL)
	sha512sum -c $(SBT_TAR).checksum
	tar xzf $(SBT_TAR)
	rm $(SBT_TAR).checksum

verify:
	test -d "lib" || mkdir "lib"
	cd lib && echo $(BOUNCY_CASTLE_SHA1_SUM) $(BOUNCY_CASTLE_JAR) > $(BOUNCY_CASTLE_JAR).checksum
	test -e "lib/$(BOUNCY_CASTLE_JAR)" || wget -O "lib/$(BOUNCY_CASTLE_JAR)" $(BOUNCY_CASTLE_LINK)
	cd lib && sha1sum -c $(BOUNCY_CASTLE_JAR).checksum
	cd lib && rm $(BOUNCY_CASTLE_JAR).checksum

log:
	cat ~/.vault5431/log | base64 --decode

submission:
	cd ../redirector && make submission
	zip -r src.zip LICENSE Makefile README build.sbt keystore.jks lib/spark-template-freemarker-2.3.jar src/ project/build.properties project/plugins.sbt ../redirector/redirector.zip

assembly:
	cp $(MAIN) $(MAIN).bak
	sed -i "s#public static final boolean test = true;#public static final boolean test = false;#g" $(MAIN)
	"$(SBT)" "assembly"
	mv $(MAIN).bak $(MAIN)

deploy: assembly up

up:
	rsync -vrc --progress target/scala-2.10/vault5431-assembly-1.0.0.jar root@vault5431.com:.
	rsync -vrc --progress ServerMakefile root@vault5431.com:Makefile
