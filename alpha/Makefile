SHELL := /bin/sh

SRC := $(wildcard *.tex)
PDF := $(SRC:.tex=.pdf)
FIGURES := $(filter-out *-crop.pdf, $(shell find figures -name "*.pdf" -type f))
PNG := $(filter-out *-crop.png, $(shell find figures -name "*.png" -type f))

SBT_TASKS := compile test run

all:
	-mkdir .build
	-rm $(PDF)
	for t in $(SRC) ; do \
		pdflatex -shell-escape -output-directory=.build $$t ; \
	done
	make links

crop:
	for fig in $(FIGURES) ; do \
		pdfcrop $$fig ; \
		mv `echo $$fig | sed "s/.pdf/-crop.pdf/g"` $$fig ; \
	done

clean:
	-rm $(PDF)
	-rm -rf .build/*

links:
	-rm $(PDF)
	ln -s .build/*.pdf .

submission:
	cd ../vault && make submission
	cp ../vault/src.zip .
	zip -r alpha.zip *.pdf FindBugsResult.html src.zip
