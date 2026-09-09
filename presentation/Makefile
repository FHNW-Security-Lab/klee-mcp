SHELL := /bin/sh
DECK := klee-mcp-kes-presentation
SOURCES := $(DECK).tex $(wildcard figures/*.tex) $(wildcard theme/*)

.PHONY: all notes clean
all: $(DECK).pdf

$(DECK).pdf: $(SOURCES)
	mkdir -p build
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build $(DECK).tex
	cp build/$(DECK).pdf $@

notes: $(SOURCES)
	mkdir -p build
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build -jobname=$(DECK)-notes -usepretex='\def\shownotes{1}' $(DECK).tex
	cp build/$(DECK)-notes.pdf $(DECK)-notes.pdf

clean:
	rm -rf build
