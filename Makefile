scss_files = $(filter-out snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
scss_includes = $(filter snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
generated_css_files = $(patsubst snikket_web/scss/%.scss,snikket_web/static/css/%.css,$(scss_files))

translation_basepath = snikket_web/translations
pot_file = $(translation_basepath)/messages.pot

PYTHON3 ?= python3
SCSSC ?= $(PYTHON3) -m scss --load-path snikket_web/scss/

all: build_css compile_translations

build_css: $(generated_css_files)

$(generated_css_files): snikket_web/static/css/%.css: snikket_web/scss/%.scss $(scss_files) $(scss_includes)
	mkdir -p snikket_web/static/css/
	$(SCSSC) -o "$@" "$<"

clean:
	rm -f $(generated_css_files)

update_translations:
	pybabel extract -F babel.cfg -k _l -o $(pot_file) .
	pybabel update -i $(pot_file) -d $(translation_basepath)

compile_translations:
	pybabel compile -d $(translation_basepath)


.PHONY: build_css clean update_translations compile_translations
