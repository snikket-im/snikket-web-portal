scss_files = $(filter-out snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
scss_includes = $(filter snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
generated_css_files = $(patsubst snikket_web/scss/%.scss,snikket_web/static/css/%.css,$(scss_files))

PYTHON3 ?= python3
SCSSC ?= $(PYTHON3) -m scss --load-path snikket_web/scss/

build_css: $(generated_css_files)

$(generated_css_files): snikket_web/static/css/%.css: snikket_web/scss/%.scss $(scss_includes)
	$(SCSSC) -o "$@" "$<"

clean:
	rm -f $(generated_css_files)

.PHONY: build_css clean
