scss_files = $(filter-out snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
scss_includes = $(filter snikket_web/scss/_%.scss,$(wildcard snikket_web/scss/*.scss))
generated_css_files = $(patsubst snikket_web/scss/%.scss,snikket_web/static/css/%.css,$(scss_files))

translation_basepath = snikket_web/translations
pot_file = $(translation_basepath)/messages.pot

black_formatted_py = snikket_web/admin.py snikket_web/prosodyclient.py

PYTHON3 ?= python3
SCSSC ?= sassc --load-path snikket_web/scss/

# According to the GNU make manual, this is how you do it...
comma:= ,
empty:=
space:= $(empty) $(empty)

all: build_css compile_translations

build_css: $(generated_css_files)

$(generated_css_files): snikket_web/static/css/%.css: snikket_web/scss/%.scss $(scss_files) $(scss_includes)
	mkdir -p snikket_web/static/css/
	$(SCSSC) "$<" "$@"

clean:
	rm -f $(generated_css_files)

extract_translations:
	pybabel extract -F babel.cfg -k _l -o $(pot_file) .

update_translations: extract_translations
	@echo "This has been deprecated as translations are now managed by weblate."
	@echo "Use extract_translations only."
	@false

force_update_translations: extract_translations
	pybabel update -i $(pot_file) -d $(translation_basepath)

compile_translations:
	-pybabel compile -d $(translation_basepath)


.PHONY: lint
lint: format flake8

.PHONY: format
format:
	$(PYTHON3) -m black $(black_formatted_py)

.PHONY: flake8
flake8:
	$(PYTHON3) -m flake8 --exclude=$(subst $(space),$(comma),$(strip $(black_formatted_py))) snikket_web
	$(PYTHON3) -m flake8 --ignore=E501,W503 $(black_formatted_py)

.PHONY: mypy
mypy:
	$(PYTHON3) -m mypy --python-version 3.11 snikket_web

.PHONY: build_css clean update_translations compile_translations extract_translations force_update_translations
