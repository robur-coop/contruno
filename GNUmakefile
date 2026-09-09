_mfetch:
	@echo " INFER"
	unic infer -r . -x _build -x vendors \
		--ignore Documents \
                -x unikernel/script.ml \
		--prefer digestif.c --prefer checkseum.c \
                --prefer mirage-ptime.solo5 \
		-o _mfetch

vendors: _mfetch
	@echo " FETCH"
	mfetch -q

contruno.hvt.target: | vendors
	@echo " BUILD unikernel/main.exe"
	@dune build --root . --profile=release ./unikernel/main.exe
	@echo " DESCR unikernel/main.exe"
	@$(shell dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernel/main.exe 1> $@ 2>&1)

contruno.hvt: contruno.hvt.target
	@echo " COPY contruno.hvt"
	@cp $(file < contruno.hvt.target) $@
	@chmod +w $@
	@echo " STRIP contruno.hvt"
	@strip $@

contruno.install: contruno.hvt
	@echo " GEN contruno.install"
	@ocaml install.ml > $@

all: contruno.install | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f contruno.hvt.target
	rm -f contruno.hvt
	rm -f contruno.install

install: contruno.intall
	@echo " INSTALL contruno"
	opam-installer contruno.install
