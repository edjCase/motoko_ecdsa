
.SUFFIXES: .wasm .mo

TIME=time

bench-gen10.mo: bench-gen.tmpl
	sed 's/@@@/10/' < bench-gen.tmpl > bench-gen10.mo

bench-gen20.mo: bench-gen.tmpl
	sed 's/@@@/20/' < bench-gen.tmpl > bench-gen20.mo

bench-gen10: bench-gen10.wasm
	$(TIME) wasmtime $<
bench-gen20: bench-gen20.wasm
	$(TIME) wasmtime $<
bench-mulmod: bench-mulmod.wasm
	$(TIME) wasmtime $<

bench-gen:
	$(MAKE) bench-gen10
	$(MAKE) bench-gen20

bench-sign10.mo: bench-sign.tmpl
	sed 's/@@@/10/' < bench-sign.tmpl > bench-sign10.mo

bench-sign20.mo: bench-sign.tmpl
	sed 's/@@@/20/' < bench-sign.tmpl > bench-sign20.mo

bench-sign10: bench-sign10.wasm
	$(TIME) wasmtime $<
bench-sign20: bench-sign20.wasm
	$(TIME) wasmtime $<

bench-sign:
	$(MAKE) bench-sign10
	$(MAKE) bench-sign20

bench-verify10.mo: bench-verify.tmpl
	sed 's/@@@/10/' < bench-verify.tmpl > bench-verify10.mo

bench-verify20.mo: bench-verify.tmpl
	sed 's/@@@/20/' < bench-verify.tmpl > bench-verify20.mo

bench-verify10: bench-verify10.wasm
	$(TIME) wasmtime $<
bench-verify20: bench-verify20.wasm
	$(TIME) wasmtime $<

bench-verify:
	$(MAKE) bench-verify10
	$(MAKE) bench-verify20

clean:
	rm -rf *.wasm

.PHONY: test
