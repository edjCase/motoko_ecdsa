bench-gen:
	$(MAKE) bench-gen

bench-sign:
	$(MAKE) bench-sign

bench-verify:
	$(MAKE) bench-verify

bench:
	$(MAKE) bench-gen
	$(MAKE) bench-sign
	$(MAKE) bench-verify

clean:
	$(MAKE) clean
