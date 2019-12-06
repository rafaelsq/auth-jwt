watch:
ifeq (, $(shell which wtc))
	cd && go get github.com/rafaelsq/wtc
endif
	@wtc
