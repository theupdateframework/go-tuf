all:
	docker build -t tuf-gen ./generate
	docker run tuf-gen | tar x

clean:
	rm -rf keystore repository

.PHONY: all clean
