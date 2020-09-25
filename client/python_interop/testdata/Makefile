all:
	docker build -t tuf-gen ./generate
	docker run tuf-gen | tar x

clean:
	rm -rf python-tuf-0.9/with{,out}-consistent-snapshot

.PHONY: all clean
