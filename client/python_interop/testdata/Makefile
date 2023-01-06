PYTHON_TUF=python-tuf-v2.0.0

all:
	docker build -t tuf-gen ./$(PYTHON_TUF)
	docker run tuf-gen | tar x -C $(PYTHON_TUF)

clean:
	rm -rf $(PYTHON_TUF)/with{,out}-consistent-snapshot

.PHONY: all clean
