# Testing

The [Python interoperability tests](../client/python_interop/) require Python 3
(available as `python` on the `$PATH`) and the [`python-tuf`
package](https://github.com/theupdateframework/python-tuf) installed. To use the correct versions of the packages, it is recommended to use a [virtual environment](https://docs.python.org/3/library/venv.html#module-venv) and install the dependencies via:

```
python -m pip install --upgrade -r requirements-test.txt
```

You may run the full set of tests using 
```
go test ./...
```


To update the data for these tests requires Docker and make (see
test data [README.md](../client/python_interop/testdata/README.md) for details).
