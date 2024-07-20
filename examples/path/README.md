# Path Traversal Vulnerability

## Description

In this benchmark, we will demonstrate how our dynamic taint analysis can be used to mitigate path traversal vulnerabilities. 
We will use a simple Python web server that employs FastAPI to expose an endpoint for querying image files.

After instrumenting the server with our taint analysis, 
it will be able to intercept malicious input and raise an error before the image file path is generated. 
For example, if an attacker issues an HTTP GET request to the /images endpoint with a malicious parameter
(e.g., path="../../../../../../../etc/passwd"), an exception will be raised. 
The server will continue to run normally, but, more importantly, the attack will be mitigated.

## Running the Example

First, install the `fastapi` and `uvicorn` libraries in a virtual environment:

```bash
cd examples/path
python3 -m venv .env
source .env/bin/activate
pip install git+https://github.com/kamodulin/tainted.git fastapi "uvicorn[standard]"
```

Run the following command to instrument the code:

```bash
python3 -m tainted.instrument main.py --output main_instrument.py
```

Start the instrumented server:

```bash
uvicorn main_instrument:app --reload
```

Now try to issue a malicious request to the server:

```bash
curl "http://127.0.0.1:8000/images?path=../../../../../../../etc/passwd"
```

After instrumentation, the server will raise an exception, and the path concatenation function (i.e., os.path.join) will not be executed.
