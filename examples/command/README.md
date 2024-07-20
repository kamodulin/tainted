# Remote Code Execution

## Description

In this benchmark, we will demonstrate how our dynamic taint analysis can be used to mitigate remote code execution. 
We will use a simple Python web server that employs FastAPI to expose an endpoint for creating a project directory.

After instrumenting the server with our taint analysis, it will be able to intercept malicious input 
and raise an error before executing the command. For example, if an attacker issues an HTTP GET request to the /create/{project_name} endpoint 
with a malicious parameter (e.g., project_name="test_dir;touch%20test.txt"), an exception will be raised. 
The server will continue to run normally, but more importantly, the attack will be mitigated.

## Running the Example

First, install the `fastapi` and `uvicorn` libraries in a virtual environment:

```bash
cd examples/command
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
curl "http://127.0.0.1:8000/create/test_dir;touch%20test.txt"
```

After instrumentation, the server will raise an exception, and the `Popen` function will not be executed.
