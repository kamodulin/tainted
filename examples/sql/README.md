# SQL Injection

## Description

In this benchmark, we will demonstrate how our dynamic taint analysis can be used to
mitigate SQL injection attacks. We will use a simple Python web server that uses FastAPI
to expose an endpoint for querying a sensitive database.

After instrumenting the server with our taint analysis, it will be able to intercept a malicious input and raise an error before the query is even executed. For example, if an attacker issues an HTTP GET request to the /users/user id endpoint with a malicious parameter (e.g., user id="https://example.com/users/0 OR 1=1"), an exception will be raised. The server and database will continue to run normally, but, more importantly, the attack will be mitigated.

## Running the Example

First, install the `fastapi` and `uvicorn` libraries in a virtual environment:

```bash
cd examples/sql
python3 -m venv .env
source .env/bin/activate
pip install git+https://github.com/kamodulin/tainted.git fastapi "uvicorn[standard]"
```

Run the following command to instrument the code:

```bash
python3 -m tainted.instrument sql --output sql_instrumented --ignore .env
```

Start the instrumented server:

```bash
uvicorn sql_instrumented.main:app --reload
```

Now try to issue a malicious request to the server:

```bash
curl "http://localhost:8000/users/0;%20DROP%20TABLE%20users%20--"
```

Notice that the server will raise an exception, the database query will not be executed, and the server will continue to run normally.
