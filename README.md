# tainted: a dynamic taint analysis tool for Python

## Background

Bugs in consumer-facing applications can lead to the theft of sensitive data, including personal and financial information. Most of the time, these vulnerabilities are the result of improper handling of sensitive data within an application or lack of input validation. For example, SQL injection attacks can be used to extract information from a database or modify its contents if an application does not properly sanitize user input.

To mitigate these risks, developers can employ a technique called taint tracking to identify and track the flow of sensitive data through an application. This works by “tainting” untrusted data and then tracking its flow through a program at runtime. If this tainted data ends up in a sensitive sink, such as a database query, the application can immediately raise an alert and exit the program. This allows developers to identify vulnerabilities and take steps to prevent sensitive data from being leaked or modified.

That's where `tainted` comes in! `tainted` provides a simple and intuitive interface for developers to add taint tracking to their Python applications. By simply adding type comments and performing a one-time program instrumentation procedure, developers can automatically track the flow of sensitive data through their applications and prevent data leaks.

## Installation

Clone this repository and run the following command to install the package:

```bash
pip install .
```

Alternatively, you can install the package directly using `git`:

```bash
pip install git+https://github.com/kamodulin/tainted.git
```

## Usage

### Type Comment Annotations

Add type comments to your code to mark sources, sanitization functions, and sinks. Here is an example:

```python
user_input = get_user_input() # type: taint[source]
result = query_db(user_input) # type: taint[sink]
```

Here is a breakdown of the type comments `tainted` supports:

- `# type: taint[source]` taints a variable as sensitive data. This is most likely used for untrusted user-provided input or internal sensitive data that should not be leaked.
- `# type: taint[sanitized]` marks a variable as sanitized data. This is used to indicate that the developer knows what they are doing and that the data is safe to use in a sink after some form of sanitization.
- `# type: taint[sink]` marks a variable as a sink for tainted data. Again, this is most likely for database queries, file writes, network requests, etc.

### Program Instrumentation

Instrument your code to automatically replace the type comments with the necessary taint tracking logic. To do this, you can use the `tainted.instrument` file on a specific Python file or directory. You can specify where the output should be saved using the `--output` flag.

```python
python3 -m tainted.instrument server.py --output server_instrumented.py
```

### Running the Instrumented Code

Run your instrumented code as you would normally and the `tainted` runtime will track the flow of data through your program automatically, raising an error if tainted data ever reaches a sink.

```python
python3 server_instrumented.py
```

## Examples

We also provide a few examples to illustrate how to use the `tainted` package with detailed step-by-step instructions. You can find these examples in the `examples` directory.
