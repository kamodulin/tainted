# Cryptographic Key Leakage

## Description

In this benchmark, we demonstrate how to use our dynamic taint analysis to detect and prevent cryptographic key leaks in a toy implementation of a messaging application. We have already labeled specific cryptographic keys as tainted and marked network calls as sinks. We introduce a few bugs that leak keys and see if our instrumented system can detect the leaks and prevent the keys from being sent over the network in plaintext.

## Running the Example

First, install the `cryptography` library in a virtual environment:

```bash
cd examples/chat
python3 -m venv .env
source .env/bin/activate
pip install git+https://github.com/kamodulin/tainted.git cryptography
```

To run the example without any leaks we first need to instrument the code. We can do this by running the following command (make sure you are in the root directory of the repository):

```bash
cd ..
python3 -m tainted.instrument chat --output chat_instrumented --ignore .env
```

Then we can run the instrumented code by running the following command in one terminal to create a server:

```bash
python3 chat_instrumented/main.py -l localhost 9090
```

and in another terminal run the following to send messages to the server:

```bash
python3 chat_instrumented/main.py localhost 9090
```

If everything goes well, you can input messages in the second terminal and you will be able to see the received messages in the terminal for the server.

Now we can introduce a single bug that leaks the key and see if `tainted` can detect it. Let's pretend that we accidentally interpret the public key variable in `main.py` as the private key. So we should change lines 20 and 56 in `main.py` to `sk, pk = generate_key_pair()`. Now that we have introduced this very simple bug, instrument the code again using the same command as above. If you then run the server and as soon as a client connects, the server will be unable to send its "public key" to the client as in a normal Diffie-Hellman key exchange because we marked private keys as taint sources in `crypto.py`. The server will then print an error message and exit.
