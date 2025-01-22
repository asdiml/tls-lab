# Simplified TLS Implementation

This project is part of UCLA ACM Cyber's series of quarterly projects where a topic within cybersecurity is chosen for exploration. 

As the name suggests, this project deals with Transport Layer Security (TLS), and specifically attempts to implement TLS v1.3 for a better understanding of how a secure communication channel is set-up across the web. 

## Running our TLS v1.3 implementation

You may wish to first create a virtual environment (see https://docs.python.org/3/tutorial/venv.html for a tutorial on venvs) so as to avoid polluting your global Python library space. 

The next step is to install the Python dependencies by running the following in the root directory of the repo

```bash
pip install -r requirements.txt
```

Finally, run the module by running the command

```bash
python3 -m tlsimpl
```

You should see the following

```
Shared ciphers:TLS_AES_256_GCM_SHA384
Signature Algorithms: RSA-PSS+SHA384
Shared Signature Algorithms: RSA-PSS+SHA384
Supported groups: x25519
Shared groups: x25519
CIPHER is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported

TLS v1.3 connection established!
Send something to the openssl server >
```

whereby, after inputing data, you should be able to see that the server received the response as follows, and prompts for how the server should respond

```
TLS v1.3 connection established!
Send something to the openssl server > Hello!

Received Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
Hello!

Now you are the server, pls reply >
```

After we determine the server's response, we can observe the trace for it, and the cycle repeats again

```
Now you are the server, pls reply > Hi, how are you doing?
Sent Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 40
  Inner Content Type = ApplicationData (23)

Data received from the server: b'Hi, how are you doing?\n'

TLS v1.3 connection established!
Send something to the openssl server >
```

## Details of Implementation

This implementation includes the generation and derivation of handshake and application keys, as they form the crux of why TLS v1.3 exists - to create a secure communication channel between the client and server. 

As is required by the specification, other 

However, the following simplifications are made for this project
1. We fix a particular cipher suite (TLS_AES_256_GCM_SHA384) for symmetric encryption, as well as some other cryptography-related parameters (such as the curve for the elliptic curve encryption)
2. We ignore a number of server extensions e.g. SUPPORTED_VERSIONS which are not particularly important to the handshake / key exchange process
3. We do not verify the server's certificate (at least for now)

## Future Work

Future work for this project includes the following
1. Verify the server's ceritificate
2. Accommodate cipher suite negotiation - this will require accepting Hello Retry Requests
3. Leverage multi-threading upon receiving multiple blocks of encrypted data from the server for decryption

## Authors & Credits

The authors of this fork of the project are [Teong Seng Tan](https://github.com/asdiml), Prabvhir Babra, and Luca Tineo. 

Credit is also due to the leads of this ACM Cyber Lab - Jason An, Mark Epstein, Gary Song and Arnav Vora - for providing the [base repo](https://github.com/pbrucla/tls-lab-skel) from which this repo was forked. 

Other significant references include https://tls13.xargs.org/. 