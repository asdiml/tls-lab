# TLS Lab

This project is part of UCLA ACM Cyber's series of quarterly projects where a topic within cybersecurity is chosen for exploration. 

As the name suggests, this project deals with Transport Layer Security (TLS), and specifically attempts to implement TLS v1.3 for a better understanding of how a secure communication channel is set-up across the web. 

## Running our TLS v1.3 implementation

> This project is incomplete. The following commands will not result in a working TLS handshake and opening of secure channel for data exchange. 

Run the module by running the command

```bash
python3 -m tlsimpl
```

from the root directory of the repo. The (fake) server that we will communicate is OpenSSL's s_server from which we will receive the [Server Hello](https://tls13.xargs.org/#server-hello), etc. 

## Authors

Credit is due to the leads of this ACM Cyber lab Jason An, Mark Epstein, Gary Song and Arnav Vora for providing the [base repo](https://github.com/pbrucla/tls-lab-skel) from which this repo was forked. 

The authors of this fork of the project are Teong Seng Tan, Prabvhir Babra, and Lucas ???. 