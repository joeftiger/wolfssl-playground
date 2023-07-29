# wolfssl-playground

The wolfssl playground to test the TLS extension for remote attestation in
my [wolfSSL branch](https://github.com/joeftiger/wolfssl/tree/remote-attestation).

## Dependencies

This project depends on the changes in
my [wolfSSL branch](https://github.com/joeftiger/wolfssl/tree/remote-attestation) (do not forget to checkout the
`remote-attestation` branch!).
Please follow wolfSSL's official instructions on how to build it.
However, we require additional flags to be able to work with remote attestation and optional encrypted client hello.
They are given below for cmake:

### Required Feature Flags for wolfSSL

In general we recommend adding the debug flag `-DWOLFSSL_DEBUG=yes`.

| Mode                | Flags                                                                                                                                                                |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TLS                 | `N/A` (default wolfSSL flags suffice)                                                                                                                                |
| TLS with RA         | `-DWOLFSSL_DEBUG=yes -DWOLFSSL_KEYING_MATERIAL=yes -DWOLFSSL_REMOTE_ATTESTATION=yes`                                                                                 |
| TLS with RA and ECH | `-DWOLFSSL_DEBUG=yes -DWOLFSSL_CURVE25519=yes -DWOLFSSL_ECH=yes -DWOLFSSL_HPKE=yes -DWOLFSSL_KEYING_MATERIAL=yes -DWOLFSSL_REMOTE_ATTESTATION=yes -DWOLFSSL_SNI=yes` |

## Structure

This repo contains the following echo-server implementations (and targets for cmake):

1. [echo](./echo): websocket connection between the pair of echo-server and client
2. [tls-echo](./tls-echo): secured by TLS
3. [attestation](./attestation): usage of `RemoteAttestation` extension by introducing a 3rd entity: the verifier
4. [ech-attestation](./ech-attestation): additional encrypted client hello

Every entity is its own executable.
The `client` sends user input from `stdin` to the server, which will echo back what it received.
Every message is split-by and terminated by the newline character, aka `[Enter]` when running interactively.

## Compiling

Create and enter the directory for cmake first like following:

```shell
mkdir cmake
cd cmake
```

### Compile all

To compile everything (is small anyway) you may run:

```shell
cmake ..
cmake --build .
```

### Compile one of the above targets

To compile one of the above mentioned targets you may run, e.g.:

```shell
cmake ..
cmake --build . --target ech-attestation
```

## Running

To run the executables, make sure that the env variable `LD_LIBRARY_PATH` points to the correct path of the custom
wolfSSL library containing the code for remote attestation.
By default, I think, the wolfSSL library is found inside `/usr/local/lib/`, so you will have to run any of the compiled
targets like following:

```shell
LD_LIBRARY_PATH=/usr/local/lib/ ./ech-attestation-server
```

### Order of running

In general, the order of running the executables is the following:

1. `verifier` (if running with remote attestation)
2. `server`
3. Wait for both servers to have started.
4. `client`