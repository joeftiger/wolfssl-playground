# wolfssl-playground

The wolfssl playground to test the TLS extension for remote attestation in my [wolfssl branch](https://github.com/joeftiger/wolfssl/tree/remote-attestation).

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