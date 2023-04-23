# wolfSSL

## TLS Connection

Sources:

- [TLS 1.2](https://tls12.xargs.org/)
- [TLS 1.3](https://tls13.xargs.org/)

## Flow inside wolfSSL

### Client side

> `ssl.c`: `wolfSSL_connect()`
> > `tls13.c`: `wolfSSL_connect_TLSv13()`
> > > `tls13.c`: `SendTls13ClientHello()`
> > > > `tls.c`: `TLSX_WriteRequest()`
> > > > - Do we need a semaphore for this???
> > > > > `tls.c`: `TLSX_Write()`
> > > > > > `tls.c`: `EV_WRITE()` -> `TLSX_EvidenceRequest_Write()`

### Server side

> `ssl.c`: `wolfSSL_accept()`
> > `tls13.c`: `wolfSSL_accept_TLSv13()`
> > > TODO