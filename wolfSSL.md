# wolfSSL

## TLS Connection

Sources:

- [TLS 1.2](https://tls12.xargs.org/)
- [TLS 1.3](https://tls13.xargs.org/)

## Flow inside wolfSSL

### Keying Material Exporter

Requires to call `wolfSSL_KeepArrays()` before.

> `ssl.c`: `wolfSSL_export_keying_material()`
> > `tls13.c`: `Tls13_Exporter()`

### Client side

> `ssl.c`: `wolfSSL_connect()`
> > `tls13.c`: `wolfSSL_connect_TLSv13()`
> > > `tls13.c`: `SendTls13ClientHello()`
> > > > `tls13.c`: `TLSX_GetRequestSize()`
> > > > > `tls.c`: `TLSX_GetSize()`
> > > > > > `tls.c`: `ATT_GET_SIZE()`
> > > > `tls13.c`: `AddTls13Headers()`
> > > >
> > > > `tls.c`: `TLSX_WriteRequest()`
> > > > - Do we need a semaphore for this???
> > > > > `tls.c`: `TLSX_Write()`
> > > > > > `tls.c`: `EV_WRITE()` -> `TLSX_EvidenceRequest_Write()`
> > > > > > - We have to encode the evidence request data into the extension data.
> > >
> > > ... <br>
> > > `tls13.c`: `DoTls13CertificateVerify()`
> > > > `tls.c`: `VerifyAttestation()`
> > > > > `ssl.c`: `wolfSSL_export_keying_material()`

### Server side

> `ssl.c`: `wolfSSL_accept()`
> > `tls13.c`: `wolfSSL_accept_TLSv13()`
> > > `internal.c`: `ProcessReply()` -> `ProcessReplyEx()` <br>
> > > > `tls13.c`: `DoTls13HandShakeMsg()`
> > > > > `tls.c`: `GetHandshakeHeader()`
> > > > >
> > > > > `tls13.c`: `DoTls13HandShakeMsgType()`
> > > > > > `tls13.c`: `DoTls13ClientHello()`
> > > > > > > `tls13.c`: `TLSX_Parse()`
> > > > > >
> > > > > > `internal.h`: `HashInput()` needed before attestation generation
> > >
> > > `tls13.c`: `SendTls13EncryptedExtensions()`
> > > > > `tls.c`: `GenerateAttestation()`
> > > > > > `ssl.c`: `wolfSSL_export_keying_material()`
> > > > > > >
> > > > > > `tls.c`: `TLSX_UseAttestationRequest()`
> > > > >
> > > > > `tls.c`: `TLSX_WriteResponse()`
> > > > > - What about the semaphores?
> > > > > > `tlc.c`: `TLSX_Write()`
> > > > > > > `tls.c`: `EV_WRITE()` -> `TLSX_EvidenceRequest_Write()`
> > > > > > > - We have to encode the evidence request data into the extension data.