# wolfSSL Implementation for Remote Attestation

## Protocol
| Client                              | Server                                          |
|-------------------------------------|-------------------------------------------------|
| Client Hello { AttestationRequest } |                                                 |
|                                     | Server Hello                                    |
|                                     | Server Encrypted Extensions { AttestationData } |
|                                     | Server Certificate                              |
|                                     | Server Certificate Verify                       |
|                                     |                                                 |

## Generation of Attestation Evidence
The attestation certificate contains
- public key `PKₜₗₛ`
- attestation claims
One of which must be 

[//]: # (TODO)





# OLD STUFF BELOW

# wolfSSL Implementation for draft-fossati-tls-attestation-03

https://www.ietf.org/archive/id/draft-fossati-tls-attestation-03.html

## Evidence Extensions

The evidence will be transmitted as either
1. **Attestation-only**: requires new Certificate Type by IANA.
2. **Attestation alongside X.509 certificates**: 

## IANA Considerations

- [x] Extend `enum TLSX_Type` to contain the new extension types `evidence_proposal` and `evidence_request`.
  > Added `TLSX_EVIDENCE_PROPOSAL` and `TLSX_EVIDENCE_REQUEST` with arbitrary IDs until IANA standardizes them.
- [x] Extend `enum AlertDescription` to contain the new alert type `unsupported_evidence` and implement
  `char* AlertTypeToString()` accordingly.
  > Added `unsupported_evidence` with arbitrary ID until IANA standardizes it.
  > Implemented `AlertTypeToString()` in an analogous manner to other alerts.
- [ ] Implement the new TLS Certificate type `Attestation`.
  > I do not find where they support different certificate types. Is it `enum CertType`?
  > It contains way too many types though???

  > This requires the extensions `client_certificate_type` and `server_certificate_type` to specify the certificate type.
  > However, wolfSSL does not seem to support these extensions. Meaning, that 

## TLS Client and Server Handshake Behavior

### Client Hello

- [ ] Extend API to add the `evidence_proposal` or `evidence_request` extension in the ClientHello.
