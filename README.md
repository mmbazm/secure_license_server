
# Secure Licensing Server
## Table of Contents
- [Context](#context)

## Context
The objective is to construct a licensing server that will enable users to authenticate to enclaves (secure computational environments).
To achieve this, it will be necessary to consider a number of design patterns that must be implemented. 
The licensing server will be required to authenticate users to the enclave using a PKI infrastructure. 
The ideal scenario would be to authenticate users via username and password, with the licensing server verifying credentials and initiating an instance of an enclave that can be accessed using a PKI scheme.

## Architecture
This section defines an architecture presenting a solution to the problem, and by defining the steps that we will take to develop and deploy the architecture. The following points are important to consider:

* The cryptographic algorithms and mechanisms for implementing the PKI architecture and the prior authentication with details.
* The licensing server must include the hash of the enclave’s TLS certificate within its TPM quote. 
* The licensing server must return the quote and its public attestation key to the client to verify the quote and compare the enclave’s certificate against the hash contained in the quote.
* The possible usage of a Kubernetes architecture must be taken into account (what and how should it be deployed to enable the licensing server to launch enclaves automatically at user’s request). 

## Implementation
Try to implement the architecture precedently defined (in a docker container with your preferred language) with gRPC. 
The following requirements must be taken into account:
* It is intended to be a container that runs in a Kubernetes node
* Extend the implementation by explaining, in a paragraph or more (and with drawings if necessary), the security changes that should be made to safely provision new keys, handle the authentication and establish a communication channel from the user to the enclave. 
* You can make the assumption that the enclave could be accessible through an IP address or a domain but the client must verify that the TLS certificate provided by the enclave matches the certificate included in the quote from the licensing server before connecting to the enclave. 

## Architecture
```mermaid
flowchart LR
    A["**Client**"] -. 1-SignUp .-> B["**Licensing Service**"]
    B -. 2-Return(access token) .-> A
    A -. 3-Login(access_token) .-> B
    
    subgraph K["**Kubernetes**"]
        C["**Enclave Pod**"]
    end
    
    B -. 4-Request to launch Enclave .-> K
    C -. 5-Transmit certificate .-> B
    
    subgraph L["**Licensing Server**"]
        B -. 5-Request TPM quote .-> D["**TPM**"]
        D -. 6-Return signed quote .-> B
    end

    B -. 7-Send quote, key, and certificate .-> A    
    A -. 8-Request certificate .-> C
    C -. 9-Send back certificate .-> A
    A -. 10-Establish TLS connection .-> C
```

## Sequence Diagram
This section describes the sequences diagram of `Authentication`service:
```mermaid
sequenceDiagram
    participant Client
    participant LicensingServer
    participant TPM
    participant Kubernetes
    participant Enclave

    Client->>LicensingServer: 1. SignUp
    LicensingServer->>Client: 2. Return(access_token)
    Client->>LicensingServer: 3. Login
    LicensingServer->>Kubernetes: 4. Request to launch new Enclave
    Kubernetes->>Enclave: 5. Launch Enclave
    Enclave->>Enclave: 6. Generate TLS certificate
    Enclave->>LicensingServer: 7. Securely transmit certificate
    LicensingServer->>LicensingServer: 8. Calculate hash of Enclave's certificate
    LicensingServer->>TPM: 9. Request TPM quote (including cert hash in PCR)
    TPM->>LicensingServer: 10. Return signed quote
    LicensingServer->>LicensingServer: 11. Prepare response for Client
    LicensingServer->>Client: 12. Send TPM quote, Public Attestation Key, Enclave's TLS cert
    Client->>Client: 13. Verify TPM quote using Public Attestation Key
    Client->>Client: 14. Extract cert hash from quote and compare with received cert
    alt Verification Succeeds
        Client->>Enclave: 15. Request TLS certificate
        Enclave->>Client: 16. Return certificate
        Client->>Client: 17. Compare certificates
        Client->>Enclave: 18. Establish secure TLS connection
    else Verification Fails
        Client->>Client: 17. Abort connection
    end
```