## Table of Contents
- [Enclave management micro-service](#enclave-management-micro-service)
- [Project Structure](#project-structure)
- [Sequence Diagram](#sequence-diagram)
- [Exprimentation](#exprimentation)
  - [DataBase](#database)
  - [Build Docker image of Authentication service and run it](#build-docker-image-of-authentication-service-and-run-it)
    - [A) Method 1:](#a-method-1)
    - [B) Method 2:](#b-method-2)
  - [Test service](#test-service)
    - [SignUp endpoint](#signup-endpoint)
    - [Login endpoint](#login-endpoint)
      - [Launch an enclave](#launch-an-enclave)
      - [Get enclave status](#get-enclave-status)

# Enclave management micro-service

# Project Structure
This project consists of various folders and files, as shown in the following tree:

```
├── app
│   ├── certificate_helper.py
│   ├── enclaveOperations_pb2_grpc.py
│   ├── enclaveOperations_pb2.py
│   ├── enclaveOperations.proto
│   ├── enclave_operations_service.py
│   ├── kubernetes_handler.py
│   └── kubernetes_handler.py
├── config
│   └── params.ini
├── docker-compose.yml
├── Dockerfile
├── enclave_operations_client.py
├── files
│   ├── root_ca.crt
│   ├── root_ca.key
│   ├── server_private_ak.pem
│   └── server_public_ak.pem
├── README.md
└── requirements.txt
```

# Sequence Diagram
This section describes the sequences diagram of `Enclave`service:
```mermaid
sequenceDiagram
    actor client
    participant EnclaveOperations
    participant DB ORM
    participant DB
    participant Kubernetes
    client->>EnclaveOperations: call --> /EnclaveOperations/EnclaveLaunch)
    EnclaveOperations->>DB ORM: get_access_token(username)
    activate DB ORM
    critical Establish a connection to DB
    DB ORM-->DB: connect  
    end
    DB -->>DB ORM: response
    alt if Error
      DB ORM-->>EnclaveOperations: return(false)
    else if OK
      DB ORM-->>EnclaveOperations: return(true)
    end
    deactivate DB ORM
    alt if Error
      EnclaveOperations-->client: return(ERROR)
    else if OK
      EnclaveOperations-->EnclaveOperations: generate_tls_cert()
      EnclaveOperations-->Kubernetes: push_tls_cert()
      EnclaveOperations-->Kubernetes: launch_enclave()
      Kubernetes-->Kubernetes: launch_enclave()
      EnclaveOperations-->client: enclave_info()
    end

    client->>EnclaveOperations: call --> /EnclaveOperations/EnclaveStatus)
    EnclaveOperations->>DB ORM: get_enclavename(username)
    activate DB ORM
    critical Establish a connection to DB
    DB ORM-->DB: connect  
    end
    DB -->>DB ORM: response
    alt if Error
      DB ORM-->>EnclaveOperations: return(false)
    else if OK
      DB ORM-->>EnclaveOperations: return(true)
    end
    deactivate DB ORM
    alt if Error
      EnclaveOperations-->client: return(ERROR)
    else if OK
      EnclaveOperations-->Kubernetes: get_enclave_status()
      Kubernetes-->EnclaveOperations: enclave_status
      EnclaveOperations-->client: enclave_status
    end
```

# Exprimentation
This section describe how to run the micro service on a local machine using Docker, and then test the exposed endpoit.
## DataBase
To run the database instance, use the official image on DockerHub provided by PostgreSQL:

```bash
docker run --name cn-postgresql -e POSTGRES_PASSWORD=$DATABASE_PASSWORD -p 5432:5432 -e PGDATA=/var/lib/postgresql/data/pgdata -v /path_to_volume/:/var/lib/postgresql/data -d postgres:13
```

* `port:5002` is exposed to external, in order to get access to docker.
* `postgres` is the default user of the instance and `-e POSTGRES_PASSWORD=$DATABASE_PASSWORD` must be used to set a password for the given user.

## Build Docker image of Authentication service and run it
### A) Method 1:
In the directory `enclave/` run the following command: 
```bash
docker build -t cn-auth .`, and then execute
```

There are six ENV variables to set when running the container:
* `DATABASE_USER`: database username, its default value is `postgres`
* `DATABASE_PASSWORD`: database password for the given user, here is `postgres`
* `DATABASE_HOST`: database address
* `DATABASE_PORT`: database port, default is `5432`
* `DATABASE_NAME`: database name, default is `usersdb`

### B) Method 2:
Run the `docker-compose.yml' file with the following command
```bash
sudo docker-compose up --build
```
This will build the appropriate Docker image and run the database and service containers accordingly.

## Test service
Finally, testing the service through `grpcurl`.

### SignUp endpoint
```bash
grpcurl -plaintext -d '{"username": "user1", "password": "securepass123", "name": "New User1"}' localhost:45000 AuthenticationService/SignUp
```
Response:
```bash
{
  "user": {
    "id": 1,
    "username": "user1",
    "name": "New User1"
  }
}
```
### Login endpoint
```bash
grpcurl -plaintext -d '{"username": "testuser1", "password": "securepassword"}' localhost:45000 AuthenticationServic
e/Login
```
Response:
```bash
{
  "user": {
    "id": 3,
    "username": "testuser1",
    "name": "Test User1"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsImV4cCI6MTcyODM5NDc5NywidXNlcm5hbWUiOiJ0ZXN0dXNlcjEiLCJuYW1lIjoiVGVzdCBVc2VyMSJ9.XgQSALiV6GE5fSCyeNSfUwAUsp4u_ZVw79mpxEEQOUM"
}
```
#### Launch an enclave
```bash
grpcurl -plaintext -d "{\"username\": \"user1\", \"access_token\": \"$access_token\"}" localhost:55000 EnclaveOperations/
EnclaveLaunch
```
Response:
```bash
{
  "enclave_name": "enclave-1",
  "access_point": "enclave-1.example.com",
  "tls_certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURhekNDQWxPZ0F3SUJBZ0lDQStnd0RRWUpLb1pJaHZjTkFRRUxCUUF3ZXpFTE1Ba0dBMVVFQmhNQ1JsSXgKRXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTURWTmhiaUJHY21GdVkybHpZMjh4RXpBUgpCZ05WQkFvTUNrMTVJRU52YlhCaGJua3hHREFXQmdOVkJBc01EMDE1SUU5eVoyRnVhWHBoZEdsdmJqRVFNQTRHCkExVUVBd3dIVW05dmRDQk",
  "public_attestation_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwcGRCSzcycklNRGNNZkpaQ0RFdApPQmJnSmQrYlNqdHdFYWhvYytGdndUeFRRMnN3QkN3VzZiWnl6WEROVEEwZDR1RkZ4NDZtRXpUalNTelV2bHNWCkxMN2ZaNlo0dDVla3R1M2Z2RUtvUkRKQWlna1NmeHZSMmxxa040T1B2V24yWDA1N051VXNUS3RtUVl1UzlRbGcKSnhxaEZ6Nm12QkR6N2krb0",
  "tpm_quote": {
    "tls_certificate_hash": "140dda0c5ed75e54754ae86d26cdfecb429ea64a6",
    "signature": "YlVuaFRqTVFLellpVXFBRE5NZGZTYVc"
  }
}
```
#### Get enclave status
```bash
grpcurl -plaintext -d "{\"username\": \"user1\", \"access_token\": \"$access_token\"}" localhost:55000 EnclaveOperations/
EnclaveStatus
```
Response:
```bash
{
  "enclave_status": "running"
}
```