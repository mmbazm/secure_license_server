## Table of Contents
- [Enclace management micro-service](#enclace-management-micro-service)
- [Project Structure](#project-structure)
- [Technical Description/Consideration](#technical-descriptionconsideration)
  - [Sequence Diagram](#sequence-diagram)
- [Exprimentation](#exprimentation)
  - [DataBase](#database)
  - [Build Docker image of Authentication service and run it](#build-docker-image-of-authentication-service-and-run-it)
    - [A) Method 1:](#a-method-1)
    - [B) Method 2:](#b-method-2)
  - [Test service](#test-service)
    - [SignUp endpoint](#signup-endpoint)
      - [Create new user](#create-new-user)
      - [Try to create a user while already exist](#try-to-create-a-user-while-already-exist)
    - [Login endpoint](#login-endpoint)

# Enclace management micro-service

# Project Structure
This project consists of various folders and files, as shown in the following tree:

```
├── Dockerfile
├── docker-compose.yml
├── README.md
├── requirements.txt
└── app
    ├── authentication_pb2_grpc.py
    ├── authentication_pb2.py
    ├── authentication_service.py
    └── authentication.proto
```


# Technical Description/Consideration
The main components of the application are shown in this diagram:

## Sequence Diagram
This section describes the sequences diagram of `Authentication`service:
```mermaid
sequenceDiagram
    actor client
    participant AuthenticationSRV
    participant DB ORM
    participant DB
    activate AuthenticationSRV
    AuthenticationSRV->>AuthenticationSRV: initilize_database()
    AuthenticationSRV->>DB ORM: init_db()
    AuthenticationSRV->>DB ORM: create_table()
    critical Establish a connection to DB
    DB ORM-->DB: connect  
    end
    DB -->>DB ORM: response
    DB ORM->>AuthenticationSRV: true/false
    deactivate AuthenticationSRV
    activate AuthenticationSRV
    client->>AuthenticationSRV: call --> /AuthenticationService/SignUp
    AuthenticationSRV->>AuthenticationSRV: store_login_event()
    AuthenticationSRV->>DB ORM: insert_to_db()
    activate DB ORM
    critical Establish a connection to DB
    DB ORM-->DB: connect  
    end

    DB ORM->>DB: insert()
    DB -->>DB ORM: response


    alt if Error
      DB ORM-->>DB ORM: return(false)
    else if OK
      DB ORM-->>AuthenticationSRV: return(true)
    end
    deactivate DB ORM
    alt if Error
      AuthenticationSRV-->client: return(ERROR)
    else if OK
      AuthenticationSRV-->client: return(User)
    end
    deactivate AuthenticationSRV

```
`Note: Running the container image for the first time will initialize the database.`

# Exprimentation
This section describe how to run the micro service on a local machine using Docker, and then test the exposed endpoit.
## DataBase
To run the database instance, use the official image on DockerHub provided by PostgreSQL:

```bash
docker run --name cn-postgresql -e POSTGRES_PASSWORD=$DATABASE_PASSWORD -p 5002:5432 -e PGDATA=/var/lib/postgresql/data/pgdata -v /path_to_volume/:/var/lib/postgresql/data -d postgres:13
```

* `port:5002` is exposed to external, in order to get access to docker.
* `postgres` is the default user of the instance and `-e POSTGRES_PASSWORD=$DATABASE_PASSWORD` must be used to set a password for the given user.

## Build Docker image of Authentication service and run it
### A) Method 1:
In the directory `auth/` run the following command: 
```bash
docker build -t cn-auth .`, and then execute
```

There are six ENV variables to set when running the container:
* `DATABASE_USER`: database username, its default value is `postgres`
* `DATABASE_PASSWORD`: database password for the given user, here is `postgres`
* `DATABASE_HOST`: database address
* `DATABASE_PORT`: database port, default is `5432`
* `DATABASE_NAME`: database name, default is `usersdb`
* `JWT_SECRET_KEY`: this is the secret key used in the generation of JWT tokens.

### B) Method 2:
Run the `docker-compose.yml' file with the following command
```bash
sudo docker-compose up --build
```
This will build the appropriate Docker image and run the database and service containers accordingly.

## Test service
Finally, testing the service through `grpcurl`.
### SignUp endpoint
#### Create new user
```bash
grpcurl -plaintext -d '{"username": "testuser1", "name": "Test User1", "password": "securepassword"}' localhost:4500
0 AuthenticationService/SignUp
```
Response:
```bash
{
  "user": {
    "id": 3,
    "username": "testuser1",
    "name": "Test User1"
  }
}
```
#### Try to create a user while already exist
```bash
grpcurl -plaintext -d '{"username": "testuser1", "name": "Test User1", "password": "securepassword"}' localhost:4500
0 AuthenticationService/SignUp
```
Response:
```bash
ERROR:
  Code: AlreadyExists
  Message: Username already exists
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