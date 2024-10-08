## Table of Contents
- [Authentication Micro-service](#authentication-micro-service)
- [Project Structure](#project-structure)
- [Technical Description/Consideration](#technical-descriptionconsideration)
  - [Sequence Diagram](#sequence-diagram)
- [Exprimentation](#exprimentation)
  - [DataBase](#database)
  - [Build Docker image of Authentication service and run it](#build-docker-image-of-authentication-service-and-run-it)
    - [A) Method 1:](#a-method-1)
    - [B) Method 2:](#b-method-2)

# Authentication Micro-service

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

There are three ENV variables to set when running the container:
* `DEVICEREGISTRATION_API_TOKEN`: is the same as `userKey` provided by the client when sending a request to the API
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
