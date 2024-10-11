"""
File: enclave_operations.py

This file contains the EnclaveOperations class, which implements the EnclaveOperationsServicer
for managing enclave operations in a secure computing environment.

Class: EnclaveOperations

The EnclaveOperations class provides methods for launching enclaves, retrieving enclave status,
and managing enclave IDs. It serves as a core component in the enclave management system.

Methods:
    - EnclaveLaunch: Launches a new enclave and returns its name, TLS certificate, TPM Quote, Access point, and Pulic attestation of server.
    - get_last_enclave_id: Retrieves the ID of the last launched enclave.
    - EnclaveStatus: Checks and returns the status of a specific enclave.

The class interacts with protocol buffer generated files (enclaveOperations_pb2 and 
enclaveOperations_pb2_grpc) to handle gRPC service calls related to enclave operations.

Usage:
    This class is typically used as part of a gRPC server implementation for enclave management.

Dependencies:
    - enclaveOperations_pb2
    - enclaveOperations_pb2_grpc

Author: MMB
"""
import os
import logging
import subprocess
import grpc
from concurrent import futures
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import enclaveOperations_pb2
import enclaveOperations_pb2_grpc
from grpc_reflection.v1alpha import reflection
import certificate_helper as cert_helper
import kubernetes_handler as kube_helper
import configparser


# Create an instance of ConfigParser
config = configparser.ConfigParser()
config.read("../config/params.ini")

root_cert_path = '../files/root_ca.crt'
root_priv_key_path = '../files/root_ca.key'


# Define DB URI template
URI_TEMPLATE = (
    "postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

DATABASE_URL = URI_TEMPLATE.format(
    DB_USER=os.environ['DATABASE_USER'],
    DB_PASSWORD=os.environ['DATABASE_PASSWORD'],
    DB_HOST=os.environ['DATABASE_HOST'],
    DB_PORT=os.environ['DATABASE_PORT'],
    DB_NAME=os.environ['DATABASE_NAME']
)

# Database setup
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# Define the base class for declarative models
Base = declarative_base()


class Enclave(Base):
    """Enclave model representing the database table for storing enclave information."""

    __tablename__ = 'enclaves'

    id = Column(Integer, primary_key=True)
    username = Column(String(256), nullable=False)
    enclave_name = Column(String(256), nullable=False)
    access_point = Column(String(256), nullable=False)

    def __repr__(self):
        return (f"<Enclave(id={self.id}, username='{self.username}', "
                f"enclave_name='{self.enclave_name}', access_point='{self.access_point}')>")


# Create tables in the database if they do not exist
Base.metadata.create_all(engine)


class AccessToken(Base):
    """AccessToken model representing the database table for storing access tokens."""

    __tablename__ = 'access_tokens'

    # 'username' as the primary key
    username = Column(String(256), primary_key=True)
    # Adjust length as needed
    access_token = Column(String(512), nullable=False)

    def __repr__(self):
        return f"<AccessToken(username='{self.username}', access_token='{self.access_token}')>"


class EnclaveOperations(enclaveOperations_pb2_grpc.EnclaveOperationsServicer):
    """gRPC service for managing enclave operations."""

    def __init__(self):
        self.server_root_cert_name = root_cert_path
        self.server_key_name = root_priv_key_path

        if not os.path.exists(self.server_root_cert_name) or not os.path.exists(self.server_key_name):
            cert_helper.generate_root_certificate()

    def get_last_enclave_id(self, session):
        """Retrieves the last enclave ID from the database.

        Args:
            session: The SQLAlchemy session object.

        Returns:
            The last enclave ID or None if no records exist.
        """
        last_enclave = session.query(Enclave).order_by(
            Enclave.id.desc()).first()
        return last_enclave.id if last_enclave else None

    def EnclaveLaunch(self, request, context):
        """Handles the launch of a new enclave.

        Args:
            request: A request object containing the username and access token.
            context: The gRPC context for setting response details and status codes.

        Returns:
            An EnclaveLaunchResponse containing the enclave name and access point.
        """
        # Read Kubernetes config
        config_kubernetes = config["KUBERNETES"]

        # Start a new session
        session = Session()

        try:
            # Retrieve the last enclave ID to set as enclave_counter
            last_id = self.get_last_enclave_id(session)
            enclave_counter = (last_id + 1) if last_id is not None else 1

            # Check if the username and access token are valid
            access_token_entry = session.query(AccessToken).filter_by(
                username=request.username, access_token=request.access_token).first()

            if not access_token_entry:
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                context.set_details("Invalid username or access token")
                return enclaveOperations_pb2.EnclaveLaunchResponse()

            # Check if the user has already an Enclave
            res_enclaves = session.query(Enclave).filter_by(
                username=request.username).first()

            if res_enclaves is not None:
                return enclaveOperations_pb2.EnclaveLaunchResponse(
                    enclave_name=res_enclaves.enclave_name,
                    access_point=res_enclaves.access_point
                )

            # Generate a new enclave name and access point
            enclave_name = f"enclave-{enclave_counter}"
            access_point = f"enclave-{enclave_counter}.example.com"
            enclave_domain = f"enclave-{enclave_counter}.example.com"

            # Store the enclave information in the database
            new_enclave = Enclave(
                username=request.username,
                enclave_name=enclave_name,
                access_point=access_point
            )
            session.add(new_enclave)
            session.commit()

            # Generate a TLS certificate for enclave
            cert_helper.generate_server_certificate(
                self.server_root_cert_name, self.server_key_name, enclave_domain)

            # Generate hash of TLS certificate
            cert_hash = cert_helper.generate_hash_crt_file(
                f"{enclave_domain}.crt")
            cert_hash_signature = cert_helper.sign_hash_with_private_key(
                cert_hash, '../files/server_private_ak.pem')

            # Push TLS certificate to Kubernetes
            kube_helper.push_tls_certificate_to_kubernetes(
                secret_name=f"{enclave_name}-tls-secret",
                namespace="tpm",
                tls_crt_path=f"{enclave_domain}.crt",
                tls_key_path=f"{enclave_domain}.key"
            )

            # Create pod in Kubernetes
            kube_res = kube_helper.create_pod(
                pod_name=enclave_name,
                image=config_kubernetes.get("ENCLAVE_IMAGE"),
                secret_name=f"{enclave_name}-tls-secret",
                hostname=enclave_name,
                subdomain=enclave_domain,
                namespace=config_kubernetes.get("NAMESPACE")
            )

            if kube_res is None:
                raise Exception("Pod launching failed")

            with open('../files/server_public_ak.pem', 'rb') as pem_file:
                server_public_ak_pem_data = pem_file.read()

            with open("{}.crt".format(enclave_domain), 'rb') as crt_file:
                enclave_cert_pem_data = crt_file.read()

            # First, create the TpmQuote message
            tpm_quote = enclaveOperations_pb2.TpmQuote(
                tls_certificate_hash=cert_hash,
                signature=cert_hash_signature
            )

            # Create final response
            return enclaveOperations_pb2.EnclaveLaunchResponse(
                enclave_name=enclave_name,
                access_point=access_point,
                tls_certificate=enclave_cert_pem_data,
                public_attestation_key=server_public_ak_pem_data,
                tpm_quote=tpm_quote
            )

        except Exception as e:
            session.rollback()
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return enclaveOperations_pb2.EnclaveLaunchResponse()

        finally:
            # Remove generated certificate
            files_to_delete = [
                f"{enclave_domain}.crt", f"{enclave_domain}.key"]

            [os.remove(fi) for fi in files_to_delete if os.path.exists(fi)]

            session.close()

    def EnclaveStatus(self, request, context):
        """Checks the status of an existing enclave for a user.

        Args:
            request: A request object containing the username.
            context: The gRPC context for setting response details and status codes.

        Returns:
            An EnclaveStatusResponse containing the status of the user's enclave.
        """

        config_kubernetes = config["KUBERNETES"]

        session = Session()
        try:
            # Check if the username and access token are valid
            access_token_entry = session.query(AccessToken).filter_by(
                username=request.username, access_token=request.access_token).first()

            if not access_token_entry:
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                context.set_details("Invalid username or access token")
                return enclaveOperations_pb2.EnclaveLaunchResponse()

            res_enclaves = session.query(Enclave).filter_by(
                username=request.username).first()
            if not res_enclaves:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("No enclave found for user")
                return enclaveOperations_pb2.EnclaveStatusResponse()

            else:
                # Get the status of the user's last enclave
                kube_enclave_status = kube_helper.check_pod_status(
                    res_enclaves.enclave_name, config_kubernetes.get("namespace"))

                if kube_enclave_status:
                    return enclaveOperations_pb2.EnclaveStatusResponse(
                        enclave_status="running"
                    )
                else:
                    return enclaveOperations_pb2.EnclaveStatusResponse(
                        enclave_status="not running"
                    )

        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return enclaveOperations_pb2.EnclaveStatusResponse()

        finally:
            session.close()


def serve():
    """Starts the gRPC server to listen for requests."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    enclaveOperations_pb2_grpc.add_EnclaveOperationsServicer_to_server(
        EnclaveOperations(), server)

    # Enable reflection on the server
    service_names = (
        enclaveOperations_pb2.DESCRIPTOR.services_by_name['EnclaveOperations'].full_name,
        reflection.SERVICE_NAME,
    )

    reflection.enable_server_reflection(service_names, server)

    server.add_insecure_port('[::]:55000')
    print("Enclave operations server started on the port 55000")
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
