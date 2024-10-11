"""
kubernetes_handler.py

This module provides utility functions for interacting with a Kubernetes cluster.
It includes operations for managing pods, namespaces, and TLS certificates.

Functions:
    push_tls_certificate_to_kubernetes: Push TLS certificate and key to Kubernetes as a Secret.
    create_pod: Create a Kubernetes Pod with specified parameters.
    check_pod_status: Check the status of a specific Kubernetes pod.
    create_namespace: Create a new namespace in the Kubernetes cluster.

This module requires the Kubernetes Python client library and appropriate
cluster access configurations. Ensure that kubectl is properly configured
with the target cluster before using these functions.

Dependencies:
    - kubernetes

@author: MMB
"""

from kubernetes import client, config
import base64


def create_namespace(name):
    """
    Create a new namespace in the Kubernetes cluster.

    This function attempts to create a namespace with the specified name in the
    Kubernetes cluster. If the namespace already exists, it will not raise an error.

    Args:
        name (str): The name of the namespace to create. Must be a valid Kubernetes
                    resource name (lowercase alphanumeric characters or '-', 
                    and must start and end with an alphanumeric character).

    Returns:
        True if namespace is created successfully, otherwise False
    """

    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        namespace = client.V1Namespace(metadata=client.V1ObjectMeta(name=name))
        v1.create_namespace(namespace)
        print(f"Namespace: {name} created successfully")
        return True
    except Exception as e:
        print(f"Error creating namespace({name}): {e}")
        return False


def push_tls_certificate_to_kubernetes(
    secret_name,
    namespace,
    tls_crt_path,
    tls_key_path
):
    """
    Push TLS certificate and key to Kubernetes as a Secret.

    This function creates or updates a Kubernetes Secret with TLS certificate data.
    It reads the certificate and key files from the specified paths and stores them
    in a Secret within the given namespace.

    Args:
        secret_name (str): The name of the Kubernetes Secret to create or update.
        namespace (str): The Kubernetes namespace where the Secret will be stored.
        tls_crt_path (str): File path to the TLS certificate.
        tls_key_path (str): File path to the TLS private key.

    Returns:
        api_response if ok, otherwise None
    """

    # Load Kubernetes configuration
    config.load_kube_config()

    # Create a Kubernetes API client
    api_instance = client.CoreV1Api()

    # Read the certificate files
    with open(tls_crt_path, 'rb') as crt_file, open(tls_key_path, 'rb') as key_file:
        tls_crt = base64.b64encode(crt_file.read()).decode('utf-8')
        tls_key = base64.b64encode(key_file.read()).decode('utf-8')

    # Prepare the secret data
    secret_data = {
        'tls.crt': tls_crt,
        'tls.key': tls_key
    }

    # Create the Secret object
    secret = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(name=secret_name),
        type="kubernetes.io/tls",
        data=secret_data
    )

    try:
        # Create the Secret in Kubernetes
        api_response = api_instance.create_namespaced_secret(namespace, secret)
        print(
            f"Secret '{secret_name}' created successfully in namespace '{namespace}'")
        return api_response
    except client.ApiException as e:
        if e.status == 409:  # Conflict error code, meaning the secret already exists
            print(f"Secret '{secret_name}' already exists. Updating...")
            try:
                # Update the existing secret
                api_response = api_instance.replace_namespaced_secret(
                    secret_name, namespace, secret)
                print(
                    f"Secret '{secret_name}' updated successfully in namespace '{namespace}'")
                return api_response
            except client.ApiException as update_e:
                print(f"Error updating secret: {update_e}")
                return None
        else:
            print(f"Error creating secret: {e}")
            return None


def create_pod(pod_name, secret_name, hostname, subdomain, namespace="default", image='alpine', port=443):
    """
    Create a Kubernetes Pod with specified parameters.

    This function creates a Pod in the Kubernetes cluster with the given configuration,
    including a TLS secret, hostname, and subdomain.

    Args:
        pod_name (str): The name of the Pod to be created.
        secret_name (str): The name of the TLS secret to be used by the Pod.
        hostname (str): The hostname to be assigned to the Pod.
        subdomain (str): The subdomain to be used for the Pod's DNS.
        namespace (str, optional): The Kubernetes namespace where the Pod will be created. 
                                   Defaults to "default".
        image (str, optional): The container image to be used for the Pod. 
                               Defaults to 'alpine'.
        port (int, optional): The port number to be exposed by the container. 
                              Defaults to 443.

    Returns:
        True if ok, otherwise None
    """

    # Load Kubernetes configuration
    config.load_kube_config()

    # Create a Kubernetes API client
    api_instance = client.CoreV1Api()

    # Define the environment variables from the secret
    env_from_secret = [
        client.V1EnvFromSource(
            secret_ref=client.V1SecretEnvSource(
                name=secret_name
            )
        )
    ]

    # Define the pod
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=pod_name,
            namespace=namespace
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name=hostname,
                    image=image,
                    ports=[client.V1ContainerPort(container_port=port)],
                    env_from=env_from_secret
                )
            ]
        )
    )

    # Create the pod
    try:
        api_response = api_instance.create_namespaced_pod(namespace, pod)
        print(f"Pod {pod_name} created successfully")
        return True
    except client.ApiException as e:
        print(f"Error creating pod: {e}")
        return None


def check_pod_status(pod_name, namespace="default"):
    """
    Check the status of a specific Kubernetes pod.

    This function retrieves and returns the current status of a pod in the specified namespace.
    It provides information about the pod's phase, conditions, and container statuses.

    Args:
        pod_name (str): The name of the pod to check.
        namespace (str, optional): The Kubernetes namespace where the pod is located. 
                                   Defaults to "default".

    Returns:
        True if pod is running, otherwise False
    """

    # Load Kubernetes configuration
    config.load_kube_config()

    # Create an instance of the API class
    api_instance = client.CoreV1Api()

    try:
        # Get the pod status
        api_response = api_instance.read_namespaced_pod_status(
            name=pod_name, namespace=namespace)

        # Check if the pod is running
        if api_response.status.phase == 'Running':
            print(f"Pod {pod_name} is running.")
            return True
        else:
            print(
                f"Pod {pod_name} is not running. Current status: {api_response.status.phase}")
            return False

    except client.ApiException as e:
        print(
            f"Exception when calling CoreV1Api->read_namespaced_pod_status: {e}")
        return False
