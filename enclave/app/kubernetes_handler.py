from kubernetes import client, config
import base64

def create_namespace(name):
    
    config.load_kube_config()
    v1 = client.CoreV1Api()
    namespace = client.V1Namespace(metadata=client.V1ObjectMeta(name=name))
    v1.create_namespace(namespace)

def push_tls_certificate_to_kubernetes(
    secret_name,
    namespace,
    tls_crt_path,
    tls_key_path,
    ca_crt_path=None
):
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

    # If CA certificate is provided, add it to the secret
    if ca_crt_path:
        with open(ca_crt_path, 'rb') as ca_file:
            ca_crt = base64.b64encode(ca_file.read()).decode('utf-8')
            secret_data['ca.crt'] = ca_crt

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
        print(f"Secret '{secret_name}' created successfully in namespace '{namespace}'")
        return api_response
    except client.ApiException as e:
        if e.status == 409:  # Conflict error code, meaning the secret already exists
            print(f"Secret '{secret_name}' already exists. Updating...")
            try:
                # Update the existing secret
                api_response = api_instance.replace_namespaced_secret(secret_name, namespace, secret)
                print(f"Secret '{secret_name}' updated successfully in namespace '{namespace}'")
                return api_response
            except client.ApiException as update_e:
                print(f"Error updating secret: {update_e}")
                return None
        else:
            print(f"Error creating secret: {e}")
            return None

def check_health(ip, port, endpoint="/health"):
    try:
        url = f"http://{ip}:{port}{endpoint}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"Health check passed for {ip}:{port}")
            return True
        else:
            print(f"Health check failed for {ip}:{port}. Status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"Error during health check for {ip}:{port}: {e}")
        return False

def create_pod(pod_name, secret_name, hostname, subdomain, namespace="default", image='alpine', port=443):
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
        return true
    except client.ApiException as e:
        print(f"Error creating pod: {e}")
        return None

def show_secret(secret_name, namespace="default"):
    config.load_kube_config()

# Create an instance of the API class
    v1 = client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(secret_name, namespace)
        print(f"Secret: {secret_name}")
        for key, value in secret.data.items():
            print(f"  {key}: {value}")
    except client.exceptions.ApiException as e:
        print(f"Exception when calling CoreV1Api->read_namespaced_secret")


def check_pod_status(pod_name, namespace="default"):
    # Load Kubernetes configuration
    config.load_kube_config()

    # Create an instance of the API class
    api_instance = client.CoreV1Api()

    try:
        # Get the pod status
        api_response = api_instance.read_namespaced_pod_status(name=pod_name, namespace=namespace)
        
        # Check if the pod is running
        if api_response.status.phase == 'Running':
            print(f"Pod {pod_name} is running.")
            return True
        else:
            print(f"Pod {pod_name} is not running. Current status: {api_response.status.phase}")
            return False

    except client.ApiException as e:
        print(f"Exception when calling CoreV1Api->read_namespaced_pod_status: {e}")
        return False
