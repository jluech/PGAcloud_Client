import os

import docker

docker_client = None


def print_containers(list_all=False):
    global docker_client
    if not docker_client:
        raise AttributeError("docker client not configured")

    containers = docker_client.containers.list(all=list_all)
    for container in containers:
        print(container.name)


def print_image_history(image_tag):
    global docker_client
    if not docker_client:
        raise AttributeError("docker client not configured")

    images = docker_client.images.list()
    for image in images:
        if image.tags.__contains__(image_tag):
            for tag in image.tags:
                print(tag)

            history = image.history()
            for entry in history:
                for key in entry:
                    print(key, " - ", entry[key])
                print("")
            print("")
            print("")


def get_docker_client(cert_path, host_ip, host_port):
    global docker_client
    if docker_client:
        return docker_client

    tls_config = docker.tls.TLSConfig(
        ca_cert=os.path.join(cert_path, "ca.pem"),
        client_cert=(
            os.path.join(cert_path, "cert.pem"),
            os.path.join(cert_path, "key.pem")
        ),
        verify=True
    )
    docker_client = docker.DockerClient(base_url="tcp://{ip_}:{port_}".format(
        ip_=host_ip,
        port_=host_port
    ),
        tls=tls_config,
        version="auto"
    )
    return docker_client
