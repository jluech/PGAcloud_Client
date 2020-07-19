import os

import docker

__docker_client = None
__bridge_network = None


def get_docker_client(cert_path, host_addr, host_port):
    global __docker_client
    if __docker_client:
        return __docker_client

    tls_config = docker.tls.TLSConfig(
        ca_cert=os.path.join(cert_path, "ca.pem"),
        client_cert=(
            os.path.join(cert_path, "cert.pem"),
            os.path.join(cert_path, "key.pem")
        ),
        verify=True
    )
    __docker_client = docker.DockerClient(
        base_url="tcp://{addr_}:{port_}".format(
            addr_=host_addr,
            port_=host_port
        ),
        tls=tls_config,
        version="auto",
    )
    return __docker_client


def get_bridge_network():
    global __bridge_network
    if __bridge_network:
        return __bridge_network
    if not __docker_client:
        raise Exception("Create a docker client first, before creating a network...")

    # Creates a new docker network to bridge the manager to a connector.
    __bridge_network = __docker_client.networks.create(
        name="bridge-pga",
        driver="overlay",
        check_duplicate=True,
        attachable=True,
        scope="swarm",
        labels={"PGAcloud": "PGA-Connection"},
    )
    return __bridge_network

