import os
import time
import traceback

import click
import logbook
import requests

from client import docker_utils, utils
from client.provider_drivers.vSphere_driver import VSphereDockerDriver

logger = logbook.Logger('client')
http = requests.sessions.Session()

CLIENT_CLI_CONTEXT_FILE = os.getcwd() + "\\client\\cli_context.yml"
CLIENT_CLI_CONTEXT_KEYS = [
    "orchestrator",
    "master_host",
    "master_port",
    "cert_path",
    "SSL_CA_PEM_ID",
    "SSL_CERT_PEM_ID",
    "SSL_KEY_PEM_ID",
]
CLIENT_CLI_CONTEXT_DEFAULTS = {
    "orchestrator": "docker",
    "master_port": 5000
}

WAIT_FOR_CONFIRMATION_DURATION = 45.0
WAIT_FOR_CONFIRMATION_EXCEEDING = 15.0
WAIT_FOR_CONFIRMATION_TROUBLED = 30.0
WAIT_FOR_CONFIRMATION_SLEEP = 3  # seconds


@click.group()
@click.pass_context
def client(ctx):
    # Initializes the meta context.
    stored_context = utils.read_context(CLIENT_CLI_CONTEXT_FILE)

    for key in CLIENT_CLI_CONTEXT_KEYS:
        if not stored_context.get(key):
            if CLIENT_CLI_CONTEXT_DEFAULTS.keys().__contains__(key):
                ctx.meta[key] = CLIENT_CLI_CONTEXT_DEFAULTS[key]
            else:
                ctx.meta[key] = None
        else:
            ctx.meta[key] = stored_context.get(key)


@client.group()
def config():
    pass


@config.command()
@click.pass_context
@click.argument("host", type=str, required=False)
def master_host(ctx, host):
    """
        Update the configuration for the master host (ip address or hostname) in the cloud.
        If no argument is provided, it will print the current configuration.

        :param host: the master host (ip address or hostname).
        :type host: str

        :param ctx: the click cli context, automatically passed by cli.
        """
    if not host:
        if ctx.meta["master_host"]:
            click.echo("Current master host: {host_}".format(host_=ctx.meta["master_host"]))
        else:
            click.echo("Master IP currently not set. You can set it by providing an argument to this function.")
        return

    changed = False
    if ctx.meta["master_host"]:
        valid_prompt = False
        while not valid_prompt:
            prompt = click.prompt(
                text="Master host currently set to {master_host_} - Do you want to overwrite?".format(
                    master_host_=ctx.meta["master_host"]
                ),
                type=click.Choice(["y", "n"]),
                show_choices=True,
                default="n",
                show_default=False
            )
            if prompt == "y":
                ctx.meta["master_host"] = host
                valid_prompt = True
                click.echo("Updated master host to {host_}".format(host_=host))
                changed = True
            elif prompt == "n":
                click.echo("Aborted setting master host")
                valid_prompt = True
    else:
        ctx.meta["master_host"] = host
        changed = True

    # Updates the meta context storage file.
    if changed:
        utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@config.command()
@click.pass_context
@click.argument("port", type=int, required=False)
def master_port(ctx, port):
    """
    Update the configuration for the exposed port on the master host to map to containers.
    If no argument is provided, it will print the current configuration.

    :param port: the master host port to expose for mapping.
    :type port: int

    :param ctx: the click cli context, automatically passed by cli.
    """
    if not port:
        if ctx.meta["master_port"]:
            click.echo("Current master port: {port_}".format(port_=ctx.meta["master_port"]))
        else:
            click.echo("Master port currently not set. You can set it by providing an argument to this function.")
        return

    changed = False
    if ctx.meta["master_port"]:
        valid_prompt = False
        while not valid_prompt:
            prompt = click.prompt(
                text="Master port currently set to {master_port_} - Do you want to overwrite?".format(
                    master_port_=ctx.meta["master_port"]
                ),
                type=click.Choice(["y", "n"]),
                show_choices=True,
                default="n",
                show_default=False
            )
            if prompt == "y":
                ctx.meta["master_port"] = port
                valid_prompt = True
                click.echo("Updated master port to {port_}".format(port_=port))
                changed = True
            elif prompt == "n":
                click.echo("Aborted setting master port")
                valid_prompt = True
    else:
        ctx.meta["master_port"] = port
        changed = True

    # Updates the meta context storage file.
    if changed:
        utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@config.command()
@click.pass_context
@click.argument("cert_path", type=click.Path(exists=True), required=False)
def certificates(ctx, cert_path):
    """
    Update the configuration for the path to the SSL certificates required for secure connection to cloud master host.
    If no argument is provided, it will print the current configuration.

    :param cert_path: the path to the certificates.
    :type cert_path: str

    :param ctx: the click cli context, automatically passed by cli.
    """
    if not cert_path:
        if ctx.meta["cert_path"]:
            click.echo("Current certificates path: {path_}".format(path_=ctx.meta["cert_path"]))
        else:
            click.echo("Certificates path currently not set. You can set it by providing an argument to this function.")
        return

    changed = False
    if ctx.meta["cert_path"]:
        valid_prompt = False
        while not valid_prompt:
            prompt = click.prompt(
                text="Certificates path currently set to {path_} - Do you want to overwrite?".format(
                    path_=ctx.meta["cert_path"]
                ),
                type=click.Choice(["y", "n"]),
                show_choices=True,
                default="n",
                show_default=False
            )
            if prompt == "y":
                ctx.meta["cert_path"] = cert_path
                valid_prompt = True
                click.echo("Updated certificates path to {path_}".format(path_=cert_path))
                changed = True
            elif prompt == "n":
                click.echo("Aborted setting certificates path")
                valid_prompt = True
    else:
        ctx.meta["cert_path"] = cert_path
        changed = True

    # Updates the meta context storage file.
    if changed:
        utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@client.group()
@click.pass_context
@click.option("--orchestrator", "-o", "orchestrator",
              type=click.Choice(["docker", "kubernetes"]),
              default="docker")
def cloud(ctx, orchestrator):
    ctx.meta["orchestrator"] = orchestrator


@cloud.command()
@click.pass_context
@click.option("--provider", "-p", "provider_name",
              type=click.Choice(["amazon", "openstack", "virtualbox", "vsphere"]),
              default="vsphere")
@click.option("--configuration", "-c", "configuration_file_path", type=click.Path(exists=True), required=True)
def create(ctx, provider_name, configuration_file_path):
    """
    Create and setup the cloud environment.

    :param provider_name: the cloud provider name.
    :type provider_name: str

    :param configuration_file_path: the path to the cloud configuration file.
    :type configuration_file_path: str

    :param ctx: the click cli context, automatically passed by cli.
    """
    # Retrieves the configuration.
    configuration = get_configuration(configuration_file_path)

    # Recognizes the correct driver.
    driver = get_driver(provider_name, ctx.meta["orchestrator"], configuration, logger)
    click.echo(driver.name)

    # Creates the cloud environment.
    driver.setup_cloud_environment()

    # Saves the manager's IP address.
    manager_host, error = utils.execute_command(
        command="docker-machine ip dockermaster",
        working_directory=os.curdir,
        environment_variables=None,
        executor=None,
        logger=logger,
    )
    if error:
        logger.error(error)
        click.echo(error)
    else:
        if not ctx.meta["master_host"]:
            click.echo("Setting master host {host_}".format(host_=manager_host))
        else:
            click.echo("Updating config for master host to {host_}".format(host_=manager_host))
        ctx.meta["master_host"] = manager_host

    # Updates the meta context storage file.
    utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@cloud.command()
@click.pass_context
@click.option("--port", "-p", "port", type=int)
@click.argument("cert_path", type=click.Path(exists=True), required=False)
def init(ctx, port, cert_path):
    """
    Initialize the PGA Manager.

    :param port: the external port on the host to map to the container.
                    Defaults to the current meta config. See :func:`config` for reference.
    :type port: int

    :param cert_path: the path to a folder containing your SSL certificates.
                Can also be set in the context, see 'config certificates'.
    :type cert_path: str

    :param ctx: the click cli context, automatically passed by cli.
    """
    # Retrieves the certificates path.
    if not cert_path:
        if not ctx.meta["cert_path"]:
            raise Exception("No certificates path defined! You can define it by providing it as an argument "
                            "or by explicitly setting it with command 'client config cert-path'. "
                            "Type 'client config cert-path --help' for more details.")
        cert_path = ctx.meta["cert_path"]
    else:
        ctx.meta["cert_path"] = cert_path
        click.echo("Updating config for certificates path to {path_}".format(path_=ctx.meta["cert_path"]))

    # Sets the port if not provided.
    if not port:
        port = ctx.meta["master_port"]

    # Ensures there is a known host to connect to.
    if not ctx.meta["master_host"]:
        raise Exception("No master host defined! You can define it by creating the cloud environment "
                        "or by explicitly setting it with command 'client config master-host'. "
                        "Type 'client config master-host --help' for more details.")

    # Initializes the PGA manager via the selected orchestrator.
    if ctx.meta["orchestrator"] == "docker":
        # Creates a docker client to issue docker commands via SSL connection.
        docker_client = docker_utils.get_docker_client(
            cert_path=cert_path,
            host_addr=ctx.meta["master_host"],
            host_port=2376
            # default docker port; Note above https://docs.docker.com/engine/security/https/#secure-by-default
        )

        # Creates docker secrets for sharing the SSL certificates.
        ssl_ca_path = os.path.join(cert_path, "ca.pem")
        ssl_cert_path = os.path.join(cert_path, "cert.pem")
        ssl_key_path = os.path.join(cert_path, "key.pem")

        try:
            ssl_ca_file = open(ssl_ca_path, mode="rb")
            ssl_ca_content = ssl_ca_file.read()
            ssl_ca_file.close()
            ssl_cert_file = open(ssl_cert_path, mode="rb")
            ssl_cert_content = ssl_cert_file.read()
            ssl_cert_file.close()
            ssl_key_file = open(ssl_key_path, mode="rb")
            ssl_key_content = ssl_key_file.read()
            ssl_key_file.close()

            ssl_ca = docker_client.secrets.create(name="SSL_CA_PEM", data=ssl_ca_content)
            ssl_cert = docker_client.secrets.create(name="SSL_CERT_PEM", data=ssl_cert_content)
            ssl_key = docker_client.secrets.create(name="SSL_KEY_PEM", data=ssl_key_content)

            ctx.meta["SSL_CA_PEM_ID"] = ssl_ca.id
            ctx.meta["SSL_CERT_PEM_ID"] = ssl_cert.id
            ctx.meta["SSL_KEY_PEM_ID"] = ssl_key.id
        except Exception as e:
            traceback.print_exc()
            logger.error(traceback.format_exc())

        # Creates the manager service on the host.
        bridge_network = docker_utils.get_bridge_network()
        docker_client.services.create(
            image="jluech/pga-cloud-manager",
            name="manager",
            hostname="manager",
            networks=[bridge_network.name],
            endpoint_spec={
                "Ports": [
                    {"Protocol": "tcp", "PublishedPort": port, "TargetPort": 5000},
                ]
            },
        )

        # Updates the service with the new secrets.
        script_path = os.path.join(os.getcwd(), "client/docker_service_update_secrets.sh")
        script_args = "--certs {certs_} --host {host_}"
        utils.execute_command(
            command=script_path + " " + script_args.format(
                certs_=cert_path,
                host_=ctx.meta["master_host"]
            ),
            working_directory=os.curdir,
            environment_variables=None,
            executor=None,
            logger=logger,
            livestream=True
        )

        # Waits for WAIT_FOR_CONFIRMATION_DURATION seconds or until manager service is running.
        service_running = False
        service_status = "NOK"
        exceeding = False
        troubled = False
        duration = 0.0
        start = time.perf_counter()
        while not service_running and duration < WAIT_FOR_CONFIRMATION_DURATION:
            try:
                response = http.get(
                    url="http://{addr_}:{port_}/status".format(
                        addr_=ctx.meta["master_host"],
                        port_=ctx.meta["master_port"]
                    ),
                    verify=False
                )
                service_status = response.content.decode("utf-8")
            except:
                pass
            finally:
                service_running = service_status == "OK"

            if duration >= WAIT_FOR_CONFIRMATION_EXCEEDING and not exceeding:
                click.echo("This is taking longer than usual...")
                exceeding = True  # only print this once

            if duration >= WAIT_FOR_CONFIRMATION_TROUBLED and not troubled:
                click.echo("Oh come on! You can do it...")
                troubled = True  # only print this once

            time.sleep(WAIT_FOR_CONFIRMATION_SLEEP)  # avoid network overhead
            duration = time.perf_counter() - start

        if duration >= WAIT_FOR_CONFIRMATION_DURATION:
            click.echo("Exceeded waiting time of {time_} seconds. It may have encountered an error. "
                       "Please verify or try again shortly.".format(time_=WAIT_FOR_CONFIRMATION_DURATION))
        else:
            click.echo("Successfully created manager service.")
    else:
        click.echo("kubernetes orchestrator not implemented yet.")  # TODO 202: implement kubernetes orchestrator

    # Updates the meta context storage file.
    utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@cloud.command()
@click.pass_context
@click.argument("cert_path", type=click.Path(exists=True), required=False)
def reset(ctx, cert_path):
    """
    Reset the cloud by removing the PGA Manager.

    :param cert_path: the path to a folder containing your SSL certificates.
                    Can also be set in the context, see 'config certificates'.
    :type cert_path: str

    :param ctx: the click cli context, automatically passed by cli.
    """
    # Retrieves the certificates path.
    if not cert_path:
        if not ctx.meta["cert_path"]:
            raise Exception("No certificates path defined! You can define it by providing it as an argument "
                            "or by explicitly setting it with command 'client config cert-path'. "
                            "Type 'client config cert-path --help' for more details.")
        cert_path = ctx.meta["cert_path"]
    else:
        ctx.meta["cert_path"] = cert_path
        click.echo("Updating config for certificates path to {path_}".format(path_=ctx.meta["cert_path"]))

    # Ensures there is a known host to connect to.
    if not ctx.meta["master_host"]:
        raise Exception("No master host defined! You can define it by creating the cloud environment "
                        "or by explicitly setting it with command 'client config master-host'. "
                        "Type 'client config master-host --help' for more details.")

    # Removes the PGA manager via the selected orchestrator.
    if ctx.meta["orchestrator"] == "docker":
        docker_client = docker_utils.get_docker_client(
            cert_path=cert_path,
            host_addr=ctx.meta["master_host"],
            host_port=2376
            # default docker port; Note above https://docs.docker.com/engine/security/https/#secure-by-default
        )

        # Removes the PGA service(s).
        pga_services_filter = {"label": "PGAcloud"}
        found_services = docker_client.services.list(filters=pga_services_filter)
        if not found_services.__len__() > 0:
            click.echo("No PGA services running that could be removed.")
        else:
            for pga_service in found_services:
                pga_service.remove()

            # Wait for WAIT_FOR_CONFIRMATION_DURATION seconds or until manager service is not found anymore.
            services_running = True
            exceeding = False
            troubled = False
            duration = 0.0
            start = time.perf_counter()
            while services_running and duration < WAIT_FOR_CONFIRMATION_DURATION:
                found_services = docker_client.services.list(filters=pga_services_filter)
                services_running = (found_services.__len__() > 0)

                if duration >= WAIT_FOR_CONFIRMATION_EXCEEDING and not exceeding:
                    click.echo("This is taking longer than usual...")
                    exceeding = True  # only print this once

                if duration >= WAIT_FOR_CONFIRMATION_TROUBLED and not troubled:
                    click.echo("Oh come on! You can do it...")
                    troubled = True  # only print this once

                time.sleep(WAIT_FOR_CONFIRMATION_SLEEP)  # avoid network overhead
                duration = time.perf_counter() - start

            if duration >= WAIT_FOR_CONFIRMATION_DURATION:
                click.echo("Exceeded waiting time of {time_} seconds. It may have encountered an error. "
                           "Please verify or try again shortly.".format(time_=WAIT_FOR_CONFIRMATION_DURATION))
            else:
                click.echo("Successfully removed PGA services.")

        # Removes the manager service(s).
        manager_service_filter = {"name": "manager"}
        found_manager_services = docker_client.services.list(filters=manager_service_filter)
        if not found_manager_services.__len__() > 0:
            click.echo("No manager running that could be removed.")
        else:
            manager_service = found_manager_services[0]
            manager_service.remove()

            # Wait for WAIT_FOR_CONFIRMATION_DURATION seconds or until manager service is not found anymore.
            service_running = True
            exceeding = False
            troubled = False
            duration = 0.0
            start = time.perf_counter()
            while service_running and duration < WAIT_FOR_CONFIRMATION_DURATION:
                found_manager_services = docker_client.services.list(filters=manager_service_filter)
                service_running = (found_manager_services.__len__() > 0)

                if duration >= WAIT_FOR_CONFIRMATION_EXCEEDING and not exceeding:
                    click.echo("This is taking longer than usual...")
                    exceeding = True  # only print this once

                if duration >= WAIT_FOR_CONFIRMATION_TROUBLED and not troubled:
                    click.echo("Oh come on! You can do it...")
                    troubled = True  # only print this once

                time.sleep(WAIT_FOR_CONFIRMATION_SLEEP)  # avoid network overhead
                duration = time.perf_counter() - start

            if duration >= WAIT_FOR_CONFIRMATION_DURATION:
                click.echo("Exceeded waiting time of {time_} seconds. It may have encountered an error. "
                           "Please verify or try again shortly.".format(time_=WAIT_FOR_CONFIRMATION_DURATION))
            else:
                click.echo("Successfully removed manager service.")

        # Removes the docker secrets for the SSL certificates.
        ssl_ca_id = ctx.meta["SSL_CA_PEM_ID"]
        ssl_cert_id = ctx.meta["SSL_CERT_PEM_ID"]
        ssl_key_id = ctx.meta["SSL_KEY_PEM_ID"]
        current_ssl_secrets = docker_client.secrets.list(filters={"id": [ssl_ca_id, ssl_cert_id, ssl_key_id]})
        if current_ssl_secrets.__len__() > 0:
            docker_client.secrets.get(ssl_ca_id).remove()
            docker_client.secrets.get(ssl_cert_id).remove()
            docker_client.secrets.get(ssl_key_id).remove()
            click.echo("Successfully removed docker secrets for SSL certificates.")
            ctx.meta["SSL_CA_PEM_ID"] = ""
            ctx.meta["SSL_CERT_PEM_ID"] = ""
            ctx.meta["SSL_KEY_PEM_ID"] = ""
        else:
            click.echo("No SSL secrets found that could be removed.")

        # Removes the docker networks.
        pga_networks = docker_client.networks.list(filters={"label": "PGAcloud"})
        if pga_networks.__len__() > 0:
            for network in pga_networks:
                network.remove()
            click.echo("Successfully removed PGA docker networks.")
        else:
            click.echo("No PGA docker networks found that could be removed.")
    else:
        click.echo("kubernetes orchestrator not implemented yet!")  # TODO 202: implement kubernetes orchestrator

    # Updates the meta context storage file.
    utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@cloud.command()
def destroy():
    """
    Remove the cloud environment and all its PGA contents.
    """
    click.echo("cloud destroy")  # TODO 105: extend client cli with cloud teardown


@client.group()
def pga():
    pass


@pga.command()
@click.pass_context
@click.argument("configuration_file_path", type=click.Path(exists=True), required=False)
@click.option("--manager-host", "-m", "manager_host", type=str, required=False)
def create(ctx, configuration_file_path, manager_host):
    """
    Create a new PGA run.

    :param configuration_file_path: the path to the PGA configuration file.
            If not supplied, the default configuration will be run.
    :type configuration_file_path: str

    :param manager_host: the IP address or hostname of the PGA Manager node.
            Can also be set in the context, see 'config master_host'.
    :type manager_host: str

    :param ctx: the click cli context, automatically passed by cli.

    :return: generated PGA id
    """
    # Sets the manager IP if not provided.
    if not manager_host:
        if not ctx.meta["master_host"]:
            raise Exception("No master host defined! You can define it by creating the cloud environment "
                            "or by explicitly setting it with command 'client config master-host'. "
                            "Type 'client config master-host --help' for more details.")
        manager_host = ctx.meta["master_host"]

    # Sets the default configuration if no configuration file path provided.
    if not configuration_file_path:
        configuration_file_path = os.path.join(os.getcwd(), "pga_config_template.yml")

    # Retrieves the configuration file.
    configuration = get_configuration(configuration_file_path)
    use_population = configuration.get("population").get("use_initial_population")
    if use_population:
        population_file_path = configuration.get("population").get("population_file_path")

        # Retrieves the file with the initial population.
        files = {"population": open(population_file_path, "r")}
        if not files.get("population"):
            raise FileNotFoundError
    else:
        files = {}

    # Retrieves the appended files for transmission.
    custom_files_dict = configuration.get("custom_files")
    custom_files_keys = [*custom_files_dict.keys()]
    for key in custom_files_keys:
        file = open(custom_files_dict.get(key), "r")
        if not file:
            raise FileNotFoundError
        files[key] = file

    # Appends the configuration file to the request.
    files["config"] = open(configuration_file_path, "r")

    # Calls the manager API to create the PGA.
    response = http.post(
        url="http://{}:{}/pga".format(manager_host, ctx.meta["master_port"]),
        params={
            "config": configuration_file_path,
            "orchestrator": ctx.meta["orchestrator"],
            "master_host": ctx.meta["master_host"]
        },
        files=files,
        verify=False
    )

    json_response = response.json()
    pga_id = json_response["id"]
    click.echo("Initialized new PGA with id: {}".format(pga_id))  # id is generated


@pga.command()
@click.argument("pga_id", type=int)
def run(pga_id):
    """
    Start computation of given PGA.

    :param pga_id: the id of the PGA to run, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga run {}".format(pga_id))  # TODO 106: extend client cli with runner start


@pga.command()
@click.argument("pga_id", type=int)
def monitor(pga_id):
    """
    Monitor computation statistics of given PGA.
    Currently fittest individual, generation, computation time, etc.

    :param pga_id: the id of the PGA to monitor, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga monitor {}".format(pga_id))  # TODO 107: extend client cli with runner manipulation


@pga.command()
@click.argument("pga_id", type=int)
def pause(pga_id):
    """
    Pause given PGA after finishing the current generation.

    :param pga_id: the id of the PGA to pause, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga pause {}".format(pga_id))  # TODO 107: extend client cli with runner manipulation


@pga.command()
@click.argument("pga_id", type=int)
def stop(pga_id):
    """
    Stop computation of given PGA and remove it.

    :param pga_id: the id of the PGA to monitor, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga stop {}".format(pga_id))  # TODO 108: extend client cli with runner teardown


def get_configuration(configuration_file_path):
    if configuration_file_path:
        return utils.parse_yaml(configuration_file_path)
    else:
        click.echo("No configuration file path defined")
        return {}


def get_driver(provider_name, orchestrator, configuration, logger):
    if provider_name == "amazon":
        # return AmazonCloudProviderDriver(configuration, logger)
        click.echo("Could not find 'amazon' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 201: implement Amazon driver
    elif provider_name == "openstack":
        # return OpenStackCloudProviderDriver(configuration, logger)
        click.echo("Could not find 'openstack' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 201: implement Openstack driver
    elif provider_name == "virtualbox":
        # return VirtualboxProviderDriver(logger)
        click.echo("Could not find 'virtualbox' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 201: implement Virtualbox driver
    elif provider_name == "vsphere":
        if orchestrator == "docker":
            return VSphereDockerDriver(configuration, logger)
        else:
            click.echo("Currently only 'docker' is implemented as orchestrator, falling back on docker orchestrator")
            return VSphereDockerDriver(configuration, logger)  # TODO 202: implement kubernetes orchestrator


if __name__ == "__main__":
    client()
