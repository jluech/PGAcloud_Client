import os
import time

import click
import logbook
import requests

from client import docker_utils, utils
from client.provider_drivers.vSphere_driver import VSphereDockerDriver

logger = logbook.Logger('client')
http = requests.sessions.Session()

CLIENT_CLI_CONTEXT_FILE = os.getcwd() + "\\client\\cli_context.yml"
CLIENT_CLI_CONTEXT_KEYS = ["orchestrator", "master_ip", "master_port"]
CLIENT_CLI_CONTEXT_DEFAULTS = {
    "orchestrator": "docker",
    "master_port": 5000
}

WAIT_FOR_CONFIRMATION_DURATION = 30.0
WAIT_FOR_CONFIRMATION_EXCEEDING = 15.0
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
@click.argument("ip", type=str, required=False)
def master_ip(ctx, ip):
    """
        Update the configuration for the master host ip address in the cloud.
        If no argument is provided, it will show the current configuration.

        :param ip: the master host ip address.
        :type ip: str

        :param ctx: the click cli context, automatically passed by cli.
        """
    if not ip:
        if ctx.meta["master_ip"]:
            click.echo("Current master IP: {ip_}".format(ip_=ctx.meta["master_ip"]))
        else:
            click.echo("Master IP currently not set. You can set it by providing an argument to this function.")
        return

    changed = False
    if ctx.meta["master_ip"]:
        valid_prompt = False
        while not valid_prompt:
            prompt = click.prompt(
                text="Master IP currently set to {master_ip_} - Do you want to overwrite?".format(
                    master_ip_=ctx.meta["master_ip"]
                ),
                type=click.Choice(["y", "n"]),
                show_choices=True,
                default="n",
                show_default=False
            )
            if prompt == "y":
                ctx.meta["master_ip"] = ip
                valid_prompt = True
                click.echo("Updated master IP to {ip_}".format(ip_=ip))
                changed = True
            elif prompt == "n":
                click.echo("Aborted setting master IP.")
                valid_prompt = True
    else:
        ctx.meta["master_ip"] = ip
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
    If no argument is provided, it will show the current configuration.

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
                click.echo("Aborted setting master port.")
                valid_prompt = True
    else:
        ctx.meta["master_port"] = port
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
    manager_ip, error = utils.execute_command(
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
        if not ctx.meta["master_ip"]:
            click.echo("Setting master host IP {ip_}".format(ip_=manager_ip))
        else:
            click.echo("Updating config for master host IP to {ip_}".format(ip_=ctx.meta["master_ip"]))
        ctx.meta["master_ip"] = manager_ip

    # Updates the meta context storage file.
    utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


@cloud.command()
@click.pass_context
@click.option("--port", "-p", "port", type=int)
@click.argument("cert_path", type=str)
def init(ctx, port, cert_path):
    """
    Initialize the PGA Manager.

    :param port: the external port on the host to map to the container.
                    Defaults to the current meta config. See :func:`config` for reference.
    :type port: int

    :param cert_path: the path to a folder containing your SSL certificates.
    :type cert_path: str

    :param ctx: the click cli context, automatically passed by cli.
    """
    # Sets the port if not provided.
    if not port:
        port = ctx.meta["master_port"]

    # Initializes the PGA manager via the selected orchestrator.
    if ctx.meta["orchestrator"] == "docker":
        docker_client = docker_utils.get_docker_client(
            cert_path=cert_path,
            host_ip=ctx.meta["master_ip"],
            host_port=2376
            # default docker port; Note above https://docs.docker.com/engine/security/https/#secure-by-default
        )
        manager_service = docker_client.services.create(
            image="jluech/pga-cloud-manager",
            name="manager",
            endpoint_spec={
                "Ports": [
                    {"Protocol": "tcp", "PublishedPort": port, "TargetPort": 5000},
                ]
            },
        )

        # Wait for WAIT_FOR_CONFIRMATION_DURATION seconds or until manager service is running.
        service_running = False
        service_status = "NOK"
        exceeding = False
        duration = 0.0
        start = time.perf_counter()
        while not service_running and duration < WAIT_FOR_CONFIRMATION_DURATION:
            try:
                response = http.get(
                    url="http://{}:{}/status".format(ctx.meta["master_ip"], ctx.meta["master_port"]),
                    verify=False
                )
                service_status = response.content.decode("utf-8")
            except:
                pass
            finally:
                # service_running = service_status == "OK"
                service_running = (service_status == "Status: OK")

            if duration >= WAIT_FOR_CONFIRMATION_EXCEEDING and not exceeding:
                click.echo("This is taking longer than usual...")
                exceeding = True  # only print this once

            time.sleep(WAIT_FOR_CONFIRMATION_SLEEP)  # avoid network overhead
            duration = time.perf_counter() - start

        if duration >= WAIT_FOR_CONFIRMATION_DURATION:
            click.echo("Exceeded waiting time of {time_}s. It may have encountered an error."
                       "Please verify or try again shortly.".format(time_=WAIT_FOR_CONFIRMATION_DURATION))
        else:
            click.echo("Successfully created service: {name_}".format(name_=manager_service.name))
    else:
        click.echo("kubernetes orchestrator not implemented yet")  # TODO 202: implement kubernetes orchestrator


@cloud.command()
@click.argument("host_ip", type=str)
def reset(host_ip):
    """
    Reset the cloud by removing the PGA Manager.

    :param host_ip: the IP address of a host in the cloud.
    :type host_ip: str
    """
    click.echo("cloud reset " + host_ip)  # TODO 105: extend client cli with cloud teardown


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
@click.option("--configuration", "-c", "configuration_file_path", type=click.Path(exists=True), required=True)
@click.option("--manager-ip", "-m", "manager_ip", type=str, required=False)
def create(ctx, configuration_file_path, manager_ip):
    """
    Create a new PGA run.

    :param configuration_file_path: the path to the PGA configuration file.
            If not supplied, the default configuration will be run.
    :type configuration_file_path: str

    :param manager_ip: the IP address or hostname of the PGA Manager node. Can also be set in the context, see 'config master_ip'.
    :type manager_ip: str

    :param ctx: the click cli context, automatically passed by cli.

    :return: generated PGA id
    """
    # Sets the manager IP if not provided.
    if not manager_ip:
        if not ctx.meta["master_ip"]:
            raise Exception("No master host IP defined! You can define it by creating the cloud environment"
                            "or by explicitly setting it with command 'client config master-ip'."
                            "Type 'client config master-ip --help' for more details.")
        manager_ip = ctx.meta["master_ip"]

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
        url="http://{}:{}/pga".format(manager_ip, ctx.meta["master_port"]),
        params={
            "config": configuration_file_path,
            "orchestrator": ctx.meta["orchestrator"]
        },
        files=files,
        verify=False
    )
    json_response = response.json()
    pga_id = json_response["id"]

    click.echo("Initialized new PGA with id: {}".format(pga_id))  # id is generated
    return pga_id


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