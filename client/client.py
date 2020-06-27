import os

import click
import logbook
import requests

from client import utils
from client.provider_drivers.vSphere_driver import VSphereDockerDriver

logger = logbook.Logger('client')
http = requests.sessions.Session()

CLIENT_CLI_CONTEXT_FILE = os.getcwd() + "\\client\\cli_context.yml"
CLIENT_CLI_CONTEXT_KEYS = ["orchestrator", "master_ip", "master_port"]
CLIENT_CLI_CONTEXT_DEFAULTS = {
    "orchestrator": "docker",
    "master_port": 5000
}


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
@click.argument("ip", type=str)
def master_ip(ctx, ip):
    """
        Update the config for the master host ip address in the cloud.

        :param ip: the master host ip address.
        :type ip: str

        :param ctx: the click cli context, automatically passed by cli.
        """
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
@click.argument("port", type=int)
def master_port(ctx, port):
    """
    Update the config for the exposed port on the master host to map to containers.

    :param port: the master host port to expose for mapping.
    :type port: int

    :param ctx: the click cli context, automatically passed by cli.
    """
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
def init(ctx, port):
    """
    Initialize the PGA Manager.

    :param port: the external port on the host to map to the container.
                    Defaults to the current meta config. See :func:`config`.
    :type port: int

    :param ctx: the click cli context, automatically passed by cli.
    """
    # Sets the port if not provided.
    if not port:
        port = ctx.meta["master_port"]

    # Initializes the manager container via the selected orchestrator.
    if ctx.meta["orchestrator"] == "docker":
        utils.execute_command(
            command=os.getcwd() + "\\client\\docker-machine_ssh_docker_run.sh "
                                  "-i jluech/pga-cloud-manager -p {port_}".format(port_=port),
            working_directory=os.curdir,
            environment_variables=None,
            executor=None,
            logger=logger,
            livestream=True
        )
    else:
        click.echo("kubernetes orchestrator not implemented yet")  # TODO 202: implement kubernetes orchestrator

    # Updates the meta context storage file.
    utils.store_context(ctx.meta, CLIENT_CLI_CONTEXT_FILE)


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

    :param manager_ip: the IP address of the PGA Manager node. Can also be set in the context, see 'config master_ip'.
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

    # Calls the manager API to create the PGA.
    response = http.post("http://{}:{}/pga".format(manager_ip, ctx.meta["master_port"]), files=files, verify=False)
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
