import os

import click
import logbook

from client import utils
from client.provider_drivers.vSphere_driver import VSphereDockerDriver

logger = logbook.Logger('orchestrator')


class Context(object):
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator


@click.group()
def client():
    pass


@client.group()
@click.pass_context
@click.option("--orchestrator", "-o", "orchestrator",
              type=click.Choice(["docker", "kubernetes"]),
              default="docker")
def cloud(ctx, orchestrator):
    ctx.obj = Context(orchestrator)


@cloud.command()
@click.pass_obj
@click.option("--provider", "-p", "provider_name",
              type=click.Choice(["amazon", "openstack", "virtualbox", "vsphere"]),
              default="vsphere")
@click.option("--configuration", "-c", "configuration_file_path", type=click.Path(exists=True), required=False)
def create(context, provider_name, configuration_file_path):
    """
    Create and setup the cloud environment.

    :param context: the click cli context, automatically passed by cli.

    :param provider_name: the cloud provider name.
    :type provider_name: str

    :param configuration_file_path: the path to the PGA configuration file.
    :type configuration_file_path: str
    """

    # Retrieves the configuration.
    configuration = get_configuration(configuration_file_path)

    # Recognizes the correct driver.
    driver = get_driver(provider_name, context.orchestrator, configuration, logger)
    click.echo(driver.name)

    # Creates the cloud environment.
    driver.setup_cloud_environment()


@cloud.command()
@click.pass_obj
def init(context):
    """
    Initialize the PGA Manager.

    :param context: the click cli context, automatically passed by cli.
    """
    if context.orchestrator == "docker":
        utils.execute_command(
            command=os.getcwd() + "\\client\\docker-machine_ssh_docker_run.sh -i jluech/pga-cloud-manager",
            working_directory=os.curdir,
            environment_variables=None,
            executor=None,
            logger=logger,
            livestream=True
        )
    else:
        print("kubernetes orchestrator not implemented yet")  # TODO 202: implement kubernetes orchestrator


@cloud.command()
@click.pass_obj
@click.argument("host_ip", type=str)
def reset(context, host_ip):
    """
    Reset the cloud by removing the PGA Manager.

    :param context: the click cli context, automatically passed by cli.

    :param host_ip: the IP address of a host in the cloud.
    :type host_ip: str
    """
    click.echo("cloud reset " + host_ip)  # TODO 105: extend client cli with cloud teardown


@cloud.command()
@click.pass_obj
def destroy(context):
    """
    Remove the cloud environment and all its PGA contents.

    :param context: the click cli context, automatically passed by cli.
    """
    click.echo("cloud destroy")  # TODO 105: extend client cli with cloud teardown


@client.group()
def pga():
    pass


@pga.command()
@click.option("--manager", "-m", "manager_ip", type=str)
@click.option("--configuration", "-c", "configuration_file_path", type=click.Path(exists=True), required=True)
def init(manager_ip, configuration_file_path):
    """
    Initialize a new PGA run.

    :param manager_ip: the IP address of the PGA Manager node.
    :type manager_ip: str

    :param configuration_file_path: the path to the PGA configuration file.
    :type configuration_file_path: str

    :return: generated PGA id
    """
    click.echo("pga init " + manager_ip)

    # Retrieves the configuration file
    configuration = get_configuration(configuration_file_path)

    pga_id = 123
    click.echo("Initialized new PGA with id: " + str(pga_id))  # id is generated
    return pga_id  # TODO 103: extend client cli with runner creation


@pga.command()
@click.argument("pga_id", type=int)
def run(pga_id):
    """
    Start computation of given PGA.

    :param pga_id: the id of the PGA to run, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga run " + str(pga_id))  # TODO 106: extend client cli with runner start


@pga.command()
@click.argument("pga_id", type=int)
def monitor(pga_id):
    """
    Monitor computation statistics of given PGA.
    Currently fittest individual, generation, computation time, etc.

    :param pga_id: the id of the PGA to monitor, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga monitor " + str(pga_id))  # TODO 107: extend client cli with runner manipulation


@pga.command()
@click.argument("pga_id", type=int)
def pause(pga_id):
    """
    Pause given PGA after finishing the current generation.

    :param pga_id: the id of the PGA to pause, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga pause " + str(pga_id))  # TODO 107: extend client cli with runner manipulation


@pga.command()
@click.argument("pga_id", type=int)
def stop(pga_id):
    """
    Stop computation of given PGA and remove it.

    :param pga_id: the id of the PGA to monitor, retrieved from initialization.
    :type pga_id: int
    """
    click.echo("pga stop " + str(pga_id))  # TODO 108: extend client cli with runner teardown


def get_configuration(configuration_file_path):
    if configuration_file_path:
        return utils.parse_yaml(configuration_file_path)
    else:
        return {}


def get_driver(provider_name, orchestrator, configuration, logger):
    if provider_name == "amazon":
        # return AmazonCloudProviderDriver(configuration, logger)
        print("Could not find 'amazon' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 104: implement Amazon driver
    elif provider_name == "openstack":
        # return OpenStackCloudProviderDriver(configuration, logger)
        print("Could not find 'openstack' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 104: implement Openstack driver
    elif provider_name == "virtualbox":
        # return VirtualboxProviderDriver(logger)
        print("Could not find 'virtualbox' driver, falling back to 'vsphere' docker driver")
        return VSphereDockerDriver(configuration, logger)  # TODO 104: implement Virtualbox driver
    elif provider_name == "vsphere":
        if orchestrator == "docker":
            return VSphereDockerDriver(configuration, logger)
        else:
            logger.warning("Currently only 'docker' is implemented as orchestrator, falling back on docker orchestrator")
            return VSphereDockerDriver(configuration, logger)  # TODO 202: implement kubernetes orchestrator


if __name__ == "__main__":
    client()
