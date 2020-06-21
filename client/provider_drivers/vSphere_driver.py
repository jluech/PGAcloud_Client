import os

from client.provider_drivers.abstract_driver import AbstractDriver
from client.utils import execute_command

CREATE_CLOUD_SCRIPT_PATH = "./client/provider_drivers/create_vsphere_docker.sh"
CREATE_CLOUD_PARAMS = "-n {name_} -u {user_} -p {pw_} -d {datastore_}"


class VSphereDockerDriver(AbstractDriver):
    name = "VMware vSphere Docker Driver"

    def __init__(self, configuration, logger):
        super().__init__(configuration, logger)
        self.__vcenter = configuration.get("vsphere-vcenter")
        self.__user = configuration.get("vsphere-username")
        self.__pw = configuration.get("vsphere-password")
        self.__datastore = configuration.get("vsphere-vcenter-datastore")

    def setup_cloud_environment(self):
        execute_command(
            command=self.__create_cloud_command(),
            working_directory=os.curdir,
            environment_variables=None,
            executor=None,
            logger=self._logger,
            livestream=True
        )

    def __create_cloud_command(self):
        path = CREATE_CLOUD_SCRIPT_PATH
        if path.startswith("./"):
            path = os.getcwd() + path[1:]

        return path.replace("/", "\\") + " " + CREATE_CLOUD_PARAMS.format(
            name_=self.__vcenter,
            user_=self.__user,
            pw_=self.__pw,
            datastore_=self.__datastore
        )
