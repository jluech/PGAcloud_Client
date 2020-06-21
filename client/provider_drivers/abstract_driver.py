from abc import ABC, abstractmethod


class AbstractDriver(ABC):
    name = ""

    @abstractmethod
    def __init__(self, configuration, logger):
        self._configuration = configuration
        self._logger = logger

    @abstractmethod
    def setup_cloud_environment(self):
        pass
