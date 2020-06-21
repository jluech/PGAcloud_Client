import subprocess
import sys

import yaml


def execute_command(
        command,
        working_directory,
        environment_variables,
        executor,
        logger,
        livestream=False
):
    logger_prefix = ""
    if executor:
        logger_prefix = executor + ": "

    process = subprocess.Popen(
        command,
        cwd=working_directory,
        env=environment_variables,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
    )

    logger.debug(logger_prefix + "command: " + command)

    stdout = ""
    for line in iter(process.stdout.readline, b''):
        line = str(line, "utf-8")
        stdout += line

        if livestream:
            sys.stdout.write(line)
        else:
            logger.debug(logger_prefix + "command output: " + line.rstrip())

    return_code = process.wait()

    stdout = stdout.rstrip()

    return stdout, return_code


def parse_yaml(yaml_file_path):
    with open(yaml_file_path, mode='r', encoding='utf-8') as yaml_file:
        content = yaml.safe_load(yaml_file)
    return content
