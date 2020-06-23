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
        content = yaml.safe_load(yaml_file) or {}
    return content


def read_context(context_file_path):
    try:
        return parse_yaml(context_file_path)
    except:
        context_file = open(context_file_path, mode="x", encoding="utf-8")
        context_file.close()
        return parse_yaml(context_file_path)


def store_context(meta_dict, context_file_path):
    dirty = False
    keys = meta_dict.keys()

    try:
        context = parse_yaml(context_file_path)

        for key in keys:
            if context.get(key) != meta_dict[key]:
                dirty = True

        if dirty:
            context_file = open(context_file_path, mode="w", encoding="utf-8")
            for key in keys:
                context_file.write("{key_}: {value_}\n".format(key_=key, value_=meta_dict[key]))
            context_file.close()
    except FileNotFoundError:
        print("except")
        context_file = open(context_file_path, mode="x", encoding="utf-8")
        for key in keys:
            context_file.write("<{key_}>: {value_}\n".format(key_=key, value_=meta_dict[key]))
    except:
        raise
