from setuptools import setup, find_packages

requirements = [
    "click",
    "logbook",
    "PyYAML",
    "requests"
]

setup(
    name="client",
    author="Janik Luechinger",
    author_email="janik.luechinger@uzh.ch",
    description="script for PGA client interaction",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": ["client=client.client:client"]
    }
)

# Shell Commands required for usage:
# $ virtualenv venv
# $ . venv/scripts/activate
# $ pip install --editable .

# Example Command:
# $ client cloud init <host_ip>
