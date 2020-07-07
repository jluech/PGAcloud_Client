#!/bin/bash

hostname="dockermaster"
image=
tag="latest"
port=

usage()
{
    echo "usage:  -n | --name         remote host name, defaults to 'dockermaster'"
    echo "        -i | --image        image to run in container"
    echo "        -t | --tag          image tag, defaults to 'latest'"
    echo "        -p | --port         external port on host to map to container"
    echo "------------------------------------------------------------------------"
    echo "        -h | --help"
}

if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
  usage
  exit 0
fi

# Assign positional parameters.
while [ "$1" != "" ]; do
    case $1 in
        -n | --name )       shift
                            hostname=$1
                            ;;
        -i| --image )       shift
                            image=$1
                            ;;
        -t| --tag )         shift
                            tag=$1
                            ;;
        -p| --port )        shift
                            port=$1
                            ;;
        * )                 usage
                            exit 1
    esac
    shift
done

# Confirming input.
echo "SSH into: $hostname"
echo "Running container with image: $image:$tag"
echo "Binding host port $port to container port 5000"
echo ""

# Run new container with given image on remote host and exit.
echo "docker image pull $image:$tag; docker run -d -p $port:5000 --name manager $image:$tag; exit" | docker-machine ssh $hostname

# Since "docker-machine ssh" opens another interactive shell, give execution feedback.
echo ""
echo ""
read -p "Press ENTER to terminate:"
