#!/bin/bash

# Required command parameters
vcenter=$1   # ESXi vcenter name
user=$2      # username
pw=$3        # password
datastore=$4 # datastore on ESXi center

# Host node settings
memory_size_MB=4096 # default: 2048
disk_size_MB=28672  # default: 20'000
cpu_count=2         # default: 2

worker_count=3  # amount of worker nodes

# Creating master node
echo "### Creating master node ..."
docker-machine create \
	--driver vmwarevsphere \
	--vmwarevsphere-vcenter=$vcenter \
	--vmwarevsphere-username=$user \
	--vmwarevsphere-password=$pw \
	--vmwarevsphere-datastore=$datastore \
	--vmwarevsphere-memory-size=$memory_size_MB \
	--vmwarevsphere-disk-size=$disk_size_MB \
	--vmwarevsphere-cpu-count=$cpu_count \
	--swarm-master \
	dockermaster
echo ""

# Get IP from master node
echo "### Saving master ip ..."
master_ip=$(docker-machine ip dockermaster)
echo ""

# Creating worker nodes
echo "### Creating worker nodes ..."
for (( c=1; c<=$worker_count; c++ ))
do
  docker-machine create \
    --driver vmwarevsphere \
    --vmwarevsphere-vcenter=$vcenter \
    --vmwarevsphere-username=$user \
    --vmwarevsphere-password=$pw \
    --vmwarevsphere-datastore=$datastore \
    --vmwarevsphere-memory-size=$memory_size_MB \
    --vmwarevsphere-disk-size=$disk_size_MB \
    --vmwarevsphere-cpu-count=$cpu_count \
    --swarm \
    dockerworker$c
  echo "-- $c/$worker_count done"
done
echo ""

# Init docker swarm mode
echo "### Initializing swarm master ..."
eval $(docker-machine env dockermaster)
# docker swarm init --advertise-addr $master_ip
docker swarm init
echo ""

# Swarm tokens
echo "### Saving swarm join tokens ..."
# manager_token=$(docker swarm join-token manager -q)
worker_token=$(docker swarm join-token worker -q)
echo ""

# Join worker nodes
echo "### Joining worker nodes ..."
for (( c=1; c<=$worker_count; c++ ))
do
  eval $(docker-machine env dockerworker$c)
  docker swarm join --token $worker_token $master_ip:2377
  echo "-- worker $c/$worker_count"
done
echo ""
