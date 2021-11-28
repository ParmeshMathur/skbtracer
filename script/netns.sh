#!/bin/bash

NSST1=nsst1
NSST2=nsst2
VETHST1=veth_st1
VETHST2=veth_st2
IPST1="10.10.1.1"
IPST2="10.10.1.2"

ip netns add ${NSST1}
ip netns add ${NSST2}

ip link add dev ${VETHST1} type veth peer name ${VETHST2}
ip link set dev ${VETHST1} netns ${NSST1}
ip link set dev ${VETHST2} netns ${NSST2}

ip netns exec ${NSST1} bash -c "
ip link set dev ${VETHST1} up
ip addr add ${IPST1}/24 dev ${VETHST1}
ip route add default via ${IPST2}
"

ip netns exec ${NSST2} bash -c "
ip link set dev ${VETHST2} up
ip addr add ${IPST2}/24 dev ${VETHST2}
ip route add default via ${IPST1}
"
