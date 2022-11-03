# LoadBallancer
*A simple 4host-1switch-4server LoadBallancer for openflow controller POX*

You need mininet to create topologies and pox as a control with one openflow switch the experiment can be done by pinging from a host to a server.

# Run
place SimpleLoadBalancer.py under /pox/ext

cd pox

sudo mn --topo single,8 --controller remote --mac --switch ovsk

./run.sh

# Brief explanation

Red hosts can only comunicate with red server and blue ones only with blue servers via 1 openflow switch.


