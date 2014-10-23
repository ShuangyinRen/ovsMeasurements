sudo ovs-vsctl add-br ovs-switch
sudo ifconfig ovs-switch up
sudo ovs-vsctl set-controller ovs-switch tcp:10.1.1.2
#add for query with traffic
#sudo ovs-vsctl add-port ovs-switch eth2
#sudo ifconfig eth2 0
#sudo ifconfig ovs-switch 10.1.2.2
