#!/usr/bin/python
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from subprocess import call
import time
import threading
import socket
def myNetwork():
    net = Mininet_wifi(topo=None,
                    build=False,
                    link=wmediumd,
                    wmediumd_mode=interference,
                    ipBase='10.0.0.0/8')

    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        protocol='tcp',
                        port=6633)

    info('*** Add switches/APs\n')
    # Augmenter la puissance et portée des APs pour assurer la connectivité
    ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, ssid='ap1-ssid',
                            channel='1', mode='g', position='123.0,108.0,0',
                            range=150, txpower=20)
    ap2 = net.addAccessPoint('ap2', cls=OVSKernelAP, ssid='ap2-ssid',
                            channel='6', mode='g', position='315.0,108.0,0',
                            range=150, txpower=20)
    ap3 = net.addAccessPoint('ap3', cls=OVSKernelAP, ssid='ap3-ssid',
                            channel='11', mode='g', position='105.0,323.0,0',
                            range=150, txpower=20)
    ap4 = net.addAccessPoint('ap4', cls=OVSKernelAP, ssid='ap4-ssid',
                            channel='1', mode='g', position='277.0,292.0,0',
                            range=150, txpower=20)
    ap5 = net.addAccessPoint('ap5', cls=OVSKernelAP, ssid='ap5-ssid',
                            channel='6', mode='g', position='459.0,349.0,0',
                            range=150, txpower=20)
    ap6 = net.addAccessPoint('ap6', cls=OVSKernelAP, ssid='ap6-ssid',
                            channel='11', mode='g', position='528.0,56.0,0',
                            range=150, txpower=20)
    ap7 = net.addAccessPoint('ap7', cls=OVSKernelAP, ssid='ap7-ssid',
                            channel='1', mode='g', position='694.0,127.0,0',
                            range=150, txpower=20)
    ap8 = net.addAccessPoint('ap8', cls=OVSKernelAP, ssid='ap8-ssid',
                            channel='6', mode='g', position='673.0,404.0,0',
                            range=150, txpower=20)

    info('*** Add hosts/stations\n')
    # Positionner les stations plus près des APs pour garantir la connexion
    sta1 = net.addStation('sta1', ip='10.0.0.1', position='39.0,34.0,0',
                         range=50, txpower=15)
    sta2 = net.addStation('sta2', ip='10.0.0.2', position='168.0,25.0,0',
                         range=50, txpower=15)
    sta3 = net.addStation('sta3', ip='10.0.0.3', position='94.0,404.0,0', range=50, txpower=15)
    sta4 = net.addStation('sta4', ip='10.0.0.4', position='771.0,74.0,0',
                         range=50, txpower=15)
    sta5 = net.addStation('sta5', ip='10.0.0.5', position='739.0,480.0,0',  # Corrigé la position
                         range=50, txpower=15)
    sta6 = net.addStation('sta6', ip='10.0.0.6', position='400.0,400.0,0',
                         range=50, txpower=15)
    sta7 = net.addStation('sta7', ip='10.0.0.7', position='700.0,200.0,0',
                         range=50, txpower=15)
    sta8 = net.addStation('sta8', ip='10.0.0.8', position='300.0,400.0,0',
                         range=50, txpower=15)
    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logNormalShadowing", exp=3, variance=5)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info('*** Add links\n')
    # Liens entre APs (backbone filaire)
    net.addLink(ap3, ap1)
    net.addLink(ap1, ap2)
    net.addLink(ap3, ap4)
    net.addLink(ap2, ap6)
    net.addLink(ap7, ap8)
    net.addLink(ap6, ap8)
    net.addLink(ap6, ap7)
    net.addLink(ap5, ap8)
    net.addLink(ap6, ap5)
    net.addLink(ap5, ap4)
    net.addLink(ap2, ap4)

    
    
    # Affichage du graphe
    net.plotGraph(max_x=850, max_y=600)

    info('*** Starting network\n')
    net.build()
    
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches/APs\n')
    for ap in [ap1, ap2, ap3, ap4, ap5, ap6, ap7, ap8]:
        ap.start([c0])

    info('*** Post configure nodes\n')
    
    # Attendre que la topologie soit découverte
    info('*** Waiting for topology discovery...\n')
    time.sleep(5)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
