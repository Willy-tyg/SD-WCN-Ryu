
Ce projet implémente un contrôleur **SDN Ryu** utilisant le **plus court chemin** et une méthode de **compression des règles MINNIE** pour réduire la taille des tables de flux.
Le réseau est simulé avec **Mininet-WiFi**, comprenant 8 AP et 20 stations.
Le contrôleur installe les règles IPv4, gère l’ARP et déclenche automatiquement la compression dès qu’une table atteint 70 entrées.
MINNIE regroupe les règles par destination et crée des **wildcards**, permettant une réduction moyenne d’environ **84 %**.
Un script `count.py` permet de compter le nombre de regle installer dans chaque AP.
Le fichier `network.py` génère la topologie, et ping teste la connectivité.
Le contrôleur détecte aussi la **mobilité** des stations et réinstalle les règles après migration.

Lancement : `ryu-manager minnie.py --observe-links` puis `sudo python3 network.py`.

---
