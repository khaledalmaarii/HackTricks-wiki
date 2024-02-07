# Services et protocoles réseau macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Services d'accès à distance

Ce sont les services macOS courants pour y accéder à distance.\
Vous pouvez activer/désactiver ces services dans `Préférences Système` --> `Partage`

* **VNC**, connu sous le nom de "Partage d'écran" (tcp:5900)
* **SSH**, appelé "Connexion à distance" (tcp:22)
* **Apple Remote Desktop** (ARD), ou "Gestion à distance" (tcp:3283, tcp:5900)
* **AppleEvent**, connu sous le nom de "Événement Apple à distance" (tcp:3031)

Vérifiez si l'un d'eux est activé en exécutant :
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Test de pénétration ARD

Apple Remote Desktop (ARD) est une version améliorée de [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adaptée pour macOS, offrant des fonctionnalités supplémentaires. Une vulnérabilité notable dans ARD est sa méthode d'authentification pour le mot de passe de l'écran de contrôle, qui utilise uniquement les 8 premiers caractères du mot de passe, le rendant vulnérable aux [attaques par force brute](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) avec des outils comme Hydra ou [GoRedShell](https://github.com/ahhh/GoRedShell/), car il n'y a pas de limites de taux par défaut.

Les instances vulnérables peuvent être identifiées en utilisant le script `vnc-info` de **nmap**. Les services prenant en charge l'`Authentification VNC (2)` sont particulièrement susceptibles aux attaques par force brute en raison de la troncature du mot de passe à 8 caractères.

Pour activer ARD pour diverses tâches administratives telles que l'escalade de privilèges, l'accès GUI ou la surveillance des utilisateurs, utilisez la commande suivante:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD offre des niveaux de contrôle polyvalents, y compris l'observation, le contrôle partagé et le contrôle total, les sessions persistant même après des changements de mot de passe utilisateur. Il permet d'envoyer directement des commandes Unix, de les exécuter en tant que root pour les utilisateurs administratifs. La planification de tâches et la recherche Spotlight à distance sont des fonctionnalités notables, facilitant les recherches à distance et à faible impact de fichiers sensibles sur plusieurs machines.


## Protocole Bonjour

Bonjour, une technologie conçue par Apple, permet aux **appareils sur le même réseau de détecter les services offerts par les autres**. Connu également sous le nom de Rendezvous, **Zero Configuration** ou Zeroconf, il permet à un appareil de rejoindre un réseau TCP/IP, de **choisir automatiquement une adresse IP** et de diffuser ses services à d'autres appareils du réseau.

Le Réseau Zero Configuration, fourni par Bonjour, garantit que les appareils peuvent :
* **Obtenir automatiquement une adresse IP** même en l'absence d'un serveur DHCP.
* Effectuer une **traduction de nom en adresse** sans nécessiter de serveur DNS.
* **Découvrir les services** disponibles sur le réseau.

Les appareils utilisant Bonjour s'attribueront une **adresse IP de la plage 169.254/16** et vérifieront son unicité sur le réseau. Les Mac maintiennent une entrée de table de routage pour ce sous-réseau, vérifiable via `netstat -rn | grep 169`.

Pour le DNS, Bonjour utilise le **protocole Multicast DNS (mDNS)**. mDNS fonctionne sur le **port 5353/UDP**, utilisant des **requêtes DNS standard** mais ciblant l'**adresse de multidiffusion 224.0.0.251**. Cette approche garantit que tous les appareils en écoute sur le réseau peuvent recevoir et répondre aux requêtes, facilitant la mise à jour de leurs enregistrements.

Lors de la connexion au réseau, chaque appareil se choisit un nom, se terminant généralement par **.local**, qui peut être dérivé du nom d'hôte ou généré de manière aléatoire.

La découverte de services au sein du réseau est facilitée par **la Découverte de Services DNS (DNS-SD)**. En exploitant le format des enregistrements SRV DNS, DNS-SD utilise des **enregistrements PTR DNS** pour permettre l'énumération de plusieurs services. Un client recherchant un service spécifique demandera un enregistrement PTR pour `<Service>.<Domaine>`, recevant en retour une liste d'enregistrements PTR formatés comme `<Instance>.<Service>.<Domaine>` si le service est disponible à partir de plusieurs hôtes.


L'utilitaire `dns-sd` peut être utilisé pour **découvrir et annoncer des services réseau**. Voici quelques exemples de son utilisation :

### Recherche de Services SSH

Pour rechercher des services SSH sur le réseau, la commande suivante est utilisée :
```bash
dns-sd -B _ssh._tcp
```
Ce commandement initie la recherche de services _ssh._tcp et affiche des détails tels que l'horodatage, les indicateurs, l'interface, le domaine, le type de service et le nom de l'instance.

### Publicité d'un service HTTP

Pour annoncer un service HTTP, vous pouvez utiliser :
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ce command enregistre un service HTTP nommé "Index" sur le port 80 avec un chemin `/index.html`.

Pour rechercher ensuite des services HTTP sur le réseau:
```bash
dns-sd -B _http._tcp
```
Lorsqu'un service démarre, il annonce sa disponibilité à tous les appareils sur le sous-réseau en diffusant sa présence. Les appareils intéressés par ces services n'ont pas besoin d'envoyer de demandes mais doivent simplement écouter ces annonces.

Pour une interface plus conviviale, l'application **Discovery - DNS-SD Browser** disponible sur l'Apple App Store peut visualiser les services offerts sur votre réseau local.

Alternativement, des scripts personnalisés peuvent être écrits pour parcourir et découvrir des services en utilisant la bibliothèque `python-zeroconf`. Le script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) démontre la création d'un navigateur de services pour les services `_http._tcp.local.`, affichant les services ajoutés ou supprimés:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Désactivation de Bonjour
Si des préoccupations concernant la sécurité ou d'autres raisons nécessitent de désactiver Bonjour, cela peut être fait en utilisant la commande suivante :
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Références

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
