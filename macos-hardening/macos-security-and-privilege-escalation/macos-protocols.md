## Services d'accès à distance

Ce sont les services macOS courants pour y accéder à distance.\
Vous pouvez activer/désactiver ces services dans `Préférences Système` --> `Partage`

* **VNC**, connu sous le nom de "Partage d'écran" (tcp:5900)
* **SSH**, appelé "Connexion à distance" (tcp:22)
* **Apple Remote Desktop** (ARD), ou "Gestion à distance" (tcp:3283, tcp:5900)
* **AppleEvent**, connu sous le nom de "Événement Apple à distance" (tcp:3031)

Vérifiez si l'un d'entre eux est activé en exécutant:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

(Cette partie a été [**prise de ce billet de blog**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html))

C'est essentiellement un [VNC](https://fr.wikipedia.org/wiki/Virtual_Network_Computing) modifié avec quelques **fonctionnalités spécifiques à macOS supplémentaires**.\
Cependant, l'option **Partage d'écran** est juste un serveur VNC **basique**. Il y a également une option avancée ARD ou Gestion à distance pour **définir un mot de passe de contrôle d'écran** qui rendra ARD **compatible avec les clients VNC**. Cependant, cette méthode d'authentification présente une faiblesse qui **limite** ce **mot de passe** à un **tampon d'authentification de 8 caractères**, le rendant très facile à **forcer par la méthode brute** avec un outil comme [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) ou [GoRedShell](https://github.com/ahhh/GoRedShell/) (il n'y a également **aucune limite de taux par défaut**).\
Vous pouvez identifier les instances **vulnérables de Partage d'écran** ou de Gestion à distance avec **nmap**, en utilisant le script `vnc-info`, et si le service prend en charge `VNC Authentication (2)`, alors il est probablement **vulnérable à la force brute**. Le service tronquera tous les mots de passe envoyés sur le fil jusqu'à 8 caractères, de sorte que si vous définissez l'authentification VNC sur "password", à la fois "passwords" et "password123" s'authentifieront.

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Si vous voulez l'activer pour escalader les privilèges (accepter les invites TCC), accéder avec une GUI ou espionner l'utilisateur, il est possible de l'activer avec:

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

Vous pouvez passer du mode **observation** au **contrôle partagé** et au **contrôle total**, en passant de l'espionnage d'un utilisateur à la prise en charge de son bureau en un clic. De plus, si vous avez accès à une session ARD, cette session restera ouverte jusqu'à ce que la session soit terminée, même si le mot de passe de l'utilisateur est modifié pendant la session.

Vous pouvez également **envoyer des commandes unix directement** via ARD et vous pouvez spécifier l'utilisateur root pour exécuter des choses en tant que root si vous êtes un utilisateur administratif. Vous pouvez même utiliser cette méthode de commande unix pour planifier des tâches à distance à exécuter à un moment spécifique, cependant cela se produit comme une connexion réseau à l'heure spécifiée (par opposition à être stocké et exécuté sur le serveur cible). Enfin, le Spotlight à distance est l'une de mes fonctionnalités préférées. C'est vraiment génial car vous pouvez exécuter une recherche indexée à faible impact rapidement et à distance. C'est de l'or pour la recherche de fichiers sensibles car c'est rapide, vous permet d'exécuter des recherches simultanément sur plusieurs machines et ne fera pas exploser le processeur.

## Protocole Bonjour

**Bonjour** est une technologie conçue par Apple qui permet aux ordinateurs et aux **appareils situés sur le même réseau de découvrir les services offerts** par d'autres ordinateurs et appareils. Il est conçu de telle sorte que tout appareil compatible Bonjour peut être branché sur un réseau TCP/IP et il **choisira une adresse IP** et rendra les autres ordinateurs de ce réseau **conscients des services qu'il offre**. Bonjour est parfois appelé Rendezvous, **Zero Configuration** ou Zeroconf.\
Le réseau Zero Configuration, tel que Bonjour fournit :

* Doit être capable d'**obtenir une adresse IP** (même sans serveur DHCP)
* Doit être capable de faire une **traduction de nom en adresse** (même sans serveur DNS)
* Doit être capable de **découvrir des services sur le réseau**

L'appareil obtiendra une **adresse IP dans la plage 169.254/16** et vérifiera si un autre appareil utilise cette adresse IP. Si ce n'est pas le cas, il conservera l'adresse IP. Les Mac conservent une entrée dans leur table de routage pour ce sous-réseau : `netstat -rn | grep 169`

Pour le DNS, le protocole **Multicast DNS (mDNS) est utilisé**. Les [**services mDNS** écoutent sur le port **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), utilisent des **requêtes DNS régulières** et utilisent l'**adresse multicast 224.0.0.251** au lieu d'envoyer la demande simplement à une adresse IP. Toute machine écoutant ces demandes répondra, généralement à une adresse multicast, de sorte que tous les appareils peuvent mettre à jour leurs tables.\
Chaque appareil **sélectionnera son propre nom** lors de l'accès au réseau, l'appareil choisira un nom **terminé par .local** (peut être basé sur le nom d'hôte ou un nom complètement aléatoire).

Pour **découvrir des services, DNS Service Discovery (DNS-SD)** est utilisé.

La dernière exigence du réseau Zero Configuration est satisfaite par **DNS Service Discovery (DNS-SD)**. DNS Service Discovery utilise la syntaxe des enregistrements DNS SRV, mais utilise des **enregistrements DNS PTR pour que plusieurs résultats puissent être renvoyés** si plus d'un hôte offre un service particulier. Un client demande la recherche PTR pour le nom `<Service>.<Domain>` et **reçoit** une liste de zéro ou plusieurs enregistrements PTR de la forme `<Instance>.<Service>.<Domain>`.

Le binaire `dns-sd` peut être utilisé pour **annoncer des services et effectuer des recherches** de services :
```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```
Lorsqu'un nouveau service est démarré, **il diffuse sa présence à tous** sur le sous-réseau. L'auditeur n'a pas besoin de demander; il doit simplement être à l'écoute.

Vous pouvez utiliser [**cet outil**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12) pour voir les **services proposés** dans votre réseau local actuel.\
Ou vous pouvez écrire vos propres scripts en python avec [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf):
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
Si vous pensez que Bonjour pourrait être plus sécurisé **désactivé**, vous pouvez le faire avec:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Références

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
