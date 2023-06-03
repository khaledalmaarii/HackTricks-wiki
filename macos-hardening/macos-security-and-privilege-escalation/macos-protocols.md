# Services et protocoles réseau macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Services d'accès à distance

Ce sont les services macOS courants pour y accéder à distance.\
Vous pouvez activer/désactiver ces services dans `Préférences Système` --> `Partage`

* **VNC**, connu sous le nom de "Partage d'écran"
* **SSH**, appelé "Connexion à distance"
* **Apple Remote Desktop** (ARD), ou "Gestion à distance"
* **AppleEvent**, connu sous le nom de "Événement Apple à distance"

Vérifiez si l'un d'entre eux est activé en exécutant :
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
## Protocole Bonjour

**Bonjour** est une technologie conçue par Apple qui permet aux ordinateurs et aux **appareils situés sur le même réseau de découvrir les services offerts** par d'autres ordinateurs et appareils. Elle est conçue de telle sorte que tout appareil compatible Bonjour peut être branché sur un réseau TCP/IP et **obtenir une adresse IP** et faire connaître aux autres ordinateurs du réseau **les services qu'il offre**. Bonjour est parfois appelé Rendezvous, **Zero Configuration** ou Zeroconf.\
Le réseau Zero Configuration, tel que Bonjour fournit :

* Doit être capable d'**obtenir une adresse IP** (même sans serveur DHCP)
* Doit être capable de faire une **traduction de nom en adresse** (même sans serveur DNS)
* Doit être capable de **découvrir les services sur le réseau**

L'appareil obtiendra une **adresse IP dans la plage 169.254/16** et vérifiera si un autre appareil utilise cette adresse IP. Si ce n'est pas le cas, il conservera l'adresse IP. Les Mac conservent une entrée dans leur table de routage pour ce sous-réseau : `netstat -rn | grep 169`

Pour le DNS, le protocole **Multicast DNS (mDNS) est utilisé**. Les [**services mDNS** écoutent sur le port **5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md), utilisent des **requêtes DNS régulières** et utilisent l'**adresse multicast 224.0.0.251** au lieu d'envoyer la demande à une adresse IP. Toute machine écoutant ces demandes répondra, généralement à une adresse multicast, de sorte que tous les appareils peuvent mettre à jour leurs tables.\
Chaque appareil **sélectionne son propre nom** lorsqu'il accède au réseau, l'appareil choisira un nom **se terminant par .local** (peut être basé sur le nom d'hôte ou un nom complètement aléatoire).

Pour **découvrir les services, DNS Service Discovery (DNS-SD)** est utilisé.

L'exigence finale du réseau Zero Configuration est satisfaite par **DNS Service Discovery (DNS-SD)**. DNS Service Discovery utilise la syntaxe des enregistrements DNS SRV, mais utilise des **enregistrements DNS PTR pour que plusieurs résultats puissent être renvoyés** si plus d'un hôte offre un service particulier. Un client demande la recherche PTR pour le nom `<Service>.<Domain>` et **reçoit** une liste de zéro ou plusieurs enregistrements PTR de la forme `<Instance>.<Service>.<Domain>`.

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
Lorsqu'un nouveau service est lancé, **le nouveau service diffuse sa présence à tous** sur le sous-réseau. Le récepteur n'a pas besoin de demander; il doit simplement être à l'écoute.

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

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
