# Protections de sécurité macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

Gatekeeper est généralement utilisé pour faire référence à la combinaison de **Quarantine + Gatekeeper + XProtect**, 3 modules de sécurité macOS qui vont essayer de **prévenir les utilisateurs d'exécuter des logiciels potentiellement malveillants téléchargés**.

Plus d'informations dans :

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Limitations des processus

### SIP - Protection de l'intégrité du système

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Bac à sable

Le bac à sable de macOS **limite les applications** s'exécutant à l'intérieur du bac à sable aux **actions autorisées spécifiées dans le profil du bac à sable** avec lequel l'application s'exécute. Cela permet de s'assurer que **l'application n'accédera qu'aux ressources attendues**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparence, Consentement et Contrôle**

**TCC (Transparence, Consentement et Contrôle)** est un mécanisme dans macOS pour **limiter et contrôler l'accès des applications à certaines fonctionnalités**, généralement du point de vue de la confidentialité. Cela peut inclure des choses telles que les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité, l'accès complet au disque et bien d'autres.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Contraintes de lancement

Il contrôle **d'où et quoi** peut lancer un **binaire signé Apple** :

* Vous ne pouvez pas lancer une application directement si elle doit être exécutée par launchd
* Vous ne pouvez pas exécuter une application en dehors de l'emplacement de confiance (comme /System/)

Le fichier qui contient des informations sur ces contraintes est situé dans macOS dans **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** (et dans iOS, il semble qu'il soit dans **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**).

Il semble qu'il était possible d'utiliser l'outil [**img4tool**](https://github.com/tihmstar/img4tool) **pour extraire le cache** :
```bash
img4tool -e in.img4 -o out.bin
```
(However, I haven't been able to compile it in M1). You could also use [**pyimg4**](https://github.com/m1stadev/PyIMG4), but the following script doesn't work with that output.

Ensuite, vous pouvez utiliser un script tel que [**celui-ci**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) pour extraire les données.

À partir de ces données, vous pouvez vérifier les applications avec une **valeur de contrainte de lancement de `0`**, qui sont celles qui ne sont pas contraintes ([**vérifiez ici**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) pour connaître la signification de chaque valeur).

## MRT - Outil de suppression de logiciels malveillants

L'outil de suppression de logiciels malveillants (MRT) est une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la fonction principale de MRT est de **supprimer les logiciels malveillants connus des systèmes infectés**.

Une fois qu'un logiciel malveillant est détecté sur un Mac (soit par XProtect, soit par d'autres moyens), MRT peut être utilisé pour **supprimer automatiquement le logiciel malveillant**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement chaque fois que le système est mis à jour ou lorsqu'une nouvelle définition de logiciel malveillant est téléchargée (il semble que les règles que MRT utilise pour détecter les logiciels malveillants soient intégrées dans le binaire).

Bien que XProtect et MRT fassent tous deux partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

* **XProtect** est un outil préventif. Il **vérifie les fichiers lorsqu'ils sont téléchargés** (via certaines applications) et s'il détecte des types de logiciels malveillants connus, il **empêche l'ouverture du fichier**, empêchant ainsi le logiciel malveillant d'infecter votre système dès le départ.
* **MRT**, en revanche, est un outil **réactif**. Il intervient après la détection d'un logiciel malveillant sur un système, dans le but de supprimer le logiciel incriminé et de nettoyer le système.

L'application MRT se trouve dans **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestion des tâches en arrière-plan

**macOS** signale maintenant chaque fois qu'un outil utilise une **technique connue pour persister l'exécution du code** (comme les éléments de connexion, les démons...), de sorte que l'utilisateur sait mieux **quel logiciel persiste**.

Il est possible d'**énumérer tous** les éléments d'arrière-plan configurés en exécutant l'outil en ligne de commande d'Apple :
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
De plus, il est également possible de répertorier ces informations avec [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ces informations sont stockées dans **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** et le Terminal a besoin de l'autorisation FDA.

Vous pouvez trouver plus d'informations :

* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

## Cache de confiance

Le cache de confiance d'Apple macOS, parfois appelé cache AMFI (Apple Mobile File Integrity), est un mécanisme de sécurité dans macOS conçu pour **empêcher l'exécution de logiciels non autorisés ou malveillants**. Essentiellement, il s'agit d'une liste de hachages cryptographiques que le système d'exploitation utilise pour **vérifier l'intégrité et l'authenticité du logiciel**.

Lorsqu'une application ou un fichier exécutable tente de s'exécuter sur macOS, le système d'exploitation vérifie le cache de confiance AMFI. Si le **hachage du fichier est trouvé dans le cache de confiance**, le système **autorise** le programme à s'exécuter car il le reconnaît comme étant de confiance.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
