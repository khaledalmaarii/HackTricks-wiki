# Sécurité et élévation des privilèges sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou vous voulez avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de primes !

**Perspectives de piratage**\
Engagez-vous avec du contenu qui explore les sensations et les défis du piratage

**Actualités de piratage en temps réel**\
Restez à jour avec le monde du piratage rapide grâce aux actualités et aux informations en temps réel

**Dernières annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

## Base de MacOS

Si vous n'êtes pas familier avec macOS, vous devriez commencer par apprendre les bases de macOS :

* **Fichiers et permissions spéciaux** de macOS :

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Utilisateurs **courants** de macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Architecture** du **noyau**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Services et protocoles réseau **courants** de macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS **Open Source** : [https://opensource.apple.com/](https://opensource.apple.com/)
* Pour télécharger un fichier `tar.gz`, modifiez une URL telle que [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) en [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Dans les entreprises, les systèmes **macOS** sont très probablement **gérés avec un MDM**. Par conséquent, du point de vue d'un attaquant, il est intéressant de savoir **comment cela fonctionne** :

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspection, débogage et fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protections de sécurité de MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Surface d'attaque

### Permissions de fichier

Si un **processus s'exécutant en tant que root écrit** un fichier qui peut être contrôlé par un utilisateur, l'utilisateur pourrait en abuser pour **escalader les privilèges**.\
Cela peut se produire dans les situations suivantes :

* Le fichier utilisé a déjà été créé par un utilisateur (appartenant à l'utilisateur)
* Le fichier utilisé est accessible en écriture par l'utilisateur en raison d'un groupe
* Le fichier utilisé se trouve dans un répertoire appartenant à l'utilisateur (l'utilisateur peut créer le fichier)
* Le fichier utilisé se trouve dans un répertoire appartenant à root, mais l'utilisateur a un accès en écriture dessus en raison d'un groupe (l'utilisateur peut créer le fichier)

Pouvoir **créer un fichier** qui va être **utilisé par root**, permet à un utilisateur de **profiter de son contenu** ou même de créer des **liens symboliques/hardlinks** pour le pointer vers un autre endroit.

Pour ce type de vulnérabilités, n'oubliez pas de **vérifier les installateurs `.pkg`** vulnérables :

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}
### Gestionnaires d'applications pour les extensions de fichiers et les URL

Des applications étranges enregistrées par des extensions de fichiers peuvent être utilisées de manière abusive et différentes applications peuvent être enregistrées pour ouvrir des protocoles spécifiques.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Privilèges TCC / SIP d'escalade de privilèges macOS

Dans macOS, les **applications et les binaires peuvent avoir des autorisations** pour accéder à des dossiers ou des paramètres qui les rendent plus privilégiés que d'autres.

Par conséquent, un attaquant qui souhaite compromettre avec succès une machine macOS devra **escalader ses privilèges TCC** (ou même **contourner SIP**, selon ses besoins).

Ces privilèges sont généralement accordés sous la forme de **droits** avec lesquels l'application est signée, ou l'application peut demander certains accès et après que l'utilisateur les a **approuvés**, ils peuvent être trouvés dans les **bases de données TCC**. Une autre façon pour un processus d'obtenir ces privilèges est d'être un **enfant d'un processus** avec ces **privilèges**, car ils sont généralement **hérités**.

Suivez ces liens pour découvrir différentes façons d'**escalader les privilèges dans TCC** (macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), de **contourner TCC** (macos-security-protections/macos-tcc/macos-tcc-bypasses/) et comment dans le passé **SIP a été contourné** (macos-security-protections/macos-sip.md#sip-bypasses).

## Escalade de privilèges traditionnelle macOS

Bien sûr, du point de vue des équipes rouges, vous devriez également être intéressé par l'escalade vers le compte root. Consultez le billet suivant pour quelques indices :

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de primes en sécurité !

**Perspectives de piratage**\
Engagez-vous avec du contenu qui explore les sensations et les défis du piratage

**Actualités de piratage en temps réel**\
Restez à jour avec le monde du piratage rapide grâce aux actualités et aux informations en temps réel

**Dernières annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
