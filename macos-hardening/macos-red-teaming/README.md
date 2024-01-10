# macOS Red Teaming

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Abuser des MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Si vous parvenez à **compromettre les identifiants d'administrateur** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre malware sur les machines.

Pour le red teaming dans les environnements MacOS, il est fortement recommandé d'avoir une certaine compréhension du fonctionnement des MDMs :

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Utiliser un MDM comme un C2

Un MDM aura la permission d'installer, de requêter ou de supprimer des profils, d'installer des applications, de créer des comptes administrateurs locaux, de définir un mot de passe de firmware, de changer la clé FileVault...

Pour exécuter votre propre MDM, vous devez faire **signer votre CSR par un fournisseur**, ce que vous pourriez essayer d'obtenir avec [**https://mdmcert.download/**](https://mdmcert.download/). Et pour exécuter votre propre MDM pour les appareils Apple, vous pourriez utiliser [**MicroMDM**](https://github.com/micromdm/micromdm).

Cependant, pour installer une application sur un appareil inscrit, vous avez toujours besoin qu'elle soit signée par un compte développeur... cependant, lors de l'inscription au MDM, l'**appareil ajoute le certificat SSL du MDM comme une CA de confiance**, vous pouvez donc maintenant signer n'importe quoi.

Pour inscrire l'appareil à un MDM, vous devez installer un fichier **`mobileconfig`** en tant que root, qui pourrait être livré via un fichier **pkg** (vous pourriez le compresser en zip et lorsqu'il est téléchargé depuis safari, il sera décompressé).

**L'agent Mythic Orthrus** utilise cette technique.

### Abuser de JAMF PRO

JAMF peut exécuter des **scripts personnalisés** (scripts développés par le sysadmin), des **charges utiles natives** (création de compte local, définition du mot de passe EFI, surveillance de fichier/processus...) et **MDM** (configurations d'appareils, certificats d'appareils...).

#### Auto-inscription JAMF

Allez sur une page telle que `https://<nom-de-l'entreprise>.jamfcloud.com/enroll/` pour voir si l'**auto-inscription est activée**. Si c'est le cas, cela pourrait **demander des identifiants pour accéder**.

Vous pourriez utiliser le script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) pour effectuer une attaque par pulvérisation de mot de passe.

De plus, après avoir trouvé les bons identifiants, vous pourriez être capable de forcer brutalement d'autres noms d'utilisateur avec le formulaire suivant :

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Authentification de l'appareil JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Le binaire **`jamf`** contenait le secret pour ouvrir le trousseau qui, au moment de la découverte, était **partagé** entre tout le monde et c'était : **`jk23ucnq91jfu9aj`**.\
De plus, jamf **persiste** en tant que **LaunchDaemon** dans **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Prise de contrôle de l'appareil JAMF

L'**URL JSS** (Jamf Software Server) que **`jamf`** utilisera se trouve dans **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ce fichier contient essentiellement l'URL :

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Ainsi, un attaquant pourrait déposer un paquet malveillant (`pkg`) qui **remplace ce fichier** lors de l'installation en définissant l'**URL pour un écouteur Mythic C2 d'un agent Typhon** pour maintenant pouvoir abuser de JAMF comme C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Impersonation de JAMF

Pour **impersonner la communication** entre un appareil et JMF, vous avez besoin :

* Du **UUID** de l'appareil : `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Du **trousseau JAMF** situé dans : `/Library/Application\ Support/Jamf/JAMF.keychain` qui contient le certificat de l'appareil

Avec ces informations, **créez une VM** avec le **UUID matériel volé** et avec **SIP désactivé**, déposez le **trousseau JAMF,** **interceptez** l'agent Jamf et volez ses informations.

#### Vol de secrets

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Vous pouvez également surveiller l'emplacement `/Library/Application Support/Jamf/tmp/` pour les **scripts personnalisés** que les administrateurs pourraient vouloir exécuter via Jamf, car ils sont **placés ici, exécutés et supprimés**. Ces scripts **peuvent contenir des identifiants**.

Cependant, les **identifiants** peuvent être transmis à ces scripts en tant que **paramètres**, donc vous devriez surveiller `ps aux | grep -i jamf` (sans même être root).

Le script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) peut écouter l'ajout de nouveaux fichiers et les nouveaux arguments de processus.

### Accès à distance macOS

Et aussi sur les **protocoles réseau** "spéciaux" de **MacOS** :

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Dans certains cas, vous constaterez que l'**ordinateur MacOS est connecté à un AD**. Dans ce scénario, vous devriez essayer d'**énumérer** l'active directory comme vous en avez l'habitude. Trouvez de l'**aide** dans les pages suivantes :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Un **outil MacOS local** qui peut également vous aider est `dscl` :
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Il existe également des outils préparés pour MacOS pour énumérer automatiquement l'AD et jouer avec kerberos :

* [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l'outil d'audit Bloodhound permettant de collecter et d'ingérer les relations Active Directory sur les hôtes MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les API krb5 de Heimdal sur macOS. L'objectif du projet est de permettre de meilleurs tests de sécurité autour de Kerberos sur les appareils macOS en utilisant les API natives sans nécessiter d'autres frameworks ou paquets sur la cible.
* [**Orchard**](https://github.com/its-a-feature/Orchard) : Outil JavaScript for Automation (JXA) pour faire l'énumération Active Directory.

### Informations sur le domaine
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utilisateurs

Les trois types d'utilisateurs MacOS sont :

* **Utilisateurs locaux** — Gérés par le service OpenDirectory local, ils ne sont connectés d'aucune manière à l'Active Directory.
* **Utilisateurs réseau** — Utilisateurs volatils de l'Active Directory qui nécessitent une connexion au serveur DC pour s'authentifier.
* **Utilisateurs mobiles** — Utilisateurs de l'Active Directory avec une sauvegarde locale pour leurs identifiants et fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations concernant l'utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_ et les informations sur le groupe _admin_ sont dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus d'utiliser les arêtes HasSession et AdminTo, **MacHound ajoute trois nouvelles arêtes** à la base de données Bloodhound :

* **CanSSH** - entité autorisée à se connecter en SSH à l'hôte
* **CanVNC** - entité autorisée à se connecter en VNC à l'hôte
* **CanAE** - entité autorisée à exécuter des scripts AppleEvent sur l'hôte
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Plus d'informations sur [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Accès au Trousseau d'accès

Le Trousseau d'accès contient très probablement des informations sensibles qui, si elles sont accédées sans générer une invite, pourraient aider à faire avancer un exercice de red team :

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Services Externes

Le Red Teaming sur MacOS est différent du Red Teaming régulier sur Windows car **MacOS est généralement intégré directement avec plusieurs plateformes externes**. Une configuration commune de MacOS est d'accéder à l'ordinateur en utilisant **des identifiants synchronisés avec OneLogin, et d'accéder à plusieurs services externes** (comme github, aws...) via OneLogin :

![](<../../.gitbook/assets/image (563).png>)

## Diverses techniques de Red Team

### Safari

Lorsqu'un fichier est téléchargé dans Safari, s'il s'agit d'un fichier "sûr", il sera **ouvert automatiquement**. Donc, par exemple, si vous **téléchargez un zip**, il sera automatiquement décompressé :

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Références

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
