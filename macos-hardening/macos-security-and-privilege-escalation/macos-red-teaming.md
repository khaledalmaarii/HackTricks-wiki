# Red Teaming sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Méthodes de gestion courantes

* JAMF Pro : `jamf checkJSSConnection`
* Kandji

Si vous parvenez à **compromettre les identifiants d'administrateur** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre logiciel malveillant sur les machines.

Pour le red teaming dans les environnements macOS, il est fortement recommandé de comprendre le fonctionnement des MDM :

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

Et aussi sur les **protocoles réseau** **spéciaux** de **MacOS** :

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Dans certains cas, vous constaterez que l'**ordinateur macOS est connecté à un AD**. Dans ce scénario, vous devriez essayer de **d'énumérer** l'annuaire actif comme vous en avez l'habitude. Trouvez de l'**aide** dans les pages suivantes :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Un **outil local MacOS** qui peut également vous aider est `dscl` :
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Il existe également des outils préparés pour MacOS pour énumérer automatiquement l'AD et jouer avec Kerberos :

* [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l'outil d'audit Bloodhound permettant de collecter et d'ingérer des relations Active Directory sur des hôtes MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les API Heimdal krb5 sur macOS. Le but du projet est de permettre de meilleurs tests de sécurité autour de Kerberos sur les appareils macOS en utilisant des API natives sans nécessiter d'autres frameworks ou packages sur la cible.
* [**Orchard**](https://github.com/its-a-feature/Orchard) : Outil JavaScript pour l'automatisation (JXA) pour effectuer une énumération Active Directory.

### Informations de domaine
```
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utilisateurs

Les trois types d'utilisateurs MacOS sont :

* **Utilisateurs locaux** - Gérés par le service local OpenDirectory, ils ne sont connectés d'aucune manière à Active Directory.
* **Utilisateurs réseau** - Utilisateurs volatils d'Active Directory qui nécessitent une connexion au serveur DC pour s'authentifier.
* **Utilisateurs mobiles** - Utilisateurs d'Active Directory avec une sauvegarde locale de leurs informations d'identification et de leurs fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations sur l'utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_ et les informations sur le groupe _admin_ sont dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus d'utiliser les bords HasSession et AdminTo, **MacHound ajoute trois nouveaux bords** à la base de données Bloodhound :

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

## Services externes

Le Red Teaming de MacOS est différent d'un Red Teaming Windows régulier car généralement **MacOS est intégré à plusieurs plateformes externes directement**. Une configuration courante de MacOS consiste à accéder à l'ordinateur en utilisant des **identifiants synchronisés OneLogin, et à accéder à plusieurs services externes** (comme github, aws...) via OneLogin :

![](<../../.gitbook/assets/image (563).png>)

###

## Références

* [https://www.youtube.com/watch?v=IiMladUbL6E](https://www.youtube.com/watch?v=IiMladUbL6E)
* [https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
