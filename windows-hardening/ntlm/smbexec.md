# SmbExec/ScExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Comment ça Marche

**Smbexec** est un outil utilisé pour l'exécution de commandes à distance sur des systèmes Windows, similaire à **Psexec**, mais il évite de placer des fichiers malveillants sur le système cible.

### Points Clés à Propos de **SMBExec**

- Il fonctionne en créant un service temporaire (par exemple, "BTOBTO") sur la machine cible pour exécuter des commandes via cmd.exe (%COMSPEC%), sans déposer de binaires.
- Malgré son approche furtive, il génère des journaux d'événements pour chaque commande exécutée, offrant une forme de "shell" non interactif.
- La commande pour se connecter en utilisant **Smbexec** ressemble à ceci:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Exécution de commandes sans binaires

- **Smbexec** permet l'exécution directe de commandes via les chemins binaires des services, éliminant ainsi le besoin de binaires physiques sur la cible.
- Cette méthode est utile pour exécuter des commandes ponctuelles sur une cible Windows. Par exemple, en l'associant au module `web_delivery` de Metasploit, il est possible d'exécuter une charge utile Meterpreter inversée ciblant PowerShell.
- En créant un service distant sur la machine de l'attaquant avec binPath configuré pour exécuter la commande fournie via cmd.exe, il est possible d'exécuter la charge utile avec succès, obtenant ainsi un callback et l'exécution de la charge utile avec l'écouteur Metasploit, même en cas d'erreurs de réponse du service.

### Exemple de commandes

La création et le démarrage du service peuvent être réalisés avec les commandes suivantes:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Pour plus de détails, consultez [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Références
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
