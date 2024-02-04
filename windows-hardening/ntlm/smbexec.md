# SmbExec/ScExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Comment ça marche

**Smbexec** fonctionne de manière similaire à **Psexec**, ciblant **cmd.exe** ou **powershell.exe** sur le système de la victime pour l'exécution de la porte dérobée, évitant l'utilisation d'exécutables malveillants.

## **SMBExec**
```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```
Smbexec's functionality involves creating a temporary service (e.g., "BTOBTO") on the target machine to execute commands without dropping a binary. This service, constructed to run a command via cmd.exe's path (%COMSPEC%), redirects output to a temporary file and deletes itself post-execution. The method is stealthy but generates event logs for each command, offering a non-interactive "shell" by repeating this process for every command issued from the attacker's side.

## Exécution de commandes sans binaires

Cette approche permet une exécution directe de commandes via des chemins binaires de service, éliminant le besoin de binaires. C'est particulièrement utile pour l'exécution ponctuelle de commandes sur une cible Windows. Par exemple, en utilisant le module `web_delivery` de Metasploit avec une charge utile Meterpreter inversée ciblant PowerShell, il est possible d'établir un écouteur qui fournit la commande d'exécution nécessaire. Créer et démarrer un service distant sur la machine Windows de l'attaquant avec le binPath défini pour exécuter cette commande via cmd.exe permet l'exécution de la charge utile, malgré d'éventuelles erreurs de réponse du service, atteignant le rappel et l'exécution de la charge utile du côté de l'écouteur Metasploit.

### Exemple de commandes

La création et le démarrage du service peuvent être réalisés avec les commandes suivantes:
```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Pour plus de détails, consultez [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


# Références
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
