# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Comment fonctionnent-ils

1. Copiez un binaire de service sur le partage ADMIN$ via SMB
2. Créez un service sur la machine distante pointant vers le binaire
3. Démarrez le service à distance
4. Lorsqu'il est fermé, arrêtez le service et supprimez le binaire

## **PsExec manuel**

Tout d'abord, supposons que nous avons un exécutable de charge utile que nous avons généré avec msfvenom et obfusqué avec Veil (afin que l'antivirus ne le signale pas). Dans ce cas, j'ai créé une charge utile meterpreter reverse\_http et l'ai appelée 'met8888.exe'

**Copiez le binaire**. Depuis notre invite de commande "jarrieta", copiez simplement le binaire sur ADMIN$. Cependant, il pourrait être copié et caché n'importe où sur le système de fichiers.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Créez un service**. La commande Windows `sc` est utilisée pour interroger, créer, supprimer, etc. des services Windows et peut être utilisée à distance. En savoir plus à ce sujet [ici](https://technet.microsoft.com/en-us/library/bb490995.aspx). Depuis notre invite de commande, nous allons créer à distance un service appelé "meterpreter" qui pointe vers notre binaire téléchargé :

![](../../.gitbook/assets/sc\_create.png)

**Démarrer le service**. La dernière étape consiste à démarrer le service et à exécuter le binaire. _Note :_ lorsque le service démarre, il "expire" et génère une erreur. C'est parce que notre binaire meterpreter n'est pas un binaire de service réel et ne renverra pas le code de réponse attendu. C'est bien parce que nous avons juste besoin qu'il s'exécute une fois pour démarrer :

![](../../.gitbook/assets/sc\_start\_error.png)

Si nous regardons notre écouteur Metasploit, nous verrons que la session a été ouverte.

**Nettoyez le service.**

![](../../.gitbook/assets/sc\_delete.png)

Extrait d'ici : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Vous pouvez également utiliser le binaire Windows Sysinternals PsExec.exe :**

![](<../../.gitbook/assets/image (165).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
