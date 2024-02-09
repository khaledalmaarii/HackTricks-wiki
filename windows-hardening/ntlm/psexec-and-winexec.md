# PsExec/Winexec/ScExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Comment fonctionnent-ils

Le processus est décrit dans les étapes ci-dessous, illustrant comment les binaires de service sont manipulés pour obtenir une exécution à distance sur une machine cible via SMB :

1. **Copie d'un binaire de service sur le partage ADMIN$ via SMB** est effectuée.
2. **Création d'un service sur la machine distante** en pointant vers le binaire.
3. Le service est **démarré à distance**.
4. À la sortie, le service est **arrêté et le binaire est supprimé**.

### **Processus d'exécution manuelle de PsExec**

En supposant qu'il y a une charge utile exécutable (créée avec msfvenom et obfusquée à l'aide de Veil pour éviter la détection par les antivirus), nommée 'met8888.exe', représentant une charge utile meterpreter reverse_http, les étapes suivantes sont prises :

- **Copie du binaire** : L'exécutable est copié sur le partage ADMIN$ à partir d'une invite de commande, bien qu'il puisse être placé n'importe où sur le système de fichiers pour rester caché.

- **Création d'un service** : En utilisant la commande Windows `sc`, qui permet de interroger, créer et supprimer des services Windows à distance, un service nommé "meterpreter" est créé pour pointer vers le binaire téléchargé.

- **Démarrage du service** : La dernière étape consiste à démarrer le service, ce qui entraînera probablement une erreur "d'expiration" en raison du binaire n'étant pas un binaire de service authentique et ne renvoyant pas le code de réponse attendu. Cette erreur est sans conséquence car l'objectif principal est l'exécution du binaire.

L'observation du listener Metasploit révélera que la session a été initiée avec succès.

[En savoir plus sur la commande `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trouvez des étapes plus détaillées dans : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Vous pourriez également utiliser le binaire Windows Sysinternals PsExec.exe :**

![](<../../.gitbook/assets/image (165).png>)

Vous pourriez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

D'autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
