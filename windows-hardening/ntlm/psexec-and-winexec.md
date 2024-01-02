# PsExec/Winexec/ScExec

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Comment fonctionnent-ils

1. Copier un binaire de service sur le partage ADMIN$ via SMB
2. Créer un service sur la machine distante pointant vers le binaire
3. Démarrer à distance le service
4. Une fois terminé, arrêter le service et supprimer le binaire

## **PsExec manuel**

Supposons d'abord que nous avons un exécutable de charge utile que nous avons généré avec msfvenom et obscurci avec Veil (pour que l'AV ne le détecte pas). Dans ce cas, j'ai créé une charge utile meterpreter reverse_http et je l'ai nommée 'met8888.exe'

**Copier le binaire**. Depuis notre invite de commande "jarrieta", copiez simplement le binaire sur ADMIN$. En réalité, il pourrait être copié et caché n'importe où sur le système de fichiers.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Créer un service**. La commande `sc` de Windows est utilisée pour interroger, créer, supprimer, etc. les services Windows et peut être utilisée à distance. En savoir plus à ce sujet [ici](https://technet.microsoft.com/en-us/library/bb490995.aspx). Depuis notre invite de commande, nous allons créer à distance un service appelé "meterpreter" qui pointe vers notre binaire téléchargé :

![](../../.gitbook/assets/sc\_create.png)

**Démarrer le service**. La dernière étape consiste à démarrer le service et exécuter le binaire. _Note :_ lorsque le service démarre, il "expire" et génère une erreur. C'est parce que notre binaire meterpreter n'est pas un véritable binaire de service et ne renvoie pas le code de réponse attendu. C'est acceptable car nous avons juste besoin qu'il s'exécute une fois pour se déclencher :

![](../../.gitbook/assets/sc\_start\_error.png)

Si nous regardons notre écouteur Metasploit, nous verrons que la session a été ouverte.

**Nettoyer le service.**

![](../../.gitbook/assets/sc\_delete.png)

Extrait d'ici : [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Vous pourriez également utiliser le binaire Windows Sysinternals PsExec.exe :**

![](<../../.gitbook/assets/image (165).png>)

Vous pourriez également utiliser [**SharpLateral**](https://github.com/mertdas/SharpLateral) :

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
```markdown
{% endcode %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
