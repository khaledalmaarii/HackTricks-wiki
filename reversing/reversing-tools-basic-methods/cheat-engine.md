<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont stockées les valeurs importantes dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, vous êtes **présenté** avec un **tutoriel** sur la façon d'utiliser l'outil. Si vous voulez apprendre à utiliser l'outil, il est fortement recommandé de le compléter.

# Que cherchez-vous ?

![](<../../.gitbook/assets/image (580).png>)

Cet outil est très utile pour trouver **où une certaine valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
**Généralement, les nombres** sont stockés sous forme de **4 octets**, mais vous pouvez également les trouver sous forme de **double** ou de **float**, ou vous pouvez vouloir chercher quelque chose de **différent d'un nombre**. Pour cette raison, vous devez être sûr de **sélectionner** ce que vous voulez **chercher** :

![](<../../.gitbook/assets/image (581).png>)

Vous pouvez également indiquer **différents types de recherches** :

![](<../../.gitbook/assets/image (582).png>)

Vous pouvez également cocher la case pour **arrêter le jeu pendant la numérisation de la mémoire** :

![](<../../.gitbook/assets/image (584).png>)

## Raccourcis clavier

Dans _**Edit --> Settings --> Hotkeys**_, vous pouvez définir différents **raccourcis clavier** pour différentes fins, comme **arrêter** le **jeu** (ce qui est très utile si à un moment donné vous voulez numériser la mémoire). D'autres options sont disponibles :

![](<../../.gitbook/assets/image (583).png>)

# Modification de la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous recherchez (plus d'informations à ce sujet dans les étapes suivantes), vous pouvez la **modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![](<../../.gitbook/assets/image
