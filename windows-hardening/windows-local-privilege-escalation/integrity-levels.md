# Niveaux d'intégrité

Depuis Windows Vista, tous les **objets protégés sont étiquetés avec un niveau d'intégrité**. La plupart des fichiers utilisateur et système ainsi que les clés de registre du système ont une étiquette de niveau d'intégrité par défaut de "moyen". La principale exception est un ensemble de dossiers et de fichiers spécifiques pouvant être écrits par Internet Explorer 7 à faible intégrité. **La plupart des processus** exécutés par des **utilisateurs standard** sont étiquetés avec une **intégrité moyenne** (même ceux démarrés par un utilisateur appartenant au groupe des administrateurs), et la plupart des **services** sont étiquetés avec une **intégrité système**. Le répertoire racine est protégé par une étiquette d'intégrité élevée.\
Notez qu'**un processus avec un niveau d'intégrité inférieur ne peut pas écrire dans un objet avec un niveau d'intégrité supérieur**.\
Il existe plusieurs niveaux d'intégrité :

* **Non approuvé** - les processus qui se connectent de manière anonyme sont automatiquement désignés comme non approuvés. _Exemple : Chrome_
* **Faible** - Le niveau de faible intégrité est le niveau utilisé par défaut pour l'interaction avec Internet. Tant que Internet Explorer est exécuté dans son état par défaut, le mode protégé, tous les fichiers et processus qui y sont associés sont assignés au niveau de faible intégrité. Certains dossiers, tels que le **dossier Temporaire Internet**, sont également assignés au niveau de **faible intégrité** par défaut. Cependant, notez qu'un **processus de faible intégrité** est très **restreint**, il **ne peut pas** écrire dans le **registre** et il est limité dans l'écriture dans **la plupart des emplacements** dans le profil de l'utilisateur actuel. _Exemple : Internet Explorer ou Microsoft Edge_
* **Moyen** - Moyen est le contexte dans lequel **la plupart des objets fonctionneront**. Les utilisateurs standard reçoivent le niveau d'intégrité moyen, et tout objet qui n'est pas explicitement désigné avec un niveau d'intégrité inférieur ou supérieur est moyen par défaut. Notez qu'un utilisateur appartenant au groupe des administrateurs utilisera par défaut des niveaux d'intégrité moyens.
* **Élevé** - Les **administrateurs** se voient attribuer le niveau d'intégrité élevé. Cela garantit que les administrateurs sont capables d'interagir avec et de modifier des objets assignés à des niveaux d'intégrité moyens ou faibles, mais peuvent également agir sur d'autres objets avec un niveau d'intégrité élevé, ce que les utilisateurs standard ne peuvent pas faire. _Exemple : "Exécuter en tant qu'administrateur"_
* **Système** - Comme son nom l'indique, le niveau d'intégrité système est réservé au système. Le noyau Windows et les services principaux se voient attribuer le niveau d'intégrité système. Étant encore plus élevé que le niveau d'intégrité élevé des administrateurs, cela protège ces fonctions principales contre toute atteinte ou compromission, même par les administrateurs. Exemple : Services
* **Installateur** - Le niveau d'intégrité de l'installateur est un cas spécial et est le plus élevé de tous les niveaux d'intégrité. En vertu d'être égal ou supérieur à tous les autres niveaux d'intégrité WIC, les objets assignés au niveau d'intégrité de l'installateur sont également capables de désinstaller tous les autres objets.

Vous pouvez obtenir le niveau d'intégrité d'un processus en utilisant **Process Explorer** de **Sysinternals**, en accédant aux **propriétés** du processus et en visualisant l'onglet "**Sécurité**" :

![](<../../.gitbook/assets/image (318).png>)

Vous pouvez également obtenir votre **niveau d'intégrité actuel** en utilisant `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveaux d'intégrité dans le système de fichiers

Un objet à l'intérieur du système de fichiers peut nécessiter un **niveau d'intégrité minimum requis** et si un processus n'a pas ce niveau d'intégrité, il ne pourra pas interagir avec lui.\
Par exemple, créons un fichier à partir d'une console utilisateur régulière et vérifions les autorisations :
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
```
Maintenant, attribuons un niveau d'intégrité minimum de **Élevé** au fichier. Cela **doit être fait à partir d'une console** en tant qu'**administrateur** car une **console régulière** s'exécute avec un niveau d'intégrité Moyen et **ne sera pas autorisée** à attribuer un niveau d'intégrité Élevé à un objet :
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
        Mandatory Label\High Mandatory Level:(NW)
```
Ici, les choses deviennent intéressantes. Vous pouvez voir que l'utilisateur `DESKTOP-IDJHTKP\user` a des **privilèges COMPLETS** sur le fichier (en effet, c'était l'utilisateur qui a créé le fichier), cependant, en raison du niveau d'intégrité minimum implémenté, il ne pourra plus modifier le fichier à moins qu'il ne s'exécute à l'intérieur d'un niveau d'intégrité élevé (notez qu'il pourra le lire).
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
Ainsi, lorsqu'un fichier a un niveau d'intégrité minimum, pour le modifier, vous devez être en train de fonctionner au moins à ce niveau d'intégrité.
{% endhint %}

## Niveaux d'intégrité dans les binaires

J'ai fait une copie de `cmd.exe` dans `C:\Windows\System32\cmd-low.exe` et je lui ai attribué un **niveau d'intégrité faible à partir d'une console d'administrateur :**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```
Maintenant, lorsque j'exécute `cmd-low.exe`, il **s'exécute avec un niveau d'intégrité faible** au lieu d'un niveau moyen :

![](<../../.gitbook/assets/image (320).png>)

Pour les personnes curieuses, si vous attribuez un niveau d'intégrité élevé à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), il ne s'exécutera pas automatiquement avec un niveau d'intégrité élevé (s'il est invoqué à partir d'un niveau d'intégrité moyen - par défaut - il s'exécutera avec un niveau d'intégrité moyen).

## Niveaux d'intégrité dans les processus

Tous les fichiers et dossiers n'ont pas de niveau d'intégrité minimum, **mais tous les processus s'exécutent avec un niveau d'intégrité**. Et de manière similaire à ce qui s'est passé avec le système de fichiers, **si un processus veut écrire à l'intérieur d'un autre processus, il doit avoir au moins le même niveau d'intégrité**. Cela signifie qu'un processus avec un niveau d'intégrité faible ne peut pas ouvrir une poignée avec un accès complet à un processus avec un niveau d'intégrité moyen.

En raison des restrictions mentionnées dans cette section et dans la section précédente, d'un point de vue de la sécurité, il est toujours **recommandé d'exécuter un processus avec le niveau d'intégrité le plus bas possible**.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
