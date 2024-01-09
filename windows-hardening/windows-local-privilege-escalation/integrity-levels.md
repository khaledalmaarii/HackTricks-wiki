<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Niveaux d'intégrité

Depuis Windows Vista, tous les **objets protégés sont étiquetés avec un niveau d'intégrité**. La plupart des fichiers utilisateurs et systèmes et des clés de registre sur le système ont une étiquette par défaut de niveau d'intégrité « moyen ». L'exception principale est un ensemble spécifique de dossiers et de fichiers modifiables par Internet Explorer 7 à faible intégrité. **La plupart des processus** exécutés par les **utilisateurs standards** sont étiquetés avec une intégrité **moyenne** (même ceux démarrés par un utilisateur dans le groupe des administrateurs), et la plupart des **services** sont étiquetés avec une intégrité **Système**. Le répertoire racine est protégé par une étiquette d'intégrité élevée.\
Notez qu'**un processus avec un niveau d'intégrité inférieur ne peut pas écrire sur un objet avec un niveau d'intégrité supérieur.**\
Il existe plusieurs niveaux d'intégrité :

* **Non fiable** – les processus qui sont connectés de manière anonyme sont automatiquement désignés comme Non fiables. _Exemple : Chrome_
* **Bas** – Le niveau d'intégrité Bas est le niveau utilisé par défaut pour l'interaction avec Internet. Tant qu'Internet Explorer est exécuté dans son état par défaut, le Mode Protégé, tous les fichiers et processus qui lui sont associés se voient attribuer le niveau d'intégrité Bas. Certains dossiers, tels que le **Dossier Internet Temporaire**, sont également attribués par défaut au niveau d'intégrité **Bas**. Cependant, notez qu'un **processus à faible intégrité** est très **restreint**, il **ne peut pas** écrire dans le **registre** et il est limité pour écrire dans **la plupart des emplacements** dans le profil de l'utilisateur actuel.  _Exemple : Internet Explorer ou Microsoft Edge_
* **Moyen** – Moyen est le contexte dans lequel **la plupart des objets fonctionneront**. Les utilisateurs standards reçoivent le niveau d'intégrité Moyen, et tout objet non explicitement désigné avec un niveau d'intégrité inférieur ou supérieur est Moyen par défaut. Notez qu'un utilisateur dans le groupe des Administrateurs utilisera par défaut des niveaux d'intégrité moyens.
* **Élevé** – Les **Administrateurs** se voient accorder le niveau d'intégrité Élevé. Cela garantit que les Administrateurs sont capables d'interagir avec et de modifier des objets attribués à des niveaux d'intégrité Moyen ou Bas, mais peuvent également agir sur d'autres objets avec un niveau d'intégrité Élevé, ce que les utilisateurs standards ne peuvent pas faire. _Exemple : "Exécuter en tant qu'Administrateur"_
* **Système** – Comme son nom l'indique, le niveau d'intégrité Système est réservé au système. Le noyau Windows et les services centraux se voient accorder le niveau d'intégrité Système. Être encore plus élevé que le niveau d'intégrité Élevé des Administrateurs protège ces fonctions centrales de toute affectation ou compromission, même par les Administrateurs. Exemple : Services
* **Installateur** – Le niveau d'intégrité Installateur est un cas particulier et est le plus élevé de tous les niveaux d'intégrité. En vertu d'être égal ou supérieur à tous les autres niveaux d'intégrité WIC, les objets attribués au niveau d'intégrité Installateur sont également capables de désinstaller tous les autres objets.

Vous pouvez obtenir le niveau d'intégrité d'un processus en utilisant **Process Explorer** de **Sysinternals**, en accédant aux **propriétés** du processus et en consultant l'onglet "**Sécurité**" :

![](<../../.gitbook/assets/image (318).png>)

Vous pouvez également obtenir votre **niveau d'intégrité actuel** en utilisant `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveaux d'intégrité dans le système de fichiers

Un objet à l'intérieur du système de fichiers peut nécessiter un **niveau d'intégrité minimum requis** et si un processus n'a pas ce niveau d'intégrité, il ne pourra pas interagir avec lui.\
Par exemple, créons **un fichier régulier à partir d'une console utilisateur régulière et vérifions les permissions** :
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
Maintenant, attribuons un niveau d'intégrité minimum de **High** au fichier. Cela **doit être fait à partir d'une console** exécutée en tant qu'**administrateur**, car une **console normale** fonctionnera au niveau d'intégrité Medium et **ne sera pas autorisée** à attribuer le niveau d'intégrité High à un objet :
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
Voici où les choses deviennent intéressantes. Vous pouvez voir que l'utilisateur `DESKTOP-IDJHTKP\user` a des **privilèges COMPLETS** sur le fichier (en effet, c'était l'utilisateur qui a créé le fichier), cependant, en raison du niveau d'intégrité minimal mis en œuvre, il ne pourra plus modifier le fichier à moins qu'il ne soit exécuté dans un Niveau d'Intégrité Élevé (notez qu'il pourra le lire) :
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Ainsi, lorsqu'un fichier a un niveau d'intégrité minimal, pour le modifier, vous devez exécuter au moins à ce niveau d'intégrité.**
{% endhint %}

## Niveaux d'intégrité dans les binaires

J'ai fait une copie de `cmd.exe` dans `C:\Windows\System32\cmd-low.exe` et je lui ai attribué **un niveau d'intégrité bas à partir d'une console d'administrateur :**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Maintenant, lorsque j'exécute `cmd-low.exe`, il **s'exécutera sous un niveau d'intégrité bas** au lieu d'un niveau moyen :

![](<../../.gitbook/assets/image (320).png>)

Pour les personnes curieuses, si vous attribuez un niveau d'intégrité élevé à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), il ne s'exécutera pas automatiquement avec un niveau d'intégrité élevé (si vous l'invoquez depuis un niveau d'intégrité moyen --par défaut-- il s'exécutera sous un niveau d'intégrité moyen).

## Niveaux d'intégrité dans les processus

Tous les fichiers et dossiers n'ont pas un niveau d'intégrité minimum, **mais tous les processus s'exécutent sous un niveau d'intégrité**. Et de manière similaire à ce qui se passe avec le système de fichiers, **si un processus veut écrire dans un autre processus, il doit avoir au moins le même niveau d'intégrité**. Cela signifie qu'un processus avec un niveau d'intégrité bas ne peut pas ouvrir un handle avec un accès complet à un processus avec un niveau d'intégrité moyen.

En raison des restrictions commentées dans cette section et la précédente, d'un point de vue sécurité, il est toujours **recommandé d'exécuter un processus au niveau d'intégrité le plus bas possible**.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
