<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Niveaux d'intégrité

Dans Windows Vista et les versions ultérieures, tous les éléments protégés sont associés à une balise d'**intégrité**. Ce paramétrage attribue principalement un niveau d'intégrité "moyen" aux fichiers et clés de registre, sauf pour certains dossiers et fichiers auxquels Internet Explorer 7 peut écrire à un niveau d'intégrité bas. Le comportement par défaut est que les processus lancés par des utilisateurs standard ont un niveau d'intégrité moyen, tandis que les services fonctionnent généralement à un niveau d'intégrité système. Une étiquette d'intégrité élevée protège le répertoire racine.

Une règle clé est que les objets ne peuvent pas être modifiés par des processus ayant un niveau d'intégrité inférieur à celui de l'objet. Les niveaux d'intégrité sont :

- **Non approuvé** : Ce niveau est destiné aux processus avec des connexions anonymes. %%%Exemple : Chrome%%%
- **Faible** : Principalement pour les interactions Internet, notamment en mode protégé d'Internet Explorer, affectant les fichiers et processus associés, et certains dossiers comme le **Dossier Internet Temporaire**. Les processus à faible intégrité font face à des restrictions importantes, notamment l'absence d'accès en écriture au registre et un accès limité en écriture au profil utilisateur.
- **Moyen** : Le niveau par défaut pour la plupart des activités, attribué aux utilisateurs standard et aux objets sans niveaux d'intégrité spécifiques. Même les membres du groupe Administrateurs fonctionnent à ce niveau par défaut.
- **Élevé** : Réservé aux administrateurs, leur permettant de modifier des objets à des niveaux d'intégrité inférieurs, y compris ceux au niveau élevé lui-même.
- **Système** : Le niveau opérationnel le plus élevé pour le noyau Windows et les services principaux, inaccessible même pour les administrateurs, assurant la protection des fonctions système vitales.
- **Installateur** : Un niveau unique qui se situe au-dessus de tous les autres, permettant aux objets à ce niveau de désinstaller tout autre objet.

Vous pouvez obtenir le niveau d'intégrité d'un processus en utilisant **Process Explorer** de **Sysinternals**, en accédant aux **propriétés** du processus et en consultant l'onglet "**Sécurité**" :

![](<../../.gitbook/assets/image (318).png>)

Vous pouvez également obtenir votre **niveau d'intégrité actuel** en utilisant `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveaux d'intégrité dans le système de fichiers

Un objet à l'intérieur du système de fichiers peut nécessiter un **niveau d'intégrité minimum requis** et si un processus n'a pas ce niveau d'intégrité, il ne pourra pas interagir avec lui.\
Par exemple, créons un **fichier régulier à partir d'une console utilisateur régulière et vérifions les autorisations** :
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
Maintenant, attribuons un niveau d'intégrité minimum de **Élevé** au fichier. Cela **doit être fait à partir d'une console** s'exécutant en tant qu'**administrateur** car une **console normale** s'exécute au niveau d'intégrité Moyen et **ne sera pas autorisée** à attribuer un niveau d'intégrité Élevé à un objet :
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
C'est là que les choses deviennent intéressantes. Vous pouvez voir que l'utilisateur `DESKTOP-IDJHTKP\user` a **des privilèges COMPLETS** sur le fichier (en effet, c'était l'utilisateur qui a créé le fichier), cependant, en raison du niveau d'intégrité minimum implémenté, il ne pourra plus modifier le fichier à moins qu'il ne soit en cours d'exécution à l'intérieur d'un niveau d'intégrité élevé (notez qu'il pourra le lire) :
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Par conséquent, lorsqu'un fichier a un niveau d'intégrité minimum, pour le modifier vous devez au moins être en cours d'exécution à ce niveau d'intégrité.**
{% endhint %}

## Niveaux d'intégrité dans les binaires

J'ai fait une copie de `cmd.exe` dans `C:\Windows\System32\cmd-low.exe` et je lui ai attribué un **niveau d'intégrité bas à partir d'une console d'administrateur :**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Maintenant, lorsque j'exécute `cmd-low.exe`, il **s'exécutera avec un niveau d'intégrité bas** au lieu d'un niveau moyen :

![](<../../.gitbook/assets/image (320).png>)

Pour les curieux, si vous attribuez un niveau d'intégrité élevé à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), il ne s'exécutera pas automatiquement avec un niveau d'intégrité élevé (si vous l'invoquez à partir d'un niveau d'intégrité moyen --par défaut-- il s'exécutera avec un niveau d'intégrité moyen).

## Niveaux d'intégrité dans les processus

Tous les fichiers et dossiers n'ont pas un niveau d'intégrité minimum, **mais tous les processus s'exécutent avec un niveau d'intégrité**. Et de manière similaire à ce qui s'est passé avec le système de fichiers, **si un processus souhaite écrire à l'intérieur d'un autre processus, il doit avoir au moins le même niveau d'intégrité**. Cela signifie qu'un processus avec un niveau d'intégrité bas ne peut pas ouvrir une poignée avec un accès complet à un processus avec un niveau d'intégrité moyen.

En raison des restrictions mentionnées dans cette section et la précédente, d'un point de vue sécurité, il est toujours **recommandé d'exécuter un processus avec le niveau d'intégrité le plus bas possible**.
