# Niveaux d'intégrité

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Niveaux d'intégrité

Dans Windows Vista et les versions ultérieures, tous les éléments protégés sont dotés d'une étiquette de **niveau d'intégrité**. Cette configuration attribue principalement un niveau d'intégrité "moyen" aux fichiers et aux clés de registre, sauf pour certains dossiers et fichiers auxquels Internet Explorer 7 peut écrire à un niveau d'intégrité faible. Le comportement par défaut est que les processus initiés par des utilisateurs standard ont un niveau d'intégrité moyen, tandis que les services fonctionnent généralement à un niveau d'intégrité système. Une étiquette d'intégrité élevée protège le répertoire racine.

Une règle clé est que les objets ne peuvent pas être modifiés par des processus ayant un niveau d'intégrité inférieur à celui de l'objet. Les niveaux d'intégrité sont :

* **Non fiable** : Ce niveau est destiné aux processus avec des connexions anonymes. %%%Exemple : Chrome%%%
* **Faible** : Principalement pour les interactions Internet, en particulier dans le mode protégé d'Internet Explorer, affectant les fichiers et processus associés, et certains dossiers comme le **Dossier Internet Temporaire**. Les processus à faible intégrité font face à des restrictions significatives, y compris l'absence d'accès en écriture au registre et un accès limité en écriture au profil utilisateur.
* **Moyen** : Le niveau par défaut pour la plupart des activités, attribué aux utilisateurs standard et aux objets sans niveaux d'intégrité spécifiques. Même les membres du groupe Administrateurs fonctionnent à ce niveau par défaut.
* **Élevé** : Réservé aux administrateurs, leur permettant de modifier des objets à des niveaux d'intégrité inférieurs, y compris ceux au niveau élevé lui-même.
* **Système** : Le niveau opérationnel le plus élevé pour le noyau Windows et les services de base, hors de portée même pour les administrateurs, garantissant la protection des fonctions vitales du système.
* **Installateur** : Un niveau unique qui se situe au-dessus de tous les autres, permettant aux objets à ce niveau de désinstaller tout autre objet.

Vous pouvez obtenir le niveau d'intégrité d'un processus en utilisant **Process Explorer** de **Sysinternals**, en accédant aux **propriétés** du processus et en consultant l'onglet "**Sécurité**" :

![](<../../.gitbook/assets/image (824).png>)

Vous pouvez également obtenir votre **niveau d'intégrité actuel** en utilisant `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Niveaux d'intégrité dans le système de fichiers

Un objet dans le système de fichiers peut nécessiter une **exigence de niveau d'intégrité minimum** et si un processus n'a pas ce niveau d'intégrité, il ne pourra pas interagir avec lui.\
Par exemple, créons **un fichier régulier à partir d'une console d'utilisateur régulier et vérifions les autorisations** :
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
Maintenant, assignons un niveau d'intégrité minimum de **High** au fichier. Cela **doit être fait depuis une console** exécutée en tant qu'**administrateur**, car une **console régulière** fonctionnera à un niveau d'intégrité Medium et **ne sera pas autorisée** à attribuer un niveau d'intégrité High à un objet :
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
C'est ici que les choses deviennent intéressantes. Vous pouvez voir que l'utilisateur `DESKTOP-IDJHTKP\user` a **tous les privilèges** sur le fichier (en effet, c'était l'utilisateur qui a créé le fichier), cependant, en raison du niveau d'intégrité minimum mis en œuvre, il ne pourra plus modifier le fichier à moins qu'il ne fonctionne à l'intérieur d'un niveau d'intégrité élevé (notez qu'il pourra le lire) :
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Par conséquent, lorsqu'un fichier a un niveau d'intégrité minimum, pour le modifier, vous devez être exécuté au moins à ce niveau d'intégrité.**
{% endhint %}

### Niveaux d'intégrité dans les binaires

J'ai fait une copie de `cmd.exe` dans `C:\Windows\System32\cmd-low.exe` et lui ai attribué un **niveau d'intégrité bas depuis une console administrateur :**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Maintenant, lorsque j'exécute `cmd-low.exe`, il **s'exécutera sous un niveau d'intégrité faible** au lieu d'un niveau moyen :

![](<../../.gitbook/assets/image (313).png>)

Pour les personnes curieuses, si vous assignez un niveau d'intégrité élevé à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), il ne s'exécutera pas automatiquement avec un niveau d'intégrité élevé (si vous l'invoquez depuis un niveau d'intégrité moyen --par défaut-- il s'exécutera sous un niveau d'intégrité moyen).

### Niveaux d'intégrité dans les processus

Tous les fichiers et dossiers n'ont pas un niveau d'intégrité minimum, **mais tous les processus s'exécutent sous un niveau d'intégrité**. Et similaire à ce qui s'est passé avec le système de fichiers, **si un processus veut écrire à l'intérieur d'un autre processus, il doit avoir au moins le même niveau d'intégrité**. Cela signifie qu'un processus avec un niveau d'intégrité faible ne peut pas ouvrir un handle avec un accès complet à un processus avec un niveau d'intégrité moyen.

En raison des restrictions commentées dans cette section et la précédente, d'un point de vue sécurité, il est toujours **recommandé d'exécuter un processus au niveau d'intégrité le plus bas possible**.
