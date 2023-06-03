## AppArmor

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informations de base

**AppArmor** est une amélioration du noyau pour confiner les **programmes** à un **ensemble limité de ressources** avec des **profils par programme**. Les profils peuvent **autoriser des capacités** telles que l'accès au réseau, l'accès aux sockets bruts et la permission de lire, d'écrire ou d'exécuter des fichiers sur des chemins correspondants.

Il s'agit d'un contrôle d'accès obligatoire ou **MAC** qui lie les attributs de **contrôle d'accès** aux programmes plutôt qu'aux utilisateurs.\
Le confinement AppArmor est fourni via des **profils chargés dans le noyau**, généralement au démarrage.\
Les profils AppArmor peuvent être dans l'un des **deux modes** :

* **Exécution forcée** : Les profils chargés en mode exécution forcée entraîneront **l'application de la politique** définie dans le profil **ainsi que le signalement** des tentatives de violation de la politique (soit via syslog, soit via auditd).
* **Plainte** : Les profils en mode plainte **ne feront pas appliquer la politique** mais **signaleront** plutôt les tentatives de **violation de la politique**.

AppArmor diffère de certains autres systèmes MAC sur Linux : il est **basé sur le chemin**, il permet le mélange de profils en mode exécution forcée et en mode plainte, il utilise des fichiers d'inclusion pour faciliter le développement et il a une barrière d'entrée bien plus basse que d'autres systèmes MAC populaires.

### Parties d'AppArmor

* **Module du noyau** : Fait le travail réel
* **Politiques** : Définit le comportement et la confinement
* **Analyseur** : Charge les politiques dans le noyau
* **Utilitaires** : Programmes en mode utilisateur pour interagir avec AppArmor

### Chemin des profils

Les profils Apparmor sont généralement enregistrés dans _**/etc/apparmor.d/**_\
Avec `sudo aa-status`, vous pourrez lister les binaires qui sont restreints par un profil. Si vous pouvez changer le caractère "/" pour un point du chemin de chaque binaire répertorié, vous obtiendrez le nom du profil Apparmor à l'intérieur du dossier mentionné.

Par exemple, un profil **AppArmor** pour _/usr/bin/man_ sera situé dans _/etc/apparmor.d/usr.bin.man_

### Commandes
```bash
aa-status     #check the current status 
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Création d'un profil

* Pour indiquer l'exécutable affecté, les **chemins absolus et les caractères génériques** sont autorisés (pour la recherche de fichiers) pour spécifier les fichiers.
* Pour indiquer l'accès que le binaire aura aux **fichiers**, les **contrôles d'accès** suivants peuvent être utilisés :
  * **r** (lecture)
  * **w** (écriture)
  * **m** (cartographie de la mémoire en tant qu'exécutable)
  * **k** (verrouillage de fichier)
  * **l** (création de liens durs)
  * **ix** (pour exécuter un autre programme avec le nouveau programme héritant de la politique)
  * **Px** (exécuter sous un autre profil, après nettoyage de l'environnement)
  * **Cx** (exécuter sous un profil enfant, après nettoyage de l'environnement)
  * **Ux** (exécuter sans confinement, après nettoyage de l'environnement)
* Des **variables** peuvent être définies dans les profils et peuvent être manipulées depuis l'extérieur du profil. Par exemple : @{PROC} et @{HOME} (ajouter #include \<tunables/global> au fichier de profil)
* Les **règles de refus sont prises en charge pour remplacer les règles d'autorisation**.

### aa-genprof

Pour commencer facilement à créer un profil, apparmor peut vous aider. Il est possible de faire **inspecter les actions effectuées par un binaire par apparmor, puis de vous laisser décider quelles actions vous voulez autoriser ou refuser**.\
Il suffit d'exécuter :
```bash
sudo aa-genprof /path/to/binary
```
Ensuite, dans une console différente, effectuez toutes les actions que le binaire effectuera normalement :
```bash
/path/to/binary -a dosomething
```
Ensuite, dans la première console, appuyez sur "**s**" et indiquez ensuite si vous voulez ignorer, autoriser ou autre chose pour les actions enregistrées. Lorsque vous avez terminé, appuyez sur "**f**" et le nouveau profil sera créé dans _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous voulez autoriser/refuser/autre
{% endhint %}

### aa-easyprof

Vous pouvez également créer un modèle de profil apparmor d'un binaire avec:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
  #include <abstractions/base>

  # No abstractions specified

  # No policy groups specified

  # No read paths specified

  # No write paths specified
}
```
{% hint style="info" %}
Notez que par défaut, dans un profil créé, rien n'est autorisé, donc tout est refusé. Vous devrez ajouter des lignes comme `/etc/passwd r,` pour autoriser la lecture du binaire `/etc/passwd`, par exemple.
{% endhint %}

Vous pouvez ensuite **forcer** le nouveau profil avec
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modification d'un profil à partir des journaux

L'outil suivant lira les journaux et demandera à l'utilisateur s'il souhaite autoriser certaines des actions interdites détectées :
```bash
sudo aa-logprof
```
{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous voulez autoriser/refuser/autre.
{% endhint %}

### Gestion d'un profil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Journaux

Exemple de journaux **AUDIT** et **DENIED** provenant de _/var/log/audit/audit.log_ de l'exécutable **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Vous pouvez également obtenir ces informations en utilisant :
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor dans Docker

Notez comment le profil **docker-profile** de Docker est chargé par défaut:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
   /sbin/dhclient
   /usr/bin/lxc-start
   /usr/lib/NetworkManager/nm-dhcp-client.action
   /usr/lib/NetworkManager/nm-dhcp-helper
   /usr/lib/chromium-browser/chromium-browser//browser_java
   /usr/lib/chromium-browser/chromium-browser//browser_openjdk
   /usr/lib/chromium-browser/chromium-browser//sanitized_helper
   /usr/lib/connman/scripts/dhclient-script
   docker-default
```
Par défaut, le profil Apparmor docker-default est généré à partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor).

Résumé du profil docker-default :

* Accès à tous les réseaux
* Aucune capacité n'est définie (Cependant, certaines capacités proviendront de l'inclusion de règles de base de base, c'est-à-dire #include \<abstractions/base>)
* L'écriture dans n'importe quel fichier /proc n'est pas autorisée
* Les autres sous-répertoires/fichiers de /proc et /sys sont refusés en lecture/écriture/verrouillage/liens/exécution
* Le montage n'est pas autorisé
* Ptrace ne peut être exécuté que sur un processus confiné par le même profil Apparmor.

Une fois que vous exécutez un conteneur Docker, vous devriez voir la sortie suivante :
```bash
1 processes are in enforce mode.
   docker-default (825)
```
Notez que **apparmor bloquera même les privilèges de capacités** accordés au conteneur par défaut. Par exemple, il sera capable de **bloquer la permission d'écrire à l'intérieur de /proc même si la capacité SYS\_ADMIN est accordée** car par défaut le profil apparmor de docker refuse cet accès:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Vous devez **désactiver apparmor** pour contourner ses restrictions:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Notez que par défaut, **AppArmor** interdit également au conteneur de monter des dossiers de l'intérieur même avec la capacité SYS\_ADMIN.

Notez que vous pouvez **ajouter/supprimer** des **capacités** au conteneur Docker (cela sera toujours restreint par des méthodes de protection comme **AppArmor** et **Seccomp**):

* `--cap-add=SYS_ADMIN` donne la capacité `SYS_ADMIN`
* `--cap-add=ALL` donne toutes les capacités
* `--cap-drop=ALL --cap-add=SYS_PTRACE` supprime toutes les capacités et ne donne que `SYS_PTRACE`

{% hint style="info" %}
Généralement, lorsque vous **constatez** que vous avez une **capacité privilégiée** disponible **à l'intérieur** d'un **conteneur docker mais** que certaines parties de l'**exploit ne fonctionnent pas**, cela est dû à ce que **AppArmor de docker l'empêche**.
{% endhint %}

### Exemple

(Exemple tiré de [**ici**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Pour illustrer la fonctionnalité d'AppArmor, j'ai créé un nouveau profil Docker "mydocker" avec la ligne suivante ajoutée:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Pour activer le profil, nous devons faire ce qui suit:
```
sudo apparmor_parser -r -W mydocker
```
Pour lister les profils, nous pouvons utiliser la commande suivante. La commande ci-dessous liste mon nouveau profil AppArmor.
```
$ sudo apparmor_status  | grep mydocker
   mydocker
```
Comme indiqué ci-dessous, une erreur se produit lorsque nous essayons de modifier "/etc/" car le profil AppArmor empêche l'accès en écriture à "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Contournement d'AppArmor Docker1

Vous pouvez trouver quel **profil apparmor est en cours d'exécution dans un conteneur** en utilisant:
```bash
docker inspect 9d622d73a614 | grep lowpriv
        "AppArmorProfile": "lowpriv",
                "apparmor=lowpriv"
```
Ensuite, vous pouvez exécuter la ligne suivante pour **trouver le profil exact utilisé**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Dans le cas étrange où vous pouvez **modifier le profil docker apparmor et le recharger**, vous pouvez supprimer les restrictions et les "contourner".

### Contournement d'AppArmor Docker 2

**AppArmor est basé sur les chemins d'accès**, cela signifie que même s'il peut **protéger** les fichiers à l'intérieur d'un répertoire comme **`/proc`**, si vous pouvez **configurer la façon dont le conteneur va être exécuté**, vous pouvez **monter** le répertoire proc de l'hôte à l'intérieur de **`/host/proc`** et il **ne sera plus protégé par AppArmor**.

### Contournement d'AppArmor Shebang

Dans [**ce bogue**](https://bugs.launchpad.net/apparmor/+bug/1911431), vous pouvez voir un exemple de **comment, même si vous empêchez perl d'être exécuté avec certaines ressources**, si vous créez simplement un script shell **en spécifiant** dans la première ligne **`#!/usr/bin/perl`** et que vous **exécutez le fichier directement**, vous pourrez exécuter ce que vous voulez. Par exemple:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
