# AppArmor

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **logiciels malveillants voleurs**.

Le but principal de WhiteIntel est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de logiciels malveillants volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

***

## Informations de base

AppArmor est une **amélioration du noyau conçue pour restreindre les ressources disponibles aux programmes via des profils par programme**, mettant en œuvre efficacement un contrôle d'accès obligatoire (MAC) en liant directement les attributs de contrôle d'accès aux programmes au lieu des utilisateurs. Ce système fonctionne en **chargeant des profils dans le noyau**, généralement au démarrage, et ces profils dictent quelles ressources un programme peut accéder, telles que les connexions réseau, l'accès aux sockets bruts et les autorisations de fichier.

Il existe deux modes opérationnels pour les profils AppArmor :

* **Mode d'application des règles** : Ce mode applique activement les politiques définies dans le profil, bloquant les actions qui violent ces politiques et journalisant toute tentative de les violer à travers des systèmes tels que syslog ou auditd.
* **Mode de plainte** : Contrairement au mode d'application des règles, le mode de plainte ne bloque pas les actions contraires aux politiques du profil. Au lieu de cela, il journalise ces tentatives en tant que violations de politiques sans imposer de restrictions.

### Composants d'AppArmor

* **Module noyau** : Responsable de l'application des politiques.
* **Politiques** : Spécifient les règles et restrictions pour le comportement des programmes et l'accès aux ressources.
* **Analyseur** : Charge les politiques dans le noyau pour l'application ou le signalement.
* **Utilitaires** : Ce sont des programmes en mode utilisateur qui fournissent une interface pour interagir avec et gérer AppArmor.

### Chemin des profils

Les profils AppArmor sont généralement enregistrés dans _**/etc/apparmor.d/**_\
Avec `sudo aa-status`, vous pourrez lister les binaires restreints par un profil. Si vous remplacez le caractère "/" par un point du chemin de chaque binaire répertorié, vous obtiendrez le nom du profil AppArmor à l'intérieur du dossier mentionné.

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

* Afin d'indiquer l'exécutable affecté, les **chemins absolus et les caractères génériques** sont autorisés (pour le globbing de fichiers) pour spécifier les fichiers.
* Pour indiquer l'accès que le binaire aura aux **fichiers**, les **contrôles d'accès** suivants peuvent être utilisés :
* **r** (lecture)
* **w** (écriture)
* **m** (mapping en mémoire comme exécutable)
* **k** (verrouillage de fichiers)
* **l** (création de liens physiques)
* **ix** (pour exécuter un autre programme avec le nouveau programme héritant de la politique)
* **Px** (exécuter sous un autre profil, après avoir nettoyé l'environnement)
* **Cx** (exécuter sous un profil enfant, après avoir nettoyé l'environnement)
* **Ux** (exécuter sans confinement, après avoir nettoyé l'environnement)
* Des **variables** peuvent être définies dans les profils et peuvent être manipulées depuis l'extérieur du profil. Par exemple : @{PROC} et @{HOME} (ajoutez #include \<tunables/global> au fichier de profil)
* Les **règles de refus sont prises en charge pour remplacer les règles d'autorisation**.

### aa-genprof

Pour commencer facilement à créer un profil, apparmor peut vous aider. Il est possible de faire **inspecter par apparmor les actions effectuées par un binaire, puis de vous laisser décider quelles actions vous souhaitez autoriser ou refuser**.\
Il vous suffit d'exécuter :
```bash
sudo aa-genprof /path/to/binary
```
Ensuite, dans une console différente, effectuez toutes les actions que le binaire effectuera généralement :
```bash
/path/to/binary -a dosomething
```
Ensuite, dans la première console, appuyez sur "**s**" puis dans les actions enregistrées indiquez si vous voulez ignorer, autoriser, ou autre. Lorsque vous avez terminé, appuyez sur "**f**" et le nouveau profil sera créé dans _/etc/apparmor.d/chemin.vers.binaire_

{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous voulez autoriser/refuser/autre
{% endhint %}

### aa-easyprof

Vous pouvez également créer un modèle de profil apparmor d'un binaire avec :
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
Notez qu'en créant un profil par défaut, rien n'est autorisé, donc tout est refusé. Vous devrez ajouter des lignes comme `/etc/passwd r,` pour autoriser la lecture du binaire `/etc/passwd`, par exemple.
{% endhint %}

Vous pouvez ensuite **appliquer** le nouveau profil avec
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modification d'un profil à partir des journaux

L'outil suivant lira les journaux et demandera à l'utilisateur s'il souhaite autoriser certaines des actions interdites détectées :
```bash
sudo aa-logprof
```
{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous voulez autoriser/refuser/autre
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

Exemple de journaux **AUDIT** et **DENIED** du fichier _/var/log/audit/audit.log_ de l'exécutable **`service_bin`**:
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

Notez comment le profil **docker-profile** de docker est chargé par défaut:
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
Par défaut, le profil **Apparmor docker-default** est généré à partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Résumé du profil docker-default**:

* **Accès** à tout le **réseau**
* Aucune **capacité** n'est définie (Cependant, certaines capacités proviendront de l'inclusion de règles de base de base, c'est-à-dire #include \<abstractions/base>)
* **Écriture** dans n'importe quel fichier **/proc** n'est **pas autorisée**
* Les autres **sous-répertoires**/**fichiers** de /**proc** et /**sys** se voient **refuser** l'accès en lecture/écriture/blocage/liens/exécution
* Le **montage** n'est **pas autorisé**
* **Ptrace** ne peut être exécuté que sur un processus confiné par le **même profil Apparmor**

Une fois que vous **exécutez un conteneur docker**, vous devriez voir la sortie suivante:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Notez que **apparmor bloquera même les privilèges de capacités** accordés au conteneur par défaut. Par exemple, il pourra **bloquer l'autorisation d'écrire à l'intérieur de /proc même si la capacité SYS\_ADMIN est accordée** car par défaut le profil apparmor de docker refuse cet accès:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Vous devez **désactiver apparmor** pour contourner ses restrictions :
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Notez que par défaut **AppArmor** interdit également au conteneur de monter des dossiers de l'intérieur même avec la capacité SYS_ADMIN.

Notez que vous pouvez **ajouter/supprimer** des **capacités** au conteneur Docker (cela restera toujours restreint par des méthodes de protection comme **AppArmor** et **Seccomp**):

* `--cap-add=SYS_ADMIN` donne la capacité `SYS_ADMIN`
* `--cap-add=ALL` donne toutes les capacités
* `--cap-drop=ALL --cap-add=SYS_PTRACE` supprime toutes les capacités et donne uniquement `SYS_PTRACE`

{% hint style="info" %}
Généralement, lorsque vous **constatez** que vous avez une **capacité privilégiée** disponible **à l'intérieur** d'un **conteneur Docker** mais qu'une partie de l'**exploit ne fonctionne pas**, c'est probablement parce que **AppArmor de Docker l'empêche**.
{% endhint %}

### Exemple

(Exemple provenant de [**ici**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Pour illustrer la fonctionnalité d'AppArmor, j'ai créé un nouveau profil Docker "mydocker" avec la ligne suivante ajoutée :
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Pour activer le profil, nous devons faire ce qui suit :
```
sudo apparmor_parser -r -W mydocker
```
Pour lister les profils, nous pouvons exécuter la commande suivante. La commande ci-dessous liste mon nouveau profil AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Comme indiqué ci-dessous, une erreur se produit lors de la tentative de modification de "/etc/" car le profil AppArmor empêche l'accès en écriture à "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Contournement d'AppArmor Docker1

Vous pouvez trouver quel **profil apparmor exécute un conteneur** en utilisant :
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Ensuite, vous pouvez exécuter la ligne suivante pour **trouver le profil exact utilisé** :
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### Contournement d'AppArmor Docker

**AppArmor est basé sur les chemins**, cela signifie que même s'il pourrait **protéger** les fichiers à l'intérieur d'un répertoire comme **`/proc`**, si vous pouvez **configurer comment le conteneur va être exécuté**, vous pourriez **monter** le répertoire proc de l'hôte à l'intérieur de **`/host/proc`** et il **ne sera plus protégé par AppArmor**.

### Contournement de Shebang AppArmor

Dans [**ce bogue**](https://bugs.launchpad.net/apparmor/+bug/1911431), vous pouvez voir un exemple de comment **même si vous empêchez perl d'être exécuté avec certaines ressources**, si vous créez simplement un script shell **spécifiant** dans la première ligne **`#!/usr/bin/perl`** et que vous **exécutez le fichier directement**, vous pourrez exécuter ce que vous voulez. Par exemple:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **malwares voleurs**.

Leur objectif principal est de lutter contre les prises de contrôle de compte et les attaques de ransomware résultant de malwares volant des informations.

Vous pouvez consulter leur site Web et essayer leur moteur **gratuitement** sur :

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
