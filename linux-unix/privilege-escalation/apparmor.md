```markdown
<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Informations de base

**AppArmor** est une amélioration du noyau pour confiner les **programmes** à un ensemble **limité** de **ressources** avec des **profils par programme**. Les profils peuvent **autoriser** des **capacités** comme l'accès au réseau, l'accès aux sockets bruts et la permission de lire, écrire ou exécuter des fichiers sur des chemins correspondants.

C'est un Contrôle d'Accès Obligatoire ou **MAC** qui lie les attributs de **contrôle d'accès** **aux programmes plutôt qu'aux utilisateurs**.\
La confinement AppArmor est fourni via des **profils chargés dans le noyau**, généralement au démarrage.\
Les profils AppArmor peuvent être dans l'un des **deux modes** :

* **Enforcement** : Les profils chargés en mode enforcement entraîneront l'**application de la politique** définie dans le profil **ainsi que le signalement** des tentatives de violation de la politique (soit via syslog ou auditd).
* **Complain** : Les profils en mode complain **n'appliqueront pas la politique** mais **signaleront** les tentatives de **violation** de la politique.

AppArmor se distingue de certains autres systèmes MAC sur Linux : il est **basé sur les chemins**, il permet de mélanger les profils en mode enforcement et complain, il utilise des fichiers d'inclusion pour faciliter le développement, et il a une barrière d'entrée beaucoup plus basse que d'autres systèmes MAC populaires.

## Composants d'AppArmor

* **Module du noyau** : Effectue le travail réel
* **Politiques** : Définit le comportement et le confinement
* **Analyseur** : Charge les politiques dans le noyau
* **Utilitaires** : Programmes en mode utilisateur pour interagir avec apparmor

## Chemin des profils

Les profils Apparmor sont généralement sauvegardés dans _**/etc/apparmor.d/**_\
Avec `sudo aa-status`, vous pourrez lister les binaires qui sont restreints par un profil. Si vous pouvez changer le caractère "/" par un point du chemin de chaque binaire listé, vous obtiendrez le nom du profil apparmor dans le dossier mentionné.

Par exemple, un profil **apparmor** pour _/usr/bin/man_ sera situé dans _/etc/apparmor.d/usr.bin.man_

## Commandes
```
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
# Création d'un profil

* Afin d'indiquer l'exécutable affecté, les **chemins absolus et les caractères jokers** sont autorisés (pour la recherche de fichiers) pour spécifier les fichiers.
* Pour indiquer l'accès que le binaire aura sur les **fichiers**, les **contrôles d'accès** suivants peuvent être utilisés :
* **r** (lecture)
* **w** (écriture)
* **m** (cartographie mémoire comme exécutable)
* **k** (verrouillage de fichier)
* **l** (création de liens physiques)
* **ix** (pour exécuter un autre programme avec la nouvelle politique héritée)
* **Px** (exécuter sous un autre profil, après nettoyage de l'environnement)
* **Cx** (exécuter sous un profil enfant, après nettoyage de l'environnement)
* **Ux** (exécuter sans contrainte, après nettoyage de l'environnement)
* Les **variables** peuvent être définies dans les profils et peuvent être manipulées de l'extérieur du profil. Par exemple : @{PROC} et @{HOME} (ajouter #include \<tunables/global> au fichier de profil)
* **Les règles de refus sont prises en charge pour remplacer les règles d'autorisation**.

## aa-genprof

Pour commencer facilement à créer un profil, apparmor peut vous aider. Il est possible de faire en sorte qu'**apparmor inspecte les actions effectuées par un binaire puis vous laisse décider quelles actions vous souhaitez autoriser ou refuser**.\
Il suffit d'exécuter :
```bash
sudo aa-genprof /path/to/binary
```
Ensuite, dans une console différente, effectuez toutes les actions que le binaire effectuerait habituellement :
```bash
/path/to/binary -a dosomething
```
Ensuite, dans la première console, appuyez sur "**s**" puis dans les actions enregistrées indiquez si vous souhaitez ignorer, autoriser, ou autre. Lorsque vous avez terminé, appuyez sur "**f**" et le nouveau profil sera créé dans _/etc/apparmor.d/chemin.vers.le.binaire_

{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous souhaitez autoriser/refuser/autre
{% endhint %}

## aa-easyprof

Vous pouvez également créer un modèle de profil apparmor pour un binaire avec :
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
Notez que par défaut dans un profil créé, rien n'est autorisé, donc tout est refusé. Vous devrez ajouter des lignes comme `/etc/passwd r,` pour permettre au binaire de lire `/etc/passwd` par exemple.
{% endhint %}

Vous pouvez ensuite **appliquer** le nouveau profil avec
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## Modification d'un profil à partir des journaux

L'outil suivant lira les journaux et demandera à l'utilisateur s'il souhaite autoriser certaines des actions interdites détectées :
```bash
sudo aa-logprof
```
{% hint style="info" %}
En utilisant les touches fléchées, vous pouvez sélectionner ce que vous souhaitez autoriser/refuser/autre
{% endhint %}

## Gestion d'un profil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# Journaux

Exemple de journaux **AUDIT** et **DENIED** provenant de _/var/log/audit/audit.log_ de l'exécutable **`service_bin`** :
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
# Apparmor dans Docker

Notez comment le profil **docker-profile** de docker est chargé par défaut :
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
Par défaut, le **profil Apparmor docker-default** est généré à partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Résumé du profil docker-default** :

* **Accès** à tout le **réseau**
* **Aucune capacité** n'est définie (Cependant, certaines capacités proviendront de l'inclusion de règles de base de base, par ex. #include \<abstractions/base>)
* **L'écriture** dans un fichier **/proc** n'est **pas autorisée**
* D'autres **sous-répertoires**/**fichiers** de /**proc** et /**sys** se voient **refuser** l'accès en lecture/écriture/verrouillage/lien/exécution
* **Le montage** n'est **pas autorisé**
* **Ptrace** ne peut être exécuté que sur un processus confiné par le **même profil apparmor**

Une fois que vous **exécutez un conteneur docker**, vous devriez voir la sortie suivante :
```bash
1 processes are in enforce mode.
docker-default (825)
```
Notez que **apparmor bloquera même les privilèges de capacités** accordés au conteneur par défaut. Par exemple, il pourra **bloquer la permission d'écrire dans /proc même si la capacité SYS_ADMIN est accordée** car par défaut le profil apparmor de docker refuse cet accès :
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Vous devez **désactiver apparmor** pour contourner ses restrictions :
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Notez que par défaut, **AppArmor** interdira également **au conteneur de monter** des dossiers de l'intérieur même avec la capacité SYS_ADMIN.

Notez que vous pouvez **ajouter/supprimer** des **capacités** au conteneur docker (cela sera toujours restreint par des méthodes de protection comme **AppArmor** et **Seccomp**):

* `--cap-add=SYS_ADMIN` _donne_ la cap `SYS_ADMIN`
* `--cap-add=ALL` _donne_ toutes les caps
* `--cap-drop=ALL --cap-add=SYS_PTRACE` supprime toutes les caps et ne donne que `SYS_PTRACE`

{% hint style="info" %}
Habituellement, lorsque vous **découvrez** que vous avez une **capacité privilégiée** disponible **à l'intérieur** d'un conteneur **docker** mais qu'une partie de l'**exploit ne fonctionne pas**, cela sera parce que l'**apparmor de docker l'empêchera**.
{% endhint %}

## Évasion AppArmor Docker

Vous pouvez trouver quel **profil apparmor est utilisé par un conteneur** en utilisant :
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Ensuite, vous pouvez exécuter la ligne suivante pour **trouver le profil exact utilisé** :
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Dans le cas étrange où vous pouvez **modifier le profil docker apparmor et le recharger.** Vous pourriez supprimer les restrictions et les "contourner".

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
