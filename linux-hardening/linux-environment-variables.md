# Variables d'environnement Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Variables globales

Les variables globales **seront** héritées par les **processus enfants**.

Vous pouvez créer une variable globale pour votre session actuelle en faisant :
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Cette variable sera accessible par vos sessions actuelles et ses processus enfants.

Vous pouvez **supprimer** une variable en faisant :
```bash
unset MYGLOBAL
```
## Variables locaux

Les **variables locales** ne peuvent être **accédées** que par le **shell/script courant**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Liste des variables actuelles
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables d'environnement persistantes

#### **Fichiers qui affectent le comportement de chaque utilisateur :**

* _**/etc/bash.bashrc**_ : Ce fichier est lu chaque fois qu'un shell interactif est démarré (terminal normal) et toutes les commandes spécifiées ici sont exécutées.
* _**/etc/profile et /etc/profile.d/\***_**:** Ce fichier est lu chaque fois qu'un utilisateur se connecte. Ainsi, toutes les commandes exécutées ici ne seront exécutées qu'une seule fois au moment de la connexion de l'utilisateur.
  *   \*\*Exemple : \*\*

      `/etc/profile.d/somescript.sh`

      ```bash
      #!/bin/bash
      TEST=$(cat /var/somefile)
      export $TEST
      ```

#### **Fichiers qui affectent le comportement d'un utilisateur spécifique :**

* _**\~/.bashrc**_ : Ce fichier fonctionne de la même manière que le fichier _/etc/bash.bashrc_, mais il est exécuté uniquement pour un utilisateur spécifique. Si vous voulez créer un environnement pour vous-même, modifiez ou créez ce fichier dans votre répertoire personnel.
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**:** Ces fichiers sont identiques à _/etc/profile_. La différence réside dans la manière dont il est exécuté. Ce fichier est exécuté uniquement lorsqu'un utilisateur dans le répertoire personnel duquel ce fichier existe se connecte.

**Extrait de :** [**ici**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **et** [**ici**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## Variables courantes

De : [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – l'affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l'ordinateur actuel.
* **EDITOR** – l'éditeur de texte préféré de l'utilisateur.
* **HISTFILESIZE** – le nombre maximum de lignes contenues dans le fichier d'historique.
* \*\*HISTSIZE - \*\*Nombre de lignes ajoutées au fichier d'historique lorsque l'utilisateur termine sa session.
* **HOME** – votre répertoire personnel.
* **HOSTNAME** – le nom d'hôte de l'ordinateur.
* **LANG** – votre langue actuelle.
* **MAIL** – l'emplacement du spool de courrier de l'utilisateur. Généralement **/var/spool/mail/USER**.
* **MANPATH** – la liste des répertoires à rechercher pour les pages de manuel.
* **OSTYPE** – le type de système d'exploitation.
* **PS1** – l'invite par défaut dans bash.
* \*\*PATH - \*\*stocke le chemin de tous les répertoires qui contiennent des fichiers binaires que vous souhaitez exécuter simplement en spécifiant le nom du fichier et non le chemin relatif ou absolu.
* **PWD** – le répertoire de travail actuel.
* **SHELL** – le chemin vers le shell de commande actuel (par exemple, **/bin/bash**).
* **TERM** – le type de terminal actuel (par exemple, **xterm**).
* **TZ** – votre fuseau horaire.
* **USER** – votre nom d'utilisateur actuel.

## Variables intéressantes pour le piratage

### **HISTFILESIZE**

Modifiez la **valeur de cette variable à 0**, de sorte que lorsque vous **terminez votre session**, le **fichier d'historique** (\~/.bash\_history) **sera supprimé**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Changez la **valeur de cette variable à 0**, ainsi lorsque vous **terminez votre session**, toute commande ne sera pas ajoutée au **fichier d'historique** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à Internet via **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d'environnement**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Modifiez l'apparence de votre invite de commande.

J'ai créé [**celle-ci**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808) (basée sur une autre, lisez le code).

Root:

![](<../.gitbook/assets/image (87).png>)

Utilisateur régulier:

![](<../.gitbook/assets/image (88).png>)

Un, deux et trois travaux en arrière-plan:

![](<../.gitbook/assets/image (89).png>)

Un travail en arrière-plan, un arrêté et la dernière commande n'a pas fini correctement:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
