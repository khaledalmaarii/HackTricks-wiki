# Variables d'environnement Linux

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

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

Les **variables locales** ne peuvent être **accédées** que par le **shell/script actuel**.
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

#### **Fichiers qui affectent le comportement de chaque utilisateur:**

* _**/etc/bash.bashrc**_: Ce fichier est lu chaque fois qu'un shell interactif est démarré (terminal normal) et toutes les commandes spécifiées ici sont exécutées.
* _**/etc/profile et /etc/profile.d/\***_**:** Ce fichier est lu à chaque fois qu'un utilisateur se connecte. Ainsi, toutes les commandes exécutées ici ne seront exécutées qu'une seule fois au moment de la connexion de l'utilisateur.
*   \*\*Exemple: \*\*

`/etc/profile.d/somescript.sh`

```bash
#!/bin/bash
TEST=$(cat /var/somefile)
export $TEST
```

## Variables communes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – l'affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l'ordinateur actuel.
* **EDITOR** – l'éditeur de texte préféré de l'utilisateur.
* **HISTFILESIZE** – le nombre maximum de lignes contenues dans le fichier d'historique.
* **HISTSIZE** – Nombre de lignes ajoutées au fichier d'historique lorsque l'utilisateur termine sa session.
* **HOME** – votre répertoire personnel.
* **HOSTNAME** – le nom d'hôte de l'ordinateur.
* **LANG** – votre langue actuelle.
* **MAIL** – l'emplacement du répertoire de messagerie de l'utilisateur. Généralement **/var/spool/mail/USER**.
* **MANPATH** – la liste des répertoires à rechercher pour les pages de manuel.
* **OSTYPE** – le type de système d'exploitation.
* **PS1** – l'invite par défaut dans bash.
* **PATH** – stocke le chemin de tous les répertoires contenant des fichiers binaires que vous souhaitez exécuter en spécifiant simplement le nom du fichier et non le chemin relatif ou absolu.
* **PWD** – le répertoire de travail actuel.
* **SHELL** – le chemin de l'interpréteur de commandes actuel (par exemple, **/bin/bash**).
* **TERM** – le type de terminal actuel (par exemple, **xterm**).
* **TZ** – votre fuseau horaire.
* **USER** – votre nom d'utilisateur actuel.

## Variables intéressantes pour le piratage

### **HISTFILESIZE**

Changez la **valeur de cette variable à 0**, ainsi lorsque vous **terminez votre session**, le **fichier d'historique** (\~/.bash\_history) **sera supprimé**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Changez la **valeur de cette variable à 0**, ainsi lorsque vous **terminez votre session** aucun commande ne sera ajoutée au **fichier d'historique** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à Internet via **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d'environnement**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Modifiez l'apparence de votre invite de commande.

[**Ceci est un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Utilisateur régulier:

![](<../.gitbook/assets/image (88).png>)

Un, deux et trois emplois en arrière-plan:

![](<../.gitbook/assets/image (89).png>)

Un travail en arrière-plan, un arrêté et la dernière commande n'a pas fini correctement:

![](<../.gitbook/assets/image (90).png>)
