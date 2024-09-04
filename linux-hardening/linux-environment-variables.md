# Variables d'environnement Linux

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

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
## Variables locales

Les **variables locales** ne peuvent être **accessées** que par le **shell/script actuel**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lister les variables actuelles
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables courantes

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – l'affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l'ordinateur actuel.
* **EDITOR** – l'éditeur de texte préféré de l'utilisateur.
* **HISTFILESIZE** – le nombre maximum de lignes contenues dans le fichier d'historique.
* **HISTSIZE** – Nombre de lignes ajoutées au fichier d'historique lorsque l'utilisateur termine sa session.
* **HOME** – votre répertoire personnel.
* **HOSTNAME** – le nom d'hôte de l'ordinateur.
* **LANG** – votre langue actuelle.
* **MAIL** – l'emplacement de la spool de mail de l'utilisateur. Généralement **/var/spool/mail/USER**.
* **MANPATH** – la liste des répertoires à rechercher pour les pages de manuel.
* **OSTYPE** – le type de système d'exploitation.
* **PS1** – l'invite par défaut dans bash.
* **PATH** – stocke le chemin de tous les répertoires contenant des fichiers binaires que vous souhaitez exécuter simplement en spécifiant le nom du fichier et non par un chemin relatif ou absolu.
* **PWD** – le répertoire de travail actuel.
* **SHELL** – le chemin vers le shell de commande actuel (par exemple, **/bin/bash**).
* **TERM** – le type de terminal actuel (par exemple, **xterm**).
* **TZ** – votre fuseau horaire.
* **USER** – votre nom d'utilisateur actuel.

## Variables intéressantes pour le hacking

### **HISTFILESIZE**

Changez la **valeur de cette variable à 0**, afin que lorsque vous **mettez fin à votre session**, le **fichier d'historique** (\~/.bash\_history) **soit supprimé**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Changez la **valeur de cette variable à 0**, afin que lorsque vous **mettez fin à votre session**, aucune commande ne soit ajoutée au **fichier d'historique** (\~/.bash\_history).
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

Changez l'apparence de votre invite.

[**Ceci est un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Utilisateur régulier:

![](<../.gitbook/assets/image (740).png>)

Un, deux et trois travaux en arrière-plan:

![](<../.gitbook/assets/image (145).png>)

Un travail en arrière-plan, un arrêté et la dernière commande ne s'est pas terminée correctement:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Apprenez et pratiquez le hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
