# Checklist - Élévation de privilèges Linux

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de primes de bugs !

**Aperçus du piratage**\
Engagez-vous avec du contenu qui plonge dans l'excitation et les défis du piratage

**Nouvelles du piratage en temps réel**\
Restez à jour avec le monde du piratage rapide grâce à des nouvelles et des aperçus en temps réel

**Dernières annonces**\
Restez informé avec le lancement des dernières primes de bugs et les mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations Système](privilege-escalation/#system-information)

* [ ] Obtenez des **informations sur l'OS**
* [ ] Vérifiez le [**PATH**](privilege-escalation/#path), un **dossier accessible en écriture** ?
* [ ] Vérifiez les [**variables d'environnement**](privilege-escalation/#env-info), un détail sensible ?
* [ ] Recherchez des [**exploits de kernel**](privilege-escalation/#kernel-exploits) **à l'aide de scripts** (DirtyCow ?)
* [ ] **Vérifiez** si la [**version de sudo** est vulnérable](privilege-escalation/#sudo-version)
* [ ] [**Échec de la vérification de signature Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Plus d'énumération système ([date, statistiques système, infos CPU, imprimantes](privilege-escalation/#more-system-enumeration))
* [ ] [Énumérez plus de défenses](privilege-escalation/#enumerate-possible-defenses)

### [Lecteurs](privilege-escalation/#drives)

* [ ] **Listez les lecteurs montés**
* [ ] **Un lecteur non monté ?**
* [ ] **Des identifiants dans fstab ?**

### [**Logiciels Installés**](privilege-escalation/#installed-software)

* [ ] **Vérifiez la présence de** [**logiciels utiles**](privilege-escalation/#useful-software) **installés**
* [ ] **Vérifiez la présence de** [**logiciels vulnérables**](privilege-escalation/#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/#processes)

* [ ] Y a-t-il un **logiciel inconnu en cours d'exécution** ?
* [ ] Un logiciel est-il en cours d'exécution avec **plus de privilèges qu'il ne devrait** ?
* [ ] Recherchez des **exploits de processus en cours** (surtout la version en cours d'exécution).
* [ ] Pouvez-vous **modifier le binaire** d'un processus en cours ?
* [ ] **Surveillez les processus** et vérifiez si un processus intéressant s'exécute fréquemment.
* [ ] Pouvez-vous **lire** la mémoire d'un processus intéressant (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](privilege-escalation/#scheduled-jobs)

* [ ] Le [**PATH**](privilege-escalation/#cron-path) est-il modifié par un cron et pouvez-vous **écrire** dedans ?
* [ ] Un [**joker**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) dans une tâche cron ?
* [ ] Un [**script modifiable**](privilege-escalation/#cron-script-overwriting-and-symlink) est-il **exécuté** ou se trouve-t-il dans un **dossier modifiable** ?
* [ ] Avez-vous détecté qu'un **script** pourrait être ou est [**exécuté très fréquemment**](privilege-escalation/#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/#services)

* [ ] Un fichier **.service accessible en écriture** ?
* [ ] Un **binaire accessible en écriture** exécuté par un **service** ?
* [ ] Un **dossier accessible en écriture dans le PATH de systemd** ?

### [Minuteries](privilege-escalation/#timers)

* [ ] Une **minuterie accessible en écriture** ?

### [Sockets](privilege-escalation/#sockets)

* [ ] Un fichier **.socket accessible en écriture** ?
* [ ] Pouvez-vous **communiquer avec un socket** ?
* [ ] **Sockets HTTP** avec des infos intéressantes ?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/#network)

* [ ] Énumérez le réseau pour savoir où vous êtes
* [ ] **Ports ouverts auxquels vous ne pouviez pas accéder avant** d'avoir un shell dans la machine ?
* [ ] Pouvez-vous **sniffer le trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/#users)

* [ ] Énumération générique des utilisateurs/groupes
* [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
* [ ] Pouvez-vous [**escalader les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
* [ ] **Données du presse-papiers** ?
* [ ] Politique de mot de passe ?
* [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur possible. Essayez également de vous connecter sans mot de passe.

### [PATH accessible en écriture](privilege-escalation/#writable-path-abuses)

* [ ] Si vous avez des **privilèges d'écriture sur un dossier dans PATH**, vous pourriez être en mesure d'escalader les privilèges

### [Commandes SUDO et SUID](privilege-escalation/#sudo-and-suid)

* [ ] Pouvez-vous exécuter **une commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Les commandes [**sudo** sont-elles **limitées** par le **chemin** ? pouvez-vous **contourner** les restrictions](privilege-escalation/#sudo-execution-bypassing-paths) ?
* [ ] [**Binaire Sudo/SUID sans chemin indiqué**](privilege-escalation/#sudo-command-suid-binary-without-command-path) ?
* [ ] [**Binaire SUID spécifiant un chemin**](privilege-escalation/#suid-binary-with-command-path) ? Contournement
* [ ] [**Vulnérabilité LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Manque de bibliothèque .so dans un binaire SUID**](privilege-escalation/#suid-binary-so-injection) à partir d'un dossier accessible en écriture ?
* [ ] [**Jetons SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens) ? [**Pouvez-vous créer un jeton SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than) ?
* [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d) ?
* [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) ?
* [ ] [**Commande OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacités](privilege-escalation/#capabilities)

* [ ] Un binaire a-t-il une **capacité inattendue** ?

### [ACL](privilege-escalation/#acls)

* [ ] Un fichier a-t-il une **ACL inattendue** ?

### [Sessions Shell ouvertes](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**PRNG OpenSSL Prévisible - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Fichiers Intéressants](privilege-escalation/#interesting-files)

* [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour privesc ?
* [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour privesc ?
* [ ] **Vérifiez les dossiers couramment intéressants** pour des données sensibles
* [ ] **Fichiers avec un emplacement/propriétaire étrange,** vous pourriez avoir accès à ou modifier des fichiers exécutables
* [ ] **Modifiés** dans les dernières minutes
* [ ] **Fichiers de base de données SQLite**
* [ ] **Fichiers cachés**
* [ ] **Scripts/Binaires dans PATH**
* [ ] **Fichiers Web** (mots de passe ?)
* [ ] **Sauvegardes** ?
* [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
* [ ] **Recherche générique**

### [**Fichiers modifiables**](privilege-escalation/#writable-files)

* [ ] **Modifier la bibliothèque python** pour exécuter des commandes arbitraires ?
* [ ] Pouvez-vous **modifier les fichiers journaux** ? Exploit **Logtotten**
* [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
* [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](privilege-escalation/#other-tricks)

* [ ] Pouvez-vous [**abuser de NFS pour escalader les privilèges**](privilege-escalation/#nfs-privilege-escalation) ?
* [ ] Avez-vous besoin de [**vous échapper d'un shell restrictif**](privilege-escalation/#escaping-from-restricted-shells) ?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de primes de bugs !

**Aperçus du piratage**\
Engagez-vous avec du contenu qui plonge dans l'excitation et les défis du piratage

**Nouvelles du piratage en temps réel**\
Restez à jour avec le monde du piratage rapide grâce à des nouvelles et des aperçus en temps réel

**Dernières annonces**\
Restez informé avec le lancement des dernières primes de bugs et les mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
