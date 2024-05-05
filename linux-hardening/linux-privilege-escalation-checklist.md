# Liste de vérification - Élévation de privilèges Linux

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des pirates expérimentés et des chasseurs de primes !

**Perspectives de piratage**\
Engagez-vous avec du contenu qui explore le frisson et les défis du piratage

**Actualités de piratage en temps réel**\
Restez informé du monde du piratage en temps réel grâce aux actualités et aux informations

**Dernières annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs pirates dès aujourd'hui !

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](privilege-escalation/#system-information)

* [ ] Obtenir des informations sur le **système d'exploitation**
* [ ] Vérifier le [**PATH**](privilege-escalation/#path), un **dossier inscriptible** ?
* [ ] Vérifier les [**variables d'environnement**](privilege-escalation/#env-info), des détails sensibles ?
* [ ] Rechercher des [**exploits du noyau**](privilege-escalation/#kernel-exploits) **en utilisant des scripts** (DirtyCow ?)
* [ ] **Vérifier** si la [**version de sudo est vulnérable**](privilege-escalation/#sudo-version)
* [ ] [**Échec de la vérification de la signature Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Plus d'énumération système ([date, statistiques système, infos CPU, imprimantes](privilege-escalation/#more-system-enumeration))
* [ ] [Énumérer plus de défenses](privilege-escalation/#enumerate-possible-defenses)

### [Disques](privilege-escalation/#drives)

* [ ] **Lister les** disques montés
* [ ] **Un disque non monté ?**
* [ ] **Des informations d'identification dans fstab ?**

### [**Logiciels installés**](privilege-escalation/#installed-software)

* [ ] **Vérifier les** [**logiciels utiles**](privilege-escalation/#useful-software) **installés**
* [ ] **Vérifier les** [**logiciels vulnérables**](privilege-escalation/#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/#processes)

* [ ] Un **logiciel inconnu est-il en cours d'exécution** ?
* [ ] Un logiciel s'exécute-t-il avec **plus de privilèges qu'il ne le devrait** ?
* [ ] Rechercher des **exploits des processus en cours d'exécution** (surtout la version en cours d'exécution).
* [ ] Pouvez-vous **modifier le binaire** de n'importe quel processus en cours d'exécution ?
* [ ] **Surveiller les processus** et vérifier si un processus intéressant s'exécute fréquemment.
* [ ] Pouvez-vous **lire** une partie de la **mémoire d'un processus** intéressant (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron jobs ?](privilege-escalation/#scheduled-jobs)

* [ ] Le [**PATH** ](privilege-escalation/#cron-path)est-il modifié par un cron et vous pouvez **écrire** dedans ?
* [ ] Un [**joker** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)dans une tâche cron ?
* [ ] Un [**script modifiable** ](privilege-escalation/#cron-script-overwriting-and-symlink)est-il **exécuté** ou se trouve-t-il dans un **dossier modifiable** ?
* [ ] Avez-vous détecté qu'un **script** pourrait être ou est **exécuté très fréquemment**](privilege-escalation/#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/#services)

* [ ] Un fichier **.service inscriptible** ?
* [ ] Un binaire inscriptible exécuté par un **service** ?
* [ ] Un dossier inscriptible dans le **PATH systemd** ?

### [Minuteries](privilege-escalation/#timers)

* [ ] Une **minuterie inscriptible** ?

### [Sockets](privilege-escalation/#sockets)

* [ ] Un fichier **.socket inscriptible** ?
* [ ] Pouvez-vous **communiquer avec un socket** ?
* [ ] **Sockets HTTP** avec des informations intéressantes ?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/#network)

* [ ] Énumérer le réseau pour savoir où vous vous trouvez
* [ ] Les ports ouverts auxquels vous n'aviez pas accès avant d'obtenir un shell à l'intérieur de la machine ?
* [ ] Pouvez-vous **capturer du trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/#users)

* [ ] Énumération des utilisateurs/groupes **génériques**
* [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
* [ ] Pouvez-vous [**élever les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
* [ ] Données du **presse-papiers** ?
* [ ] Politique de mot de passe ?
* [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur **possible**. Essayez également de vous connecter sans mot de passe.

### [Chemin inscriptible](privilege-escalation/#writable-path-abuses)

* [ ] Si vous avez des **privilèges d'écriture sur un dossier du PATH**, vous pouvez peut-être élever les privilèges

### [Commandes SUDO et SUID](privilege-escalation/#sudo-and-suid)

* [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quelque chose en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Les [**commandes sudo** sont-elles **limitées** par **le chemin** ? Pouvez-vous **contourner** les restrictions](privilege-escalation/#sudo-execution-bypassing-paths) ?
* [ ] [**Binaire Sudo/SUID sans chemin indiqué**](privilege-escalation/#sudo-command-suid-binary-without-command-path) ?
* [ ] [**Binaire SUID spécifiant un chemin**](privilege-escalation/#suid-binary-with-command-path) ? Contournement
* [ ] [**Vulnérabilité LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Absence de bibliothèque .so dans le binaire SUID**](privilege-escalation/#suid-binary-so-injection) à partir d'un dossier inscriptible ?
* [ ] [**Jetons SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens) ? [**Pouvez-vous créer un jeton SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than) ?
* [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d) ?
* [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) ?
* [**OpenBSD DOAS**](privilege-escalation/#doas) command
### [Capacités](privilege-escalation/#capabilities)

* [ ] Est-ce qu'un binaire a une **capacité inattendue**?

### [ACLs](privilege-escalation/#acls)

* [ ] Est-ce qu'un fichier a un **ACL inattendu**?

### [Sessions Shell ouvertes](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL PRNG Prévisible - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Fichiers Intéressants](privilege-escalation/#interesting-files)

* [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour l'élévation de privilèges ?
* [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour l'élévation de privilèges ?
* [ ] **Vérifier les dossiers couramment intéressants** pour des données sensibles
* [ ] **Emplacement étrange/Fichiers possédés,** auxquels vous pourriez avoir accès ou modifier des fichiers exécutables
* [ ] **Modifié** dans les dernières minutes
* [ ] **Fichiers de base de données SQLite**
* [ ] **Fichiers cachés**
* [ ] **Scripts/Binaires dans le PATH**
* [ ] **Fichiers Web** (mots de passe ?)
* [ ] **Sauvegardes** ?
* [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
* [ ] **Recherche générique**

### [**Fichiers Modifiables**](privilege-escalation/#writable-files)

* [ ] **Modifier une bibliothèque Python** pour exécuter des commandes arbitraires ?
* [ ] Pouvez-vous **modifier des fichiers journaux** ? Exploitation de **Logtotten**
* [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploitation sur Centos/Redhat
* [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Autres astuces**](privilege-escalation/#other-tricks)

* [ ] Pouvez-vous [**abuser de NFS pour escalader les privilèges**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Avez-vous besoin de [**échapper à un shell restrictif**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

**Perspectives de Hacking**\
Engagez-vous avec du contenu qui explore le frisson et les défis du hacking

**Actualités de Hacking en Temps Réel**\
Restez à jour avec le monde du hacking en évolution rapide grâce aux actualités et aux informations en temps réel

**Dernières Annonces**\
Restez informé des dernières primes de bugs lancées et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !
