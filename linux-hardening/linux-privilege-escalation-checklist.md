# Liste de vérification - Élévation de privilèges Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).​

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bug.

**Acquérez de l'expérience en pentest web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 dès ses débuts.

**Devenez la légende du pirate web3**\
Gagnez des points de réputation avec chaque bug vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos piratages !

{% embed url="https://hackenproof.com/register" %}

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](privilege-escalation/#system-information)

* [ ] Obtenez les **informations sur le système d'exploitation**
* [ ] Vérifiez le [**PATH**](privilege-escalation/#path), un **dossier inscriptible** ?
* [ ] Vérifiez les [**variables d'environnement**](privilege-escalation/#env-info), des détails sensibles ?
* [ ] Recherchez des [**exploits du noyau**](privilege-escalation/#kernel-exploits) **en utilisant des scripts** (DirtyCow ?)
* [ ] **Vérifiez** si la [**version de sudo est vulnérable**](privilege-escalation/#sudo-version)
* [ ] [**Échec de la vérification de la signature Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Plus d'énumération du système ([date, statistiques du système, informations sur le processeur, imprimantes](privilege-escalation/#more-system-enumeration))
* [ ] [Énumérez davantage de défenses](privilege-escalation/#enumerate-possible-defenses)

### [Disques](privilege-escalation/#drives)

* [ ] **Listez les** disques montés
* [ ] **Un disque non monté ?**
* [ ] **Des informations d'identification dans fstab ?**

### [**Logiciels installés**](privilege-escalation/#installed-software)

* [ ] **Vérifiez les** [**logiciels utiles**](privilege-escalation/#useful-software) **installés**
* [ ] **Vérifiez les** [**logiciels vulnérables**](privilege-escalation/#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/#processes)

* [ ] Un **logiciel inconnu est-il en cours d'exécution** ?
* [ ] Un logiciel s'exécute-t-il avec **plus de privilèges qu'il ne devrait en avoir** ?
* [ ] Recherchez des **exploits des processus en cours d'exécution** (en particulier la version en cours d'exécution).
* [ ] Pouvez-vous **modifier le binaire** de n'importe quel processus en cours d'exécution ?
* [ ] **Surveillez les processus** et vérifiez si un processus intéressant s'exécute fréquemment.
* [ ] Pouvez-vous **lire** la **mémoire de certains processus** intéressants (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](privilege-escalation/#scheduled-jobs)

* [ ] Le [**PATH** ](privilege-escalation/#cron-path)est-il modifié par un cron et pouvez-vous **écrire** dedans ?
* [ ] Un [**joker** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)dans une tâche cron ?
* [ ] Un [**script modifiable** ](privilege-escalation/#cron-script-overwriting-and-symlink)est-il **exécuté** ou se trouve-t-il dans un **dossier modifiable** ?
* [ ] Avez-vous détecté qu'un **script** pourrait être ou est **exécuté très fréquemment**](privilege-escalation/#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/#services)

* [ ] Un fichier **.service inscriptible** ?
* [ ] Un **binaire inscriptible** exécuté par un **service** ?
* [ ] Un **dossier inscriptible dans le PATH de systemd** ?
### [Minuteries](privilege-escalation/#timers)

* [ ] Y a-t-il une **minuterie modifiable** ?

### [Sockets](privilege-escalation/#sockets)

* [ ] Y a-t-il un fichier **.socket modifiable** ?
* [ ] Pouvez-vous **communiquer avec un socket** ?
* [ ] Des sockets **HTTP** contenant des informations intéressantes ?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/#network)

* [ ] Énumérez le réseau pour savoir où vous vous trouvez
* [ ] Des ports **ouverts auxquels vous n'aviez pas accès** avant d'obtenir un shell sur la machine ?
* [ ] Pouvez-vous **capturer le trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/#users)

* [ ] Énumération des utilisateurs/groupes **génériques**
* [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
* [ ] Pouvez-vous [**escalader les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
* [ ] Données du **presse-papiers** ?
* [ ] Politique de mot de passe ?
* [ ] Essayez d'**utiliser** tous les **mots de passe connus** que vous avez découverts précédemment pour vous connecter **avec chaque** utilisateur **possible**. Essayez également de vous connecter sans mot de passe.

### [Chemin d'accès modifiable](privilege-escalation/#writable-path-abuses)

* [ ] Si vous avez des **privileges d'écriture sur un dossier dans le PATH**, vous pouvez peut-être escalader les privilèges

### [Commandes SUDO et SUID](privilege-escalation/#sudo-and-suid)

* [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Les [**commandes sudo** sont-elles **limitées** par **le chemin d'accès** ? Pouvez-vous **contourner** les restrictions](privilege-escalation/#sudo-execution-bypassing-paths) ?
* [ ] [**Binaire Sudo/SUID sans chemin indiqué**](privilege-escalation/#sudo-command-suid-binary-without-command-path) ?
* [ ] [**Binaire SUID avec chemin spécifié**](privilege-escalation/#suid-binary-with-command-path) ? Contournement
* [ ] [**Vulnérabilité LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Absence de bibliothèque .so dans le binaire SUID**](privilege-escalation/#suid-binary-so-injection) à partir d'un dossier modifiable ?
* [ ] [**Jetons SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens) ? [**Pouvez-vous créer un jeton SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than) ?
* [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d) ?
* [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) ?
* [ ] [**Commande OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacités](privilege-escalation/#capabilities)

* [ ] Est-ce que n'importe quel binaire a une **capacité inattendue** ?

### [ACLs](privilege-escalation/#acls)

* [ ] Est-ce que n'importe quel fichier a une **ACL inattendue** ?

### [Sessions shell ouvertes](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Fichiers intéressants](privilege-escalation/#interesting-files)

* [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour l'élévation des privilèges ?
* [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour l'élévation des privilèges ?
* [ ] Vérifiez les **dossiers couramment intéressants** pour les données sensibles
* [ ] **Emplacement étrange/Fichiers appartenant**, vous pouvez avoir accès ou modifier des fichiers exécutables
* [ ] **Modifié** dans les dernières minutes
* [ ] **Fichiers de base de données SQLite**
* [ ] **Fichiers cachés**
* [ ] **Scripts/Binaires dans le PATH**
* [ ] **Fichiers Web** (mots de passe ?)
* [ ] **Sauvegardes** ?
* [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
* [ ] **Recherche générique**

### [Fichiers modifiables](privilege-escalation/#writable-files)

* [ ] **Modifier une bibliothèque Python** pour exécuter des commandes arbitraires ?
* [ ] Pouvez-vous **modifier les fichiers journaux** ? Exploitation de **Logtotten**
* [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploitation de Centos/Redhat
* [ ] Pouvez-vous [**écrire dans les fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](privilege-escalation/#other-tricks)

* [ ] Pouvez-vous **abuser de NFS pour escalader les privilèges**](privilege-escalation/#nfs-privilege-escalation) ?
* [ ] Avez-vous besoin de **vous échapper d'un shell restrictif**](privilege-escalation/#escaping-from-restricted-shells) ?

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof est la plateforme des primes de bugs cryptographiques.**

**Obtenez des récompenses sans délai**\
Les primes HackenProof sont lancées uniquement lorsque les clients déposent le budget de récompense. Vous recevrez la récompense après la vérification du bogue.

**Acquérez de l'expérience en pentesting web3**\
Les protocoles blockchain et les contrats intelligents sont le nouvel Internet ! Maîtrisez la sécurité web3 à ses débuts.

**Devenez la légende des hackers web3**\
Gagnez des points de réputation avec chaque bogue vérifié et conquérez le sommet du classement hebdomadaire.

[**Inscrivez-vous sur HackenProof**](https://hackenproof.com/register) et commencez à gagner grâce à vos hacks !

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PRs au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
