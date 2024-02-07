<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


## Logstash

Logstash est utilisé pour **rassembler, transformer et envoyer des journaux** à travers un système appelé **pipelines**. Ces pipelines sont composés d'étapes **d'entrée**, de **filtre** et de **sortie**. Un aspect intéressant se présente lorsque Logstash fonctionne sur une machine compromise.

### Configuration du pipeline

Les pipelines sont configurés dans le fichier **/etc/logstash/pipelines.yml**, qui répertorie les emplacements des configurations de pipeline :
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Ce fichier révèle où se trouvent les fichiers **.conf**, contenant les configurations de pipeline. Lors de l'utilisation d'un **module de sortie Elasticsearch**, il est courant que les **pipelines** incluent des **informations d'identification Elasticsearch**, qui possèdent souvent des privilèges étendus en raison du besoin de Logstash d'écrire des données dans Elasticsearch. Les jokers dans les chemins de configuration permettent à Logstash d'exécuter tous les pipelines correspondants dans le répertoire désigné.

### Élévation de privilèges via les pipelines inscriptibles

Pour tenter une élévation de privilèges, identifiez d'abord l'utilisateur sous lequel le service Logstash est en cours d'exécution, généralement l'utilisateur **logstash**. Assurez-vous de remplir **l'un** de ces critères :

- Posséder un **accès en écriture** à un fichier **.conf** de pipeline **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un joker, et vous pouvez écrire dans le dossier cible

De plus, **l'une** de ces conditions doit être remplie :

- Capacité à redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** a **config.reload.automatic: true** défini

Étant donné un joker dans la configuration, la création d'un fichier correspondant à ce joker permet l'exécution de commandes. Par exemple :
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Voici, **interval** détermine la fréquence d'exécution en secondes. Dans l'exemple donné, la commande **whoami** s'exécute toutes les 120 secondes, avec sa sortie dirigée vers **/tmp/output.log**.

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détectera et appliquera automatiquement les nouvelles configurations de pipeline modifiées sans nécessiter de redémarrage. En l'absence de joker, des modifications peuvent toujours être apportées aux configurations existantes, mais il est conseillé de faire preuve de prudence pour éviter les perturbations.


# Références

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
