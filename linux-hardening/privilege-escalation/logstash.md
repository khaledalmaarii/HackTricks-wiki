<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Informations de base

Logstash est utilisé pour collecter, transformer et sortir les logs. Cela est réalisé en utilisant des **pipelines**, qui contiennent des modules d'entrée, de filtre et de sortie. Le service devient intéressant lorsqu'on a compromis une machine qui exécute Logstash en tant que service.

## Pipelines

Le fichier de configuration de pipeline **/etc/logstash/pipelines.yml** spécifie les emplacements des pipelines actifs :
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Dans cette section, vous trouverez les chemins vers les fichiers **.conf**, qui contiennent les pipelines configurés. Si le **module de sortie Elasticsearch** est utilisé, les **pipelines** sont susceptibles de **contenir** des **identifiants** valides pour une instance Elasticsearch. Ces identifiants ont souvent plus de privilèges, car Logstash doit écrire des données dans Elasticsearch. Si des caractères génériques sont utilisés, Logstash essaie d'exécuter tous les pipelines situés dans ce dossier correspondant au caractère générique.

## Élévation de privilèges avec des pipelines modifiables

Avant d'essayer d'élever vos propres privilèges, vous devriez vérifier quel utilisateur exécute le service logstash, car ce sera l'utilisateur que vous posséderez par la suite. Par défaut, le service logstash s'exécute avec les privilèges de l'utilisateur **logstash**.

Vérifiez si vous avez **l'un** des droits requis :

* Vous avez des **droits d'écriture** sur un fichier de pipeline **.conf** **ou**
* **/etc/logstash/pipelines.yml** contient un caractère générique et vous êtes autorisé à écrire dans le dossier spécifié

De plus, **l'une** des conditions suivantes doit être remplie :

* Vous êtes capable de redémarrer le service logstash **ou**
* **/etc/logstash/logstash.yml** contient l'entrée **config.reload.automatic: true**

Si un caractère générique est spécifié, essayez de créer un fichier correspondant à ce caractère générique. Le contenu suivant peut être écrit dans le fichier pour exécuter des commandes :
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
L'**interval** spécifie le temps en secondes. Dans cet exemple, la commande **whoami** est exécutée toutes les 120 secondes. La sortie de la commande est enregistrée dans **/tmp/output.log**.

Si **/etc/logstash/logstash.yml** contient l'entrée **config.reload.automatic: true**, vous n'avez qu'à attendre que la commande soit exécutée, car Logstash reconnaîtra automatiquement les nouveaux fichiers de configuration de pipeline ou tout changement dans les configurations de pipeline existantes. Sinon, déclenchez un redémarrage du service logstash.

Si aucun joker n'est utilisé, vous pouvez appliquer ces changements à une configuration de pipeline existante. **Assurez-vous de ne rien casser !**

# Références

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
