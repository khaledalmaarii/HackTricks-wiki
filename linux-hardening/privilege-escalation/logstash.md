<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Informations de base

Logstash est utilisé pour collecter, transformer et émettre des journaux. Cela est réalisé en utilisant des **pipelines**, qui contiennent des modules d'entrée, de filtre et de sortie. Le service devient intéressant lorsqu'on a compromis une machine qui exécute Logstash en tant que service.

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
Ici, vous pouvez trouver les chemins d'accès aux fichiers **.conf**, qui contiennent les pipelines configurés. Si le module de sortie **Elasticsearch** est utilisé, les **pipelines** contiennent probablement des **informations d'identification** valides pour une instance Elasticsearch. Ces informations d'identification ont souvent plus de privilèges, car Logstash doit écrire des données dans Elasticsearch. Si des caractères génériques sont utilisés, Logstash essaie d'exécuter tous les pipelines situés dans ce dossier correspondant au caractère générique.

## Privilège d'escalade avec des pipelines modifiables

Avant d'essayer d'élever vos propres privilèges, vous devez vérifier quel utilisateur exécute le service logstash, car ce sera l'utilisateur que vous posséderez par la suite. Par défaut, le service logstash s'exécute avec les privilèges de l'utilisateur **logstash**.

Vérifiez si vous avez **l'un** des droits requis :

* Vous avez des **permissions d'écriture** sur un fichier **.conf** de pipeline **ou**
* **/etc/logstash/pipelines.yml** contient un caractère générique et vous êtes autorisé à écrire dans le dossier spécifié

De plus, **l'une** des exigences suivantes doit être remplie :

* Vous êtes en mesure de redémarrer le service logstash **ou**
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
L'**intervalle** spécifie le temps en secondes. Dans cet exemple, la commande **whoami** est exécutée toutes les 120 secondes. La sortie de la commande est enregistrée dans **/tmp/output.log**.

Si **/etc/logstash/logstash.yml** contient l'entrée **config.reload.automatic: true**, vous n'avez qu'à attendre que la commande soit exécutée, car Logstash reconnaîtra automatiquement les nouveaux fichiers de configuration de pipeline ou toute modification des configurations de pipeline existantes. Sinon, déclenchez un redémarrage du service logstash.

Si aucun joker n'est utilisé, vous pouvez appliquer ces modifications à une configuration de pipeline existante. **Assurez-vous de ne rien casser !**

# Références

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
