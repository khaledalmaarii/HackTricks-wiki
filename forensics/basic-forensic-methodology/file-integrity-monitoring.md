<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Baseline

Une ligne de base consiste à prendre une capture d'écran de certaines parties d'un système pour **la comparer avec un état futur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hachage de chaque fichier du système de fichiers pour pouvoir savoir quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes d'utilisateurs créés, les processus en cours d'exécution, les services en cours d'exécution et toute autre chose qui ne devrait pas changer beaucoup, voire pas du tout.

## Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers est l'une des techniques les plus puissantes utilisées pour sécuriser les infrastructures informatiques et les données commerciales contre une grande variété de menaces connues et inconnues.\
L'objectif est de générer une **ligne de base de tous les fichiers** que vous souhaitez surveiller, puis de **vérifier périodiquement** ces fichiers pour détecter d'éventuels **changements** (dans le contenu, les attributs, les métadonnées, etc.).

1\. **Comparaison de la ligne de base**, dans laquelle un ou plusieurs attributs de fichier seront capturés ou calculés et stockés en tant que ligne de base qui peut être comparée à l'avenir. Cela peut être aussi simple que l'heure et la date du fichier, cependant, comme ces données peuvent être facilement falsifiées, une approche plus fiable est généralement utilisée. Cela peut inclure l'évaluation périodique de la somme de contrôle cryptographique pour un fichier surveillé (par exemple, en utilisant l'algorithme de hachage MD5 ou SHA-2) et la comparaison du résultat avec la somme de contrôle précédemment calculée.

2\. **Notification de changement en temps réel**, qui est généralement mise en œuvre dans ou en tant qu'extension du noyau du système d'exploitation qui signalera lorsqu'un fichier est accédé ou modifié.

## Outils

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Références

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>
