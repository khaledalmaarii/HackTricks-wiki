<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Baseline

Une ligne de base consiste à prendre un instantané de certaines parties d'un système pour **le comparer à un état futur afin de mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hachage de chaque fichier du système de fichiers pour pouvoir savoir quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes d'utilisateurs créés, les processus en cours d'exécution, les services en cours d'exécution et toute autre chose qui ne devrait pas changer beaucoup, voire pas du tout.

## Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers est l'une des techniques les plus puissantes utilisées pour sécuriser les infrastructures informatiques et les données commerciales contre une grande variété de menaces connues et inconnues.\
L'objectif est de générer une **ligne de base de tous les fichiers** que vous souhaitez surveiller, puis de **vérifier périodiquement** ces fichiers pour d'éventuels **changements** (dans le contenu, les attributs, les métadonnées, etc.).

1\. **Comparaison de la ligne de base**, où un ou plusieurs attributs de fichier seront capturés ou calculés et stockés en tant que ligne de base pouvant être comparée ultérieurement. Cela peut être aussi simple que l'heure et la date du fichier, cependant, comme ces données peuvent être facilement falsifiées, une approche plus fiable est généralement utilisée. Cela peut inclure l'évaluation périodique du hachage cryptographique d'un fichier surveillé, (par exemple en utilisant l'algorithme de hachage MD5 ou SHA-2) puis comparer le résultat au hachage précédemment calculé.

2\. **Notification de changement en temps réel**, qui est généralement implémentée à l'intérieur ou en tant qu'extension du noyau du système d'exploitation qui signalera quand un fichier est accédé ou modifié.

## Outils

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Références

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
