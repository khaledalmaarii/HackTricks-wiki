<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Baseline

Une baseline consiste à prendre une capture instantanée de certaines parties d'un système pour **la comparer à un état futur afin de mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du système de fichiers pour pouvoir déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateurs créés, les processus en cours d'exécution, les services en cours d'exécution et toute autre chose qui ne devrait pas changer beaucoup, voire pas du tout.

## Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers est l'une des techniques les plus puissantes utilisées pour sécuriser les infrastructures informatiques et les données commerciales contre une grande variété de menaces connues et inconnues.\
L'objectif est de générer une **baseline de tous les fichiers** que vous souhaitez surveiller, puis de **vérifier périodiquement** ces fichiers pour d'éventuels **changements** (dans le contenu, les attributs, les métadonnées, etc.).

1\. **Comparaison de baseline,** où un ou plusieurs attributs de fichier seront capturés ou calculés et stockés comme une baseline qui pourra être comparée à l'avenir. Cela peut être aussi simple que la date et l'heure du fichier, cependant, puisque ces données peuvent être facilement falsifiées, une approche plus fiable est généralement utilisée. Cela peut inclure l'évaluation périodique de la somme de contrôle cryptographique pour un fichier surveillé, (par exemple, en utilisant l'algorithme de hachage MD5 ou SHA-2) puis en comparant le résultat à la somme de contrôle précédemment calculée.

2\. **Notification de changement en temps réel**, qui est généralement mise en œuvre au sein ou en tant qu'extension du noyau du système d'exploitation qui signalera lorsqu'un fichier est accédé ou modifié.

## Outils

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Références

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
