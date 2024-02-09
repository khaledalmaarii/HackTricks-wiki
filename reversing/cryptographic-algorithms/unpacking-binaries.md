<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Identification des binaires compressés

* **Absence de chaînes** : Il est courant de constater que les binaires compressés n'ont presque aucune chaîne.
* Beaucoup de **chaînes inutilisées** : De plus, lorsqu'un logiciel malveillant utilise un type de compresseur commercial, il est courant de trouver beaucoup de chaînes sans références croisées. Même si ces chaînes existent, cela ne signifie pas que le binaire n'est pas compressé.
* Vous pouvez également utiliser certains outils pour essayer de trouver quel compresseur a été utilisé pour compresser un binaire :
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recommandations de base

* **Commencez** l'analyse du binaire compressé **du bas dans IDA et remontez**. Les désassembleurs sortent une fois que le code désassemblé sort, il est donc peu probable que le désassembleur passe l'exécution au code désassemblé au début.
* Recherchez des **JMP** ou des **CALL** vers des **registres** ou des **régions** de **mémoire**. Recherchez également des **fonctions poussant des arguments et une adresse de direction puis appelant `retn`**, car le retour de la fonction dans ce cas peut appeler l'adresse juste poussée sur la pile avant de l'appeler.
* Placez un **point d'arrêt** sur `VirtualAlloc` car cela alloue de l'espace en mémoire où le programme peut écrire du code décompressé. "Exécutez jusqu'au code utilisateur" ou utilisez F8 pour **arriver à la valeur à l'intérieur de EAX** après l'exécution de la fonction et "**suivez cette adresse dans le dump**". Vous ne savez jamais si c'est la région où le code décompressé va être sauvegardé.
* **`VirtualAlloc`** avec la valeur "**40**" comme argument signifie Lecture+Écriture+Exécution (du code qui nécessite une exécution va être copié ici).
* **Pendant le décompactage** du code, il est normal de trouver **plusieurs appels** à des **opérations arithmétiques** et à des fonctions comme **`memcopy`** ou **`Virtual`**`Alloc`. Si vous vous trouvez dans une fonction qui ne semble effectuer que des opérations arithmétiques et peut-être un peu de `memcopy`, la recommandation est d'essayer de **trouver la fin de la fonction** (peut-être un JMP ou un appel à un registre) **ou** au moins l'**appel à la dernière fonction** et d'exécuter jusqu'à ce moment car le code n'est pas intéressant.
* Pendant le décompactage du code, **notez** chaque fois que vous **changez de région mémoire** car un changement de région mémoire peut indiquer le **début du code décompressé**. Vous pouvez facilement décharger une région mémoire en utilisant Process Hacker (processus --> propriétés --> mémoire).
* En essayant de décompresser du code, une bonne façon de **savoir si vous travaillez déjà avec le code décompressé** (pour pouvoir simplement le décharger) est de **vérifier les chaînes du binaire**. Si à un moment donné vous effectuez un saut (peut-être en changeant la région mémoire) et que vous remarquez que **beaucoup plus de chaînes ont été ajoutées**, alors vous pouvez savoir **que vous travaillez avec le code décompressé**.\
Cependant, si le compresseur contient déjà beaucoup de chaînes, vous pouvez voir combien de chaînes contiennent le mot "http" et voir si ce nombre augmente.
* Lorsque vous déchargez un exécutable à partir d'une région de mémoire, vous pouvez corriger certains en-têtes en utilisant [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

</details>
