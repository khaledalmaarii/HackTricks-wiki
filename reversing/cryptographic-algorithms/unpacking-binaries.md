<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Identifier les binaires empaquetés

* **manque de chaînes de caractères** : Il est courant de constater que les binaires empaquetés n'ont presque aucune chaîne de caractères
* Beaucoup de **chaînes de caractères inutilisées** : De plus, lorsqu'un malware utilise une sorte d'empaqueteur commercial, il est courant de trouver de nombreuses chaînes sans références croisées. Même si ces chaînes existent, cela ne signifie pas que le binaire n'est pas empaqueté.
* Vous pouvez également utiliser certains outils pour essayer de trouver quel empaqueteur a été utilisé pour empaqueter un binaire :
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recommandations de base

* **Commencez** à analyser le binaire empaqueté **depuis le bas dans IDA et remontez**. Les désempaqueteurs se terminent une fois que le code désempaqueté se termine, il est donc peu probable que le désempaqueteur passe l'exécution au code désempaqueté au début.
* Recherchez des **JMP** ou des **CALL** vers des **registres** ou des **régions** de **mémoire**. Recherchez également des **fonctions poussant des arguments et une direction d'adresse puis appelant `retn`**, car le retour de la fonction dans ce cas peut appeler l'adresse juste poussée sur la pile avant de l'appeler.
* Placez un **point d'arrêt** sur `VirtualAlloc` car cela alloue de l'espace dans la mémoire où le programme peut écrire du code désempaqueté. Utilisez "exécuter jusqu'au code utilisateur" ou utilisez F8 pour **atteindre la valeur à l'intérieur de EAX** après avoir exécuté la fonction et "**suivez cette adresse dans le dump**". Vous ne savez jamais si c'est la région où le code désempaqueté va être sauvegardé.
* **`VirtualAlloc`** avec la valeur "**40**" comme argument signifie Lecture+Écriture+Exécution (du code nécessitant une exécution va être copié ici).
* **Pendant le désassemblage** du code, il est normal de trouver **plusieurs appels** à des opérations **arithmétiques** et des fonctions comme **`memcopy`** ou **`Virtual`**`Alloc`. Si vous vous retrouvez dans une fonction qui apparemment n'effectue que des opérations arithmétiques et peut-être un peu de `memcopy`, la recommandation est d'essayer de **trouver la fin de la fonction** (peut-être un JMP ou un appel à un registre) **ou** au moins l'**appel à la dernière fonction** et exécutez jusqu'à ce point car le code n'est pas intéressant.
* Pendant le désassemblage du code, **notez** chaque fois que vous **changez de région de mémoire** car un changement de région de mémoire peut indiquer le **début du code de désassemblage**. Vous pouvez facilement dumper une région de mémoire en utilisant Process Hacker (processus --> propriétés --> mémoire).
* Lorsque vous essayez de désassembler du code, une bonne façon de **savoir si vous travaillez déjà avec le code désempaqueté** (pour pouvoir simplement le dumper) est de **vérifier les chaînes de caractères du binaire**. Si à un moment donné vous effectuez un saut (peut-être en changeant de région de mémoire) et vous remarquez qu'**un nombre beaucoup plus important de chaînes a été ajouté**, alors vous pouvez savoir **que vous travaillez avec le code désempaqueté**.\
Cependant, si l'empaqueteur contient déjà beaucoup de chaînes, vous pouvez voir combien de chaînes contiennent le mot "http" et voir si ce nombre augmente.
* Lorsque vous dumper un exécutable d'une région de mémoire, vous pouvez corriger certains en-têtes en utilisant [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
