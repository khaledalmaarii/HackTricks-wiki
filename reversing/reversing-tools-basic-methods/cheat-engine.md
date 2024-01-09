<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où des valeurs importantes sont sauvegardées dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, vous êtes **présenté** avec un **tutoriel** sur comment utiliser l'outil. Il est fortement recommandé de le compléter si vous souhaitez apprendre à utiliser l'outil.

# Qu'est-ce que vous recherchez ?

![](<../../.gitbook/assets/image (580).png>)

Cet outil est très utile pour trouver **où une certaine valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
**Habituellement, les nombres** sont stockés sous forme de **4 octets**, mais vous pourriez également les trouver en formats **double** ou **float**, ou vous pourriez vouloir chercher quelque chose **différent d'un nombre**. Pour cette raison, vous devez être sûr de **sélectionner** ce que vous voulez **rechercher** :

![](<../../.gitbook/assets/image (581).png>)

Vous pouvez également indiquer **différents** types de **recherches** :

![](<../../.gitbook/assets/image (582).png>)

Vous pouvez aussi cocher la case pour **arrêter le jeu pendant l'analyse de la mémoire** :

![](<../../.gitbook/assets/image (584).png>)

## Raccourcis clavier

Dans _**Éditer --> Paramètres --> Raccourcis clavier**_, vous pouvez définir différents **raccourcis clavier** pour différents objectifs comme **arrêter** le **jeu** (ce qui est assez utile si à un moment donné vous voulez analyser la mémoire). D'autres options sont disponibles :

![](<../../.gitbook/assets/image (583).png>)

# Modifier la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous **cherchez** (plus à ce sujet dans les étapes suivantes), vous pouvez **la modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![](<../../.gitbook/assets/image (585).png>)

Et enfin **cocher la case** pour réaliser la modification dans la mémoire :

![](<../../.gitbook/assets/image (586).png>)

Le **changement** dans la **mémoire** sera immédiatement **appliqué** (notez que tant que le jeu n'utilise pas à nouveau cette valeur, la valeur **ne sera pas mise à jour dans le jeu**).

# Rechercher la valeur

Supposons qu'il y ait une valeur importante (comme la vie de votre utilisateur) que vous souhaitez améliorer, et que vous cherchiez cette valeur dans la mémoire)

## À travers un changement connu

Supposons que vous cherchez la valeur 100, vous **effectuez une analyse** à la recherche de cette valeur et vous trouvez beaucoup de coïncidences :

![](<../../.gitbook/assets/image (587).png>)

Ensuite, vous faites quelque chose pour que cette **valeur change**, et vous **arrêtez** le jeu et **effectuez** une **nouvelle analyse** :

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine recherchera les **valeurs** qui **sont passées de 100 à la nouvelle valeur**. Félicitations, vous avez **trouvé** l'**adresse** de la valeur que vous cherchiez, vous pouvez maintenant la modifier.\
_Si vous avez encore plusieurs valeurs, faites quelque chose pour modifier à nouveau cette valeur, et effectuez une autre "nouvelle analyse" pour filtrer les adresses._

## Valeur inconnue, changement connu

Dans le scénario où vous **ne connaissez pas la valeur** mais vous savez **comment la faire changer** (et même la valeur du changement), vous pouvez rechercher votre nombre.

Commencez donc par effectuer une analyse de type "**Valeur initiale inconnue**" :

![](<../../.gitbook/assets/image (589).png>)

Ensuite, faites changer la valeur, indiquez **comment** la **valeur a changé** (dans mon cas, elle a diminué de 1) et effectuez une **nouvelle analyse** :

![](<../../.gitbook/assets/image (590).png>)

Vous verrez **toutes les valeurs qui ont été modifiées de la manière sélectionnée** :

![](<../../.gitbook/assets/image (591).png>)

Une fois que vous avez trouvé votre valeur, vous pouvez la modifier.

Notez qu'il y a **beaucoup de changements possibles** et vous pouvez faire ces **étapes autant que vous le souhaitez** pour filtrer les résultats :

![](<../../.gitbook/assets/image (592).png>)

## Adresse mémoire aléatoire - Trouver le code

Jusqu'à présent, nous avons appris à trouver une adresse stockant une valeur, mais il est très probable que dans **différentes exécutions du jeu, cette adresse soit à différents endroits de la mémoire**. Alors découvrons comment toujours trouver cette adresse.

En utilisant certaines des astuces mentionnées, trouvez l'adresse où votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez) faites un **clic droit** sur l'**adresse trouvée** et sélectionnez "**Découvrir ce qui accède à cette adresse**" ou "**Découvrir ce qui écrit à cette adresse**" :

![](<../../.gitbook/assets/image (593).png>)

La **première option** est utile pour savoir quelles **parties** du **code** utilisent cette **adresse** (ce qui est utile pour d'autres choses comme **savoir où vous pouvez modifier le code** du jeu).\
La **deuxième option** est plus **spécifique**, et sera plus utile dans ce cas car nous sommes intéressés à savoir **d'où cette valeur est écrite**.

Une fois que vous avez sélectionné l'une de ces options, le **débogueur** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Maintenant, **jouez** au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait se **remplir** avec les **adresses** qui **modifient** la **valeur** :

![](<../../.gitbook/assets/image (594).png>)

Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez **modifier le code à votre guise** (Cheat Engine vous permet de le modifier rapidement en NOPs) :

![](<../../.gitbook/assets/image (595).png>)

Ainsi, vous pouvez maintenant le modifier pour que le code n'affecte pas votre nombre, ou qu'il l'affecte toujours de manière positive.

## Adresse mémoire aléatoire - Trouver le pointeur

Suivant les étapes précédentes, trouvez où la valeur qui vous intéresse est. Ensuite, en utilisant "**Découvrir ce qui écrit à cette adresse**", découvrez quelle adresse écrit cette valeur et double-cliquez dessus pour obtenir la vue du désassemblage :

![](<../../.gitbook/assets/image (596).png>)

Ensuite, effectuez une nouvelle analyse **à la recherche de la valeur hexadécimale entre "\[]"** (la valeur de $edx dans ce cas) :

![](<../../.gitbook/assets/image (597).png>)

(_Si plusieurs apparaissent, vous avez généralement besoin de la plus petite adresse_)\
Maintenant, nous avons **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur "**Ajouter une adresse manuellement**" :

![](<../../.gitbook/assets/image (598).png>)

Maintenant, cochez la case "Pointeur" et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario, l'adresse trouvée dans l'image précédente était "Tutorial-i386.exe"+2426B0) :

![](<../../.gitbook/assets/image (599).png>)

(Notez comment la première "Adresse" est automatiquement remplie à partir de l'adresse du pointeur que vous introduisez)

Cliquez sur OK et un nouveau pointeur sera créé :

![](<../../.gitbook/assets/image (600).png>)

Maintenant, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante même si l'adresse mémoire où la valeur se trouve est différente.**

## Injection de code

L'injection de code est une technique où vous injectez un morceau de code dans le processus cible, puis vous détournez l'exécution du code pour le faire passer par votre propre code écrit (comme vous donner des points au lieu de les soustraire).

Imaginez donc que vous avez trouvé l'adresse qui soustrait 1 à la vie de votre joueur :

![](<../../.gitbook/assets/image (601).png>)

Cliquez sur Afficher le désassembleur pour obtenir le **code désassemblé**.\
Ensuite, cliquez sur **CTRL+a** pour invoquer la fenêtre d'assemblage automatique et sélectionnez _**Modèle --> Injection de code**_

![](<../../.gitbook/assets/image (602).png>)

Remplissez **l'adresse de l'instruction que vous souhaitez modifier** (cela est généralement pré-rempli) :

![](<../../.gitbook/assets/image (603).png>)

Un modèle sera généré :

![](<../../.gitbook/assets/image (604).png>)

Insérez donc votre nouveau code d'assemblage dans la section "**newmem**" et retirez le code original de la section "**originalcode**" si vous ne voulez pas qu'il soit exécuté**.** Dans cet exemple, le code injecté ajoutera 2 points au lieu de soustraire 1 :

![](<../../.gitbook/assets/image (605).png>)

**Cliquez sur exécuter et ainsi de suite et votre code devrait être injecté dans le programme en changeant le comportement de la fonctionnalité !**

# **Références**

* **Tutoriel Cheat Engine, complétez-le pour apprendre à commencer avec Cheat Engine**



<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
