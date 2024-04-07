# Cheat Engine

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) est un programme utile pour trouver où sont enregistrées les valeurs importantes dans la mémoire d'un jeu en cours d'exécution et les modifier.\
Lorsque vous le téléchargez et l'exécutez, vous avez droit à un **tutoriel** sur l'utilisation de l'outil. Il est fortement recommandé de le suivre si vous souhaitez apprendre à utiliser l'outil.

## Que recherchez-vous ?

![](<../../.gitbook/assets/image (759).png>)

Cet outil est très utile pour trouver **où une certaine valeur** (généralement un nombre) **est stockée dans la mémoire** d'un programme.\
**Généralement les nombres** sont stockés sous forme de **4 octets**, mais vous pouvez également les trouver sous forme de **double** ou **float**, ou vous pouvez chercher quelque chose **d'autre qu'un nombre**. Pour cette raison, assurez-vous de **sélectionner** ce que vous voulez **rechercher** :

![](<../../.gitbook/assets/image (321).png>)

Vous pouvez également indiquer **différents** types de **recherches** :

![](<../../.gitbook/assets/image (307).png>)

Vous pouvez également cocher la case pour **arrêter le jeu pendant l'analyse de la mémoire** :

![](<../../.gitbook/assets/image (1049).png>)

### Raccourcis

Dans _**Edit --> Paramètres --> Raccourcis**_, vous pouvez définir différents **raccourcis** pour différentes fonctions comme **arrêter** le **jeu** (ce qui est très utile si à un moment donné vous souhaitez analyser la mémoire). D'autres options sont disponibles :

![](<../../.gitbook/assets/image (861).png>)

## Modifier la valeur

Une fois que vous avez **trouvé** où se trouve la **valeur** que vous **cherchez** (plus d'informations à ce sujet dans les étapes suivantes), vous pouvez la **modifier** en double-cliquant dessus, puis en double-cliquant sur sa valeur :

![](<../../.gitbook/assets/image (560).png>)

Et enfin, **cochez la case** pour que la modification soit effectuée en mémoire :

![](<../../.gitbook/assets/image (382).png>)

Le **changement** dans la **mémoire** sera immédiatement **appliqué** (notez que tant que le jeu n'utilise pas à nouveau cette valeur, la valeur **ne sera pas mise à jour dans le jeu**).

## Recherche de la valeur

Donc, supposons qu'il y ait une valeur importante (comme la vie de votre utilisateur) que vous souhaitez améliorer, et que vous cherchez cette valeur dans la mémoire)

### À travers un changement connu

En supposant que vous cherchez la valeur 100, vous **effectuez une analyse** en recherchant cette valeur et vous trouvez beaucoup de correspondances :

![](<../../.gitbook/assets/image (105).png>)

Ensuite, faites quelque chose pour que la **valeur change**, et **arrêtez** le jeu et **effectuez** une **analyse suivante** :

![](<../../.gitbook/assets/image (681).png>)

Cheat Engine recherchera les **valeurs** qui sont passées de 100 à la nouvelle valeur. Félicitations, vous avez **trouvé** l'**adresse** de la valeur que vous cherchiez, vous pouvez maintenant la modifier.\
_Si vous avez encore plusieurs valeurs, faites quelque chose pour modifier à nouveau cette valeur, et effectuez une autre "analyse suivante" pour filtrer les adresses._

### Valeur inconnue, changement connu

Dans le scénario où vous **ne connaissez pas la valeur** mais vous savez **comment la faire changer** (et même la valeur du changement), vous pouvez rechercher votre nombre.

Donc, commencez par effectuer une analyse de type "**Valeur initiale inconnue**" :

![](<../../.gitbook/assets/image (887).png>)

Ensuite, faites changer la valeur, indiquez **comment** la **valeur a changé** (dans mon cas, elle a été diminuée de 1) et effectuez une **analyse suivante** :

![](<../../.gitbook/assets/image (368).png>)

Vous verrez **toutes les valeurs qui ont été modifiées de la manière sélectionnée** :

![](<../../.gitbook/assets/image (566).png>)

Une fois que vous avez trouvé votre valeur, vous pouvez la modifier.

Notez qu'il y a **beaucoup de changements possibles** et vous pouvez effectuer ces **étapes autant que vous le souhaitez** pour filtrer les résultats :

![](<../../.gitbook/assets/image (571).png>)

### Adresse mémoire aléatoire - Trouver le code

Jusqu'à présent, nous avons appris à trouver une adresse stockant une valeur, mais il est très probable que dans **différentes exécutions du jeu cette adresse se trouve à des endroits différents de la mémoire**. Voyons comment trouver cette adresse de manière constante.

En utilisant quelques-uns des astuces mentionnées, trouvez l'adresse où votre jeu actuel stocke la valeur importante. Ensuite (en arrêtant le jeu si vous le souhaitez), faites un **clic droit** sur l'**adresse trouvée** et sélectionnez "**Découvrir ce qui accède à cette adresse**" ou "**Découvrir ce qui écrit à cette adresse**" :

![](<../../.gitbook/assets/image (1064).png>)

La **première option** est utile pour savoir quelles **parties** du **code** utilisent cette **adresse** (ce qui est utile pour d'autres choses comme **savoir où vous pouvez modifier le code** du jeu).\
La **deuxième option** est plus **spécifique**, et sera plus utile dans ce cas car nous voulons savoir **d'où cette valeur est écrite**.

Une fois que vous avez sélectionné l'une de ces options, le **débogueur** sera **attaché** au programme et une nouvelle **fenêtre vide** apparaîtra. Maintenant, **jouez** au **jeu** et **modifiez** cette **valeur** (sans redémarrer le jeu). La **fenêtre** devrait être **remplie** des **adresses** qui modifient la **valeur** :

![](<../../.gitbook/assets/image (88).png>)

Maintenant que vous avez trouvé l'adresse qui modifie la valeur, vous pouvez **modifier le code à votre guise** (Cheat Engine vous permet de le modifier en NOPs très rapidement) :

![](<../../.gitbook/assets/image (1054).png>)

Ainsi, vous pouvez maintenant le modifier pour que le code n'affecte pas votre nombre, ou affecte toujours de manière positive.
### Adresse mémoire aléatoire - Trouver le pointeur

Suivant les étapes précédentes, trouvez où se trouve la valeur qui vous intéresse. Ensuite, en utilisant "**Découvrir ce qui écrit à cette adresse**", découvrez quelle adresse écrit cette valeur et double-cliquez dessus pour obtenir la vue de désassemblage :

![](<../../.gitbook/assets/image (1036).png>)

Ensuite, effectuez une nouvelle analyse en **recherchant la valeur hexadécimale entre "\[]"** (la valeur de $edx dans ce cas) :

![](<../../.gitbook/assets/image (991).png>)

(_Si plusieurs apparaissent, vous avez généralement besoin de celui avec l'adresse la plus petite_)\
Maintenant, nous avons **trouvé le pointeur qui modifiera la valeur qui nous intéresse**.

Cliquez sur "**Ajouter une adresse manuellement**" :

![](<../../.gitbook/assets/image (987).png>)

Maintenant, cochez la case "Pointeur" et ajoutez l'adresse trouvée dans la zone de texte (dans ce scénario, l'adresse trouvée dans l'image précédente était "Tutorial-i386.exe"+2426B0) :

![](<../../.gitbook/assets/image (388).png>)

(Notez comment la première "Adresse" est automatiquement renseignée à partir de l'adresse du pointeur que vous introduisez)

Cliquez sur OK et un nouveau pointeur sera créé :

![](<../../.gitbook/assets/image (305).png>)

Maintenant, chaque fois que vous modifiez cette valeur, vous **modifiez la valeur importante même si l'adresse mémoire où se trouve la valeur est différente**.

### Injection de code

L'injection de code est une technique où vous injectez un morceau de code dans le processus cible, puis redirigez l'exécution du code pour passer par votre propre code écrit (comme vous donnant des points au lieu de les retirer).

Donc, imaginez que vous avez trouvé l'adresse qui soustrait 1 à la vie de votre joueur :

![](<../../.gitbook/assets/image (200).png>)

Cliquez sur Afficher le désassembleur pour obtenir le **code désassemblé**.\
Ensuite, cliquez sur **CTRL+a** pour ouvrir la fenêtre Auto Assemble et sélectionnez _**Modèle --> Injection de code**_

![](<../../.gitbook/assets/image (899).png>)

Remplissez l'**adresse de l'instruction que vous souhaitez modifier** (celle-ci est généralement pré-remplie) :

![](<../../.gitbook/assets/image (741).png>)

Un modèle sera généré :

![](<../../.gitbook/assets/image (941).png>)

Insérez votre nouveau code d'assemblage dans la section "**newmem**" et supprimez le code original de la section "**originalcode** si vous ne voulez pas qu'il soit exécuté\*\*.\*\* Dans cet exemple, le code injecté ajoutera 2 points au lieu de soustraire 1 :

![](<../../.gitbook/assets/image (518).png>)

**Cliquez sur exécuter et ainsi de suite, votre code devrait être injecté dans le programme, modifiant le comportement de la fonctionnalité !**

## **Références**

* **Tutoriel Cheat Engine, complétez-le pour apprendre à démarrer avec Cheat Engine**
