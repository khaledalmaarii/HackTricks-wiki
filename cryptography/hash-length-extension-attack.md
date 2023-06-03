# Résumé de l'attaque

Imaginez un serveur qui **signe** des **données** en **ajoutant** un **secret** à des données claires connues, puis en hachant ces données. Si vous connaissez :

* **La longueur du secret** (cela peut également être forcé par une plage de longueur donnée)
* **Les données claires**
* **L'algorithme (et il est vulnérable à cette attaque)**
* **Le padding est connu**
  * Habituellement, un padding par défaut est utilisé, donc si les 3 autres exigences sont remplies, cela l'est également
  * Le padding varie en fonction de la longueur du secret+des données, c'est pourquoi la longueur du secret est nécessaire

Alors, il est possible pour un **attaquant** d'**ajouter** des **données** et de **générer** une **signature** valide pour les **données précédentes + données ajoutées**.

## Comment ?

Fondamentalement, les algorithmes vulnérables génèrent les hachages en hachant d'abord un bloc de données, puis, à partir du hash précédemment créé (état), ils ajoutent le bloc de données suivant et le hachent.

Ensuite, imaginez que le secret est "secret" et les données sont "data", le MD5 de "secretdata" est 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un attaquant veut ajouter la chaîne "append", il peut :

* Générer un MD5 de 64 "A"
* Changer l'état du hash précédemment initialisé en 6036708eba0d11f6ef52ad44e8b74d5b
* Ajouter la chaîne "append"
* Terminer le hash et le hash résultant sera un **valide pour "secret" + "data" + "padding" + "append"**

## **Outil**

{% embed url="https://github.com/iagox86/hash_extender" %}

# Références

Vous pouvez trouver cette attaque bien expliquée dans [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
