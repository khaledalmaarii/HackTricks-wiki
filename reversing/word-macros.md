## Code inutile

Il est très courant de trouver du **code inutile qui n'est jamais utilisé** pour rendre la rétro-ingénierie de la macro plus difficile.\
Par exemple, dans l'image suivante, vous pouvez voir qu'un If qui ne sera jamais vrai est utilisé pour exécuter un code inutile.

![](<../.gitbook/assets/image (373).png>)

## Formulaires de macro

En utilisant la fonction **GetObject**, il est possible d'obtenir des données à partir de formulaires de la macro. Cela peut être utilisé pour compliquer l'analyse. La photo suivante montre un formulaire de macro utilisé pour **cacher des données à l'intérieur de zones de texte** (une zone de texte peut cacher d'autres zones de texte) :

![](<../.gitbook/assets/image (374).png>)
