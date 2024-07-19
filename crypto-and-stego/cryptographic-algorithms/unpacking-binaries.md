{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
{% endhint %}


# Identification des binaires empaquetés

* **manque de chaînes** : Il est courant de constater que les binaires empaquetés n'ont presque aucune chaîne.
* Beaucoup de **chaînes inutilisées** : De plus, lorsqu'un malware utilise un type de packer commercial, il est courant de trouver beaucoup de chaînes sans références croisées. Même si ces chaînes existent, cela ne signifie pas que le binaire n'est pas empaqueté.
* Vous pouvez également utiliser certains outils pour essayer de trouver quel packer a été utilisé pour empaqueter un binaire :
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recommandations de base

* **Commencez** à analyser le binaire empaqueté **par le bas dans IDA et remontez**. Les dépackers sortent une fois que le code dépacké sort, donc il est peu probable que le dépacker passe l'exécution au code dépacké au début.
* Recherchez des **JMP** ou des **CALL** vers des **registres** ou des **zones** de **mémoire**. Recherchez également des **fonctions poussant des arguments et une direction d'adresse puis appelant `retn`**, car le retour de la fonction dans ce cas peut appeler l'adresse juste poussée sur la pile avant de l'appeler.
* Mettez un **point d'arrêt** sur `VirtualAlloc` car cela alloue de l'espace en mémoire où le programme peut écrire du code dépacké. "Exécutez jusqu'au code utilisateur" ou utilisez F8 pour **obtenir la valeur à l'intérieur de EAX** après l'exécution de la fonction et "**suivez cette adresse dans le dump**". Vous ne savez jamais si c'est la région où le code dépacké va être sauvegardé.
* **`VirtualAlloc`** avec la valeur "**40**" comme argument signifie Lire+Écrire+Exécuter (certaines instructions nécessitant une exécution vont être copiées ici).
* **Lors du dépackaging** du code, il est normal de trouver **plusieurs appels** à des **opérations arithmétiques** et des fonctions comme **`memcopy`** ou **`Virtual`**`Alloc`. Si vous vous trouvez dans une fonction qui apparemment ne fait que des opérations arithmétiques et peut-être quelques `memcopy`, la recommandation est d'essayer de **trouver la fin de la fonction** (peut-être un JMP ou un appel à un registre) **ou** au moins le **dernier appel de fonction** et d'exécuter jusqu'à là car le code n'est pas intéressant.
* Lors du dépackaging du code, **notez** chaque fois que vous **changez de région mémoire** car un changement de région mémoire peut indiquer le **début du code dépacké**. Vous pouvez facilement dumper une région mémoire en utilisant Process Hacker (processus --> propriétés --> mémoire).
* En essayant de dépacker le code, une bonne façon de **savoir si vous travaillez déjà avec le code dépacké** (donc vous pouvez simplement le dumper) est de **vérifier les chaînes du binaire**. Si à un moment donné vous effectuez un saut (peut-être en changeant la région mémoire) et que vous remarquez que **beaucoup plus de chaînes ont été ajoutées**, alors vous pouvez savoir **que vous travaillez avec le code dépacké**.\
Cependant, si le packer contient déjà beaucoup de chaînes, vous pouvez voir combien de chaînes contiennent le mot "http" et voir si ce nombre augmente.
* Lorsque vous dumpez un exécutable d'une région de mémoire, vous pouvez corriger certains en-têtes en utilisant [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
</details>
{% endhint %}
