# Identification des binaires compressés

* **Absence de chaînes**: Il est courant de constater que les binaires compressés n'ont presque aucune chaîne.
* Beaucoup de **chaînes inutilisées**: Lorsqu'un logiciel malveillant utilise un type de packer commercial, il est courant de trouver de nombreuses chaînes sans références croisées. Même si ces chaînes existent, cela ne signifie pas que le binaire n'est pas compressé.
* Vous pouvez également utiliser certains outils pour essayer de trouver quel packer a été utilisé pour compresser un binaire :
  * [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
  * [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
  * [Language 2000](http://farrokhi.net/language/)

# Recommandations de base

* **Commencez** l'analyse du binaire compressé **à partir du bas dans IDA et remontez**. Les unpackers sortent une fois que le code unpacké sort, il est donc peu probable que l'unpacker passe l'exécution au code unpacké au début.
* Recherchez les **JMP** ou **CALL** vers les **registres** ou les **régions** de la **mémoire**. Recherchez également les **fonctions qui poussent des arguments et une adresse de direction, puis appellent `retn`**, car le retour de la fonction dans ce cas peut appeler l'adresse juste poussée sur la pile avant de l'appeler.
* Mettez un **point d'arrêt** sur `VirtualAlloc`, car cela alloue de l'espace dans la mémoire où le programme peut écrire du code décompressé. Exécutez la fonction jusqu'à la valeur à l'intérieur de EAX après l'exécution et **suivez cette adresse dans le dump**. Vous ne savez jamais si c'est la région où le code décompressé va être enregistré.
  * **`VirtualAlloc`** avec la valeur "**40**" comme argument signifie Read+Write+Execute (du code qui doit être exécuté va être copié ici).
* **Pendant le déballage** du code, il est normal de trouver **plusieurs appels** à des **opérations arithmétiques** et à des fonctions comme **`memcopy`** ou **`Virtual`**`Alloc`. Si vous vous trouvez dans une fonction qui ne semble effectuer que des opérations arithmétiques et peut-être un `memcopy`, la recommandation est d'essayer de **trouver la fin de la fonction** (peut-être un JMP ou un appel à un registre) **ou** au moins l'**appel à la dernière fonction** et de l'exécuter car le code n'est pas intéressant.
* Pendant le déballage du code, **notez** chaque fois que vous **changez de région de mémoire**, car un changement de région de mémoire peut indiquer le **début du code décompressé**. Vous pouvez facilement décharger une région de mémoire en utilisant Process Hacker (processus --> propriétés --> mémoire).
* Lorsque vous essayez de décompresser du code, une bonne façon de **savoir si vous travaillez déjà avec le code décompressé** (afin que vous puissiez simplement le décharger) est de **vérifier les chaînes du binaire**. Si à un moment donné vous effectuez un saut (peut-être en changeant la région de mémoire) et que vous remarquez que **beaucoup plus de chaînes ont été ajoutées**, alors vous pouvez savoir que **vous travaillez avec le code décompressé**.\
  Cependant, si le packer contient déjà beaucoup de chaînes, vous pouvez voir combien de chaînes contiennent le mot "http" et voir si ce nombre augmente.
* Lorsque vous déchargez un exécutable à partir d'une région de mémoire, vous pouvez corriger certains en-têtes à l'aide de [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
