# Algorithmes Cryptographiques/Compression

## Algorithmes Cryptographiques/Compression

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identification des Algorithmes

Si vous tombez sur un code **utilisant des décalages à droite et à gauche, des xors et plusieurs opérations arithmétiques**, il est fort probable qu'il s'agisse de l'implémentation d'un **algorithme cryptographique**. Ici, il sera montré des moyens d'**identifier l'algorithme utilisé sans avoir à inverser chaque étape**.

### Fonctions API

**CryptDeriveKey**

Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Consultez ici le tableau des algorithmes possibles et leurs valeurs attribuées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Compresse et décompresse un tampon de données donné.

**CryptAcquireContext**

La fonction **CryptAcquireContext** est utilisée pour acquérir un handle vers un conteneur de clés spécifique au sein d'un fournisseur de services cryptographiques (CSP) particulier. **Ce handle retourné est utilisé dans les appels aux fonctions CryptoAPI** qui utilisent le CSP sélectionné.

**CryptCreateHash**

Initie le hachage d'un flux de données. Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../.gitbook/assets/image (376).png>)

\
Consultez ici le tableau des algorithmes possibles et leurs valeurs attribuées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de Code

Parfois, il est très facile d'identifier un algorithme grâce au fait qu'il doit utiliser une valeur spéciale et unique.

![](<../../.gitbook/assets/image (370).png>)

Si vous recherchez la première constante sur Google, voici ce que vous obtenez :

![](<../../.gitbook/assets/image (371).png>)

Par conséquent, vous pouvez supposer que la fonction décompilée est un **calculateur sha256.**\
Vous pouvez rechercher n'importe laquelle des autres constantes et vous obtiendrez (probablement) le même résultat.

### Informations sur les données

Si le code ne contient aucune constante significative, il peut **charger des informations à partir de la section .data**.\
Vous pouvez accéder à ces données, **regrouper le premier dword** et le rechercher sur Google comme nous l'avons fait dans la section précédente :

![](<../../.gitbook/assets/image (372).png>)

Dans ce cas, si vous recherchez **0xA56363C6**, vous pouvez trouver qu'il est lié aux **tables de l'algorithme AES**.

## RC4 **(Crypt Symétrique)**

### Caractéristiques

Il est composé de 3 parties principales :

* **Phase d'initialisation/** : Crée une **table de valeurs de 0x00 à 0xFF** (256 octets au total, 0x100). Cette table est communément appelée **Boîte de Substitution** (ou SBox).
* **Phase de brouillage** : Va **parcourir la table** créée précédemment (boucle de 0x100 itérations, encore) en modifiant chaque valeur avec des octets **semi-aléatoires**. Pour créer ces octets semi-aléatoires, la **clé RC4 est utilisée**. Les **clés RC4** peuvent être **entre 1 et 256 octets de longueur**, cependant il est généralement recommandé qu'elle soit supérieure à 5 octets. Habituellement, les clés RC4 font 16 octets de longueur.
* **Phase XOR** : Enfin, le texte clair ou le texte chiffré est **XORé avec les valeurs créées précédemment**. La fonction pour chiffrer et déchiffrer est la même. Pour cela, une **boucle à travers les 256 octets créés** sera effectuée autant de fois que nécessaire. Ceci est généralement reconnu dans un code décompilé avec un **%256 (mod 256)**.

{% hint style="info" %}
**Pour identifier un RC4 dans un code désassemblé/décompilé, vous pouvez vérifier 2 boucles de taille 0x100 (avec l'utilisation d'une clé) puis un XOR des données d'entrée avec les 256 valeurs créées précédemment dans les 2 boucles probablement en utilisant un %256 (mod 256)**
{% endhint %}

### **Phase d'initialisation/Boîte de Substitution :** (Notez le nombre 256 utilisé comme compteur et comment un 0 est écrit à chaque place des 256 caractères)

![](<../../.gitbook/assets/image (377).png>)

### **Phase de Brouillage :**

![](<../../.gitbook/assets/image (378).png>)

### **Phase XOR :**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Crypt Symétrique)**

### **Caractéristiques**

* Utilisation de **boîtes de substitution et de tables de recherche**
* Il est possible de **distinguer AES grâce à l'utilisation de valeurs spécifiques de tables de recherche** (constantes). _Notez que la **constante** peut être **stockée** dans le binaire **ou créée**_ _**dynamiquement**._
* La **clé de chiffrement** doit être **divisible** par **16** (généralement 32B) et généralement un **IV** de 16B est utilisé.

### Constantes SBox

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Crypt Symétrique)**

### Caractéristiques

* Il est rare de trouver des malwares l'utilisant mais il y a des exemples (Ursnif)
* Simple à déterminer si un algorithme est Serpent ou non en fonction de sa longueur (fonction extrêmement longue)

### Identification

Dans l'image suivante, notez comment la constante **0x9E3779B9** est utilisée (notez que cette constante est également utilisée par d'autres algorithmes cryptographiques comme **TEA** -Tiny Encryption Algorithm).\
Notez également la **taille de la boucle** (**132**) et le **nombre d'opérations XOR** dans les **instructions de désassemblage** et dans l'**exemple de code** :

![](<../../.gitbook/assets/image (381).png>)

Comme mentionné précédemment, ce code peut être visualisé dans n'importe quel décompilateur comme une **fonction très longue** car il **n'y a pas de sauts** à l'intérieur. Le code décompilé peut ressembler à ce qui suit :

![](<../../.gitbook/assets/image (382).png>)

Par conséquent, il est possible d'identifier cet algorithme en vérifiant le **nombre magique** et les **XOR initiaux**, en voyant une **fonction très longue** et en **comparant** certaines **instructions** de la longue fonction **avec une implémentation** (comme le décalage à gauche de 7 et la rotation à gauche de 22).

## RSA **(Crypt Asymétrique)**

### Caractéristiques

* Plus complexe que les algorithmes symétriques
* Il n'y a pas de constantes ! (les implémentations personnalisées sont difficiles à déterminer)
* KANAL (un analyseur crypto) échoue à donner des indices sur RSA car il repose sur des constantes.

### Identification par comparaisons

![](<../../.gitbook/assets/image (383).png>)

* À la ligne 11 (gauche), il y a un `+7) >> 3` qui est le même qu'à la ligne 35 (droite) : `+7) / 8`
* La ligne 12 (gauche) vérifie si `modulus_len < 0x040` et à la ligne 36 (droite) elle vérifie si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caractéristiques

* 3 fonctions : Init, Update, Final
* Fonctions d'initialisation similaires

### Identifier

**Init**

Vous pouvez identifier les deux en vérifiant les constantes. Notez que le sha\_init a 1 constante que MD5 n'a pas :

![](<../../.gitbook/assets/image (385).png>)

**Transformation MD5**

Notez l'utilisation de plus de constantes

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Plus petit et plus efficace car sa fonction est de trouver des changements accidentels dans les données
* Utilise des tables de recherche (donc vous pouvez identifier des constantes)

### Identifier

Vérifiez **les constantes de la table de recherche** :

![](<../../.gitbook/assets/image (387).png>)

Un algorithme de hash CRC ressemble à :

![](<../../.gitbook/assets/image (386).png>)

## APLib (Compression)

### Caractéristiques

* Pas de constantes reconnaissables
* Vous pouvez essayer d'écrire l'algorithme en python et rechercher des choses similaires en ligne

### Identifier

Le graphe est assez grand :

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Vérifiez **3 comparaisons pour le reconnaître** :

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
