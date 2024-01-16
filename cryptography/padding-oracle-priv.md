<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC - Chiffrement par Blocs en Chaîne

En mode CBC, **le bloc chiffré précédent est utilisé comme IV** pour le XOR avec le bloc suivant :

![Chiffrement CBC](https://defuse.ca/images/cbc\_encryption.png)

Pour déchiffrer en CBC, les **opérations opposées** sont effectuées :

![Déchiffrement CBC](https://defuse.ca/images/cbc\_decryption.png)

Remarquez qu'il est nécessaire d'utiliser une **clé de chiffrement** et un **IV**.

# Bourrage de Message

Comme le chiffrement est effectué en **blocs de taille fixe**, un **bourrage** est généralement nécessaire dans le **dernier bloc** pour compléter sa longueur.\
Généralement, **PKCS7** est utilisé, qui génère un bourrage en **répétant** le **nombre d'octets nécessaires** pour **compléter** le bloc. Par exemple, s'il manque 3 octets au dernier bloc, le bourrage sera `\x03\x03\x03`.

Voyons plus d'exemples avec **2 blocs de longueur 8 octets** :

| octet #0 | octet #1 | octet #2 | octet #3 | octet #4 | octet #5 | octet #6 | octet #7 | octet #0  | octet #1  | octet #2  | octet #3  | octet #4  | octet #5  | octet #6  | octet #7  |
| -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | --------- | --------- | --------- | --------- | --------- | --------- | --------- | --------- |
| P        | A        | S        | S        | W        | O        | R        | D        | 1         | 2         | 3         | 4         | 5         | 6         | **0x02**  | **0x02**  |
| P        | A        | S        | S        | W        | O        | R        | D        | 1         | 2         | 3         | 4         | 5         | **0x03**  | **0x03**  | **0x03**  |
| P        | A        | S        | S        | W        | O        | R        | D        | 1         | 2         | 3         | **0x05**  | **0x05**  | **0x05**  | **0x05**  | **0x05**  |
| P        | A        | S        | S        | W        | O        | R        | D        | **0x08**  | **0x08**  | **0x08**  | **0x08**  | **0x08**  | **0x08**  | **0x08**  | **0x08**  |

Notez comment dans le dernier exemple **le dernier bloc était plein donc un autre a été généré uniquement avec du bourrage**.

# Oracle de Bourrage

Lorsqu'une application déchiffre des données chiffrées, elle va d'abord déchiffrer les données ; puis elle va retirer le bourrage. Pendant le nettoyage du bourrage, si un **bourrage invalide déclenche un comportement détectable**, vous avez une **vulnérabilité d'oracle de bourrage**. Le comportement détectable peut être une **erreur**, une **absence de résultats**, ou une **réponse plus lente**.

Si vous détectez ce comportement, vous pouvez **déchiffrer les données chiffrées** et même **chiffrer n'importe quel texte clair**.

## Comment exploiter

Vous pourriez utiliser [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) pour exploiter ce type de vulnérabilité ou simplement faire
```
sudo apt-get install padbuster
```
Afin de tester si le cookie d'un site est vulnérable, vous pourriez essayer :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**L'encodage 0** signifie que **base64** est utilisé (mais d'autres sont disponibles, consultez le menu d'aide).

Vous pourriez également **abuser de cette vulnérabilité pour chiffrer de nouvelles données. Par exemple, imaginez que le contenu du cookie soit "**_**user=MyUsername**_**", alors vous pourriez le modifier en "\_user=administrator\_" et élever vos privilèges à l'intérieur de l'application. Vous pourriez aussi le faire en utilisant `paduster` en spécifiant le paramètre -plaintext** :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Si le site est vulnérable, `padbuster` essaiera automatiquement de détecter quand l'erreur de padding se produit, mais vous pouvez également indiquer le message d'erreur en utilisant le paramètre **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La théorie

En **résumé**, vous pouvez commencer à déchiffrer les données cryptées en devinant les bonnes valeurs qui peuvent être utilisées pour créer tous les **différents paddings**. Ensuite, l'attaque par oracle de padding commencera à déchiffrer les octets de la fin au début en devinant quelle sera la bonne valeur qui **crée un padding de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Imaginez que vous avez un texte crypté qui occupe **2 blocs** formés par les octets de **E0 à E15**.\
Pour **déchiffrer** le **dernier** **bloc** (**E8** à **E15**), le bloc entier passe par le "déchiffrement de chiffrement par blocs" générant les **octets intermédiaires I0 à I15**.\
Finalement, chaque octet intermédiaire est **XORé** avec les octets cryptés précédents (E0 à E7). Donc :

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Maintenant, il est possible de **modifier `E7` jusqu'à ce que `C15` soit `0x01`**, ce qui sera également un padding correct. Donc, dans ce cas : `\x01 = I15 ^ E'7`

Ainsi, en trouvant E'7, il est **possible de calculer I15** : `I15 = 0x01 ^ E'7`

Ce qui nous permet de **calculer C15** : `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Connaissant **C15**, il est maintenant possible de **calculer C14**, mais cette fois en forçant brutalement le padding `\x02\x02`.

Ce BF est aussi complexe que le précédent car il est possible de calculer le `E''15` dont la valeur est 0x02 : `E''7 = \x02 ^ I15` donc il suffit de trouver le **`E'14`** qui génère un **`C14` égal à `0x02`**.\
Ensuite, faites les mêmes étapes pour déchiffrer C14 : **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Suivez cette chaîne jusqu'à ce que vous déchiffriez l'intégralité du texte crypté.**

## Détection de la vulnérabilité

Enregistrez un compte et connectez-vous avec ce compte.\
Si vous vous **connectez plusieurs fois** et obtenez toujours le **même cookie**, il y a probablement **quelque chose** **qui ne va pas** dans l'application. Le **cookie renvoyé devrait être unique** à chaque connexion. Si le cookie est **toujours** le **même**, il sera probablement toujours valide et il **n'y aura aucun moyen de l'invalider**.

Maintenant, si vous essayez de **modifier** le **cookie**, vous pouvez voir que vous obtenez une **erreur** de l'application.\
Mais si vous forcez brutalement le padding (en utilisant padbuster par exemple), vous parvenez à obtenir un autre cookie valide pour un utilisateur différent. Ce scénario est très probablement vulnérable à padbuster.

# Références

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
