# CBC - Cipher Block Chaining

En mode CBC, le **bloc chiffré précédent est utilisé comme IV** pour XOR avec le bloc suivant :

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

Pour décrypter CBC, les **opérations opposées** sont effectuées :

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

Remarquez qu'il est nécessaire d'utiliser une **clé de chiffrement** et un **IV**.

# Remplissage de message

Comme le chiffrement est effectué en **blocs de taille fixe**, un **remplissage** est généralement nécessaire dans le **dernier bloc** pour compléter sa longueur.\
Généralement, **PKCS7** est utilisé, ce qui génère un remplissage **répétant** le **nombre** d'**octets nécessaires** pour **compléter** le bloc. Par exemple, si le dernier bloc manque 3 octets, le remplissage sera `\x03\x03\x03`.

Regardons d'autres exemples avec **2 blocs de 8 octets de longueur** :

| octet #0 | octet #1 | octet #2 | octet #3 | octet #4 | octet #5 | octet #6 | octet #7 | octet #0  | octet #1  | octet #2  | octet #3  | octet #4  | octet #5  | octet #6  | octet #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Notez comment dans le dernier exemple, le **dernier bloc était plein, donc un autre a été généré uniquement avec un remplissage**.

# Oracle de remplissage

Lorsqu'une application décrypte des données chiffrées, elle décryptera d'abord les données ; puis elle supprimera le remplissage. Pendant le nettoyage du remplissage, si un **remplissage invalide déclenche un comportement détectable**, vous avez une **vulnérabilité d'oracle de remplissage**. Le comportement détectable peut être une **erreur**, un **manque de résultats** ou une **réponse plus lente**.

Si vous détectez ce comportement, vous pouvez **décrypter les données chiffrées** et même **chiffrer n'importe quel texte en clair**.

## Comment exploiter

Vous pouvez utiliser [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) pour exploiter ce type de vulnérabilité ou simplement faire...
```
sudo apt-get install padbuster
```
Pour tester si le cookie d'un site est vulnérable, vous pouvez essayer :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**L'encodage 0** signifie que **base64** est utilisé (mais d'autres sont disponibles, vérifiez le menu d'aide).

Vous pourriez également **exploiter cette vulnérabilité pour chiffrer de nouvelles données. Par exemple, imaginez que le contenu du cookie est "**_**user=MyUsername**_**", vous pouvez le changer en "\_user=administrateur\_" et ainsi obtenir des privilèges élevés dans l'application. Vous pouvez également le faire en utilisant `padbuster` en spécifiant le paramètre -plaintext** :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Si le site est vulnérable, `padbuster`essaiera automatiquement de trouver quand l'erreur de padding se produit, mais vous pouvez également indiquer le message d'erreur en utilisant le paramètre **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La théorie

En résumé, vous pouvez commencer à décrypter les données chiffrées en devinant les valeurs correctes qui peuvent être utilisées pour créer tous les différents paddings. Ensuite, l'attaque de l'oracle de padding commencera à décrypter les octets de la fin vers le début en devinant quelle sera la valeur correcte qui crée un padding de 1, 2, 3, etc.

Imaginez que vous avez un texte chiffré qui occupe 2 blocs formés par les octets de E0 à E15. Pour décrypter le dernier bloc (E8 à E15), tout le bloc passe par le "déchiffrement du chiffrement par bloc" générant les octets intermédiaires I0 à I15. Enfin, chaque octet intermédiaire est XORé avec les octets chiffrés précédents (E0 à E7). Ainsi :

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Maintenant, il est possible de modifier `E7` jusqu'à ce que `C15` soit `0x01`, ce qui sera également un padding correct. Ainsi, dans ce cas : `\x01 = I15 ^ E'7`

Donc, en trouvant E'7, il est possible de calculer I15 : `I15 = 0x01 ^ E'7`

Ce qui nous permet de calculer C15 : `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

En connaissant C15, il est maintenant possible de calculer C14, mais cette fois en forçant le padding `\x02\x02`.

Ce BF est aussi complexe que le précédent car il est possible de calculer le `E''15` dont la valeur est 0x02 : `E''7 = \x02 ^ I15` donc il suffit de trouver le `E'14` qui génère un `C14` égal à `0x02`. Ensuite, effectuez les mêmes étapes pour décrypter C14 : `C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`

Suivez cette chaîne jusqu'à ce que vous ayez décrypté tout le texte chiffré.

## Détection de la vulnérabilité

Enregistrez un compte et connectez-vous avec ce compte. Si vous vous connectez plusieurs fois et que vous obtenez toujours le même cookie, il y a probablement quelque chose qui ne va pas dans l'application. Le cookie renvoyé devrait être unique à chaque fois que vous vous connectez. Si le cookie est toujours le même, il sera probablement toujours valide et il n'y aura aucun moyen de l'invalider.

Maintenant, si vous essayez de modifier le cookie, vous pouvez voir que vous obtenez une erreur de l'application. Mais si vous forcez le padding (en utilisant padbuster par exemple), vous parvenez à obtenir un autre cookie valide pour un utilisateur différent. Ce scénario est très probablement vulnérable à padbuster.

# Références

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
