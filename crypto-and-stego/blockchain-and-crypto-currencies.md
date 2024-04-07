<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


## Concepts de base

- Les **Contrats Intelligents** sont définis comme des programmes qui s'exécutent sur une blockchain lorsque certaines conditions sont remplies, automatisant l'exécution d'accords sans intermédiaires.
- Les **Applications Décentralisées (dApps)** s'appuient sur des contrats intelligents, offrant une interface conviviale pour les utilisateurs et un backend transparent et auditable.
- Les **Jetons & Pièces** se différencient où les pièces servent de monnaie numérique, tandis que les jetons représentent une valeur ou une propriété dans des contextes spécifiques.
- Les **Jetons d'Utilité** donnent accès à des services, et les **Jetons de Sécurité** signifient la propriété d'actifs.
- **DeFi** signifie Finance Décentralisée, offrant des services financiers sans autorités centrales.
- **DEX** et **DAOs** font référence aux Plateformes d'Échange Décentralisées et aux Organisations Autonomes Décentralisées, respectivement.

## Mécanismes de consensus

Les mécanismes de consensus garantissent des validations de transactions sécurisées et acceptées sur la blockchain :
- **Preuve de Travail (PoW)** repose sur la puissance de calcul pour la vérification des transactions.
- **Preuve d'Enjeu (PoS)** exige que les validateurs détiennent un certain montant de jetons, réduisant la consommation d'énergie par rapport au PoW.

## Principes essentiels du Bitcoin

### Transactions

Les transactions Bitcoin impliquent le transfert de fonds entre des adresses. Les transactions sont validées par des signatures numériques, garantissant que seul le propriétaire de la clé privée peut initier des transferts.

#### Composants clés :

- Les **Transactions Multisignatures** nécessitent plusieurs signatures pour autoriser une transaction.
- Les transactions se composent de **inputs** (source des fonds), **outputs** (destination), **frais** (payés aux mineurs) et **scripts** (règles de transaction).

### Réseau Lightning

Vise à améliorer la scalabilité du Bitcoin en permettant de multiples transactions dans un canal, ne diffusant que l'état final à la blockchain.

## Préoccupations concernant la confidentialité du Bitcoin

Les attaques de confidentialité, telles que la **Propriété Commune des Inputs** et la **Détection de l'Adresse de Changement UTXO**, exploitent les schémas de transaction. Des stratégies comme les **Mélangeurs** et **CoinJoin** améliorent l'anonymat en obscurcissant les liens de transaction entre les utilisateurs.

## Acquisition de Bitcoins de manière anonyme

Les méthodes incluent les échanges en espèces, le minage et l'utilisation de mélangeurs. **CoinJoin** mélange plusieurs transactions pour compliquer la traçabilité, tandis que **PayJoin** déguise les CoinJoins en transactions régulières pour une confidentialité accrue.


# Attaques de confidentialité du Bitcoin

# Résumé des attaques de confidentialité du Bitcoin

Dans le monde du Bitcoin, la confidentialité des transactions et l'anonymat des utilisateurs sont souvent des sujets de préoccupation. Voici un aperçu simplifié de plusieurs méthodes courantes par lesquelles les attaquants peuvent compromettre la confidentialité du Bitcoin.

## **Hypothèse de Propriété Commune des Inputs**

Il est généralement rare que les inputs de différents utilisateurs soient combinés dans une seule transaction en raison de la complexité impliquée. Ainsi, **deux adresses d'input dans la même transaction sont souvent supposées appartenir au même propriétaire**.

## **Détection de l'Adresse de Changement UTXO**

Un UTXO, ou **Unspent Transaction Output**, doit être entièrement dépensé dans une transaction. Si seule une partie est envoyée à une autre adresse, le reste va à une nouvelle adresse de changement. Les observateurs peuvent supposer que cette nouvelle adresse appartient à l'expéditeur, compromettant la confidentialité.

### Exemple
Pour atténuer cela, les services de mélange ou l'utilisation de plusieurs adresses peuvent aider à obscurcir la propriété.

## **Exposition sur les Réseaux Sociaux & Forums**

Les utilisateurs partagent parfois leurs adresses Bitcoin en ligne, facilitant la **corrélation de l'adresse avec son propriétaire**.

## **Analyse du Graphique de Transactions**

Les transactions peuvent être visualisées sous forme de graphiques, révélant des connexions potentielles entre les utilisateurs en fonction du flux de fonds.

## **Heuristique d'Input Inutile (Heuristique de Changement Optimal)**

Cette heuristique repose sur l'analyse des transactions avec plusieurs inputs et outputs pour deviner quel output est le changement retournant à l'expéditeur.

### Exemple
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si l'ajout de plus d'entrées rend la sortie du changement plus grande que n'importe quelle entrée unique, cela peut perturber l'heuristique.

## **Réutilisation Forcée d'Adresse**

Les attaquants peuvent envoyer de petites sommes à des adresses déjà utilisées, espérant que le destinataire les combine avec d'autres entrées dans des transactions futures, liant ainsi les adresses entre elles.

### Comportement Correct du Portefeuille
Les portefeuilles doivent éviter d'utiliser des pièces reçues sur des adresses déjà utilisées et vides pour éviter cette fuite de confidentialité.

## **Autres Techniques d'Analyse de Blockchain**

- **Montants de Paiement Exact:** Les transactions sans changement sont probablement entre deux adresses appartenant au même utilisateur.
- **Nombres Ronds:** Un nombre rond dans une transaction suggère un paiement, le montant non rond étant probablement le changement.
- **Empreinte de Portefeuille:** Différents portefeuilles ont des schémas uniques de création de transactions, permettant aux analystes d'identifier le logiciel utilisé et potentiellement l'adresse de changement.
- **Corrélations de Montant et de Timing:** La divulgation des heures ou des montants de transaction peut rendre les transactions traçables.

## **Analyse de Trafic**

En surveillant le trafic réseau, les attaquants peuvent potentiellement relier des transactions ou des blocs à des adresses IP, compromettant la confidentialité de l'utilisateur. Cela est particulièrement vrai si une entité exploite de nombreux nœuds Bitcoin, améliorant leur capacité à surveiller les transactions.

## Plus
Pour une liste complète des attaques et défenses de confidentialité, visitez [Bitcoin Privacy sur Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Transactions Bitcoin Anonymes

## Moyens d'Obtenir des Bitcoins Anonymement

- **Transactions en Espèces**: Acquérir des bitcoins en espèces.
- **Alternatives en Espèces**: Acheter des cartes-cadeaux et les échanger en ligne contre des bitcoins.
- **Minage**: La méthode la plus privée pour gagner des bitcoins est le minage, surtout lorsqu'il est effectué seul car les pools de minage peuvent connaître l'adresse IP du mineur. [Informations sur les Pools de Minage](https://en.bitcoin.it/wiki/Pooled_mining)
- **Vol**: Théoriquement, voler des bitcoins pourrait être un autre moyen de les acquérir de manière anonyme, bien que ce soit illégal et non recommandé.

## Services de Mélange

En utilisant un service de mélange, un utilisateur peut **envoyer des bitcoins** et recevoir **des bitcoins différents en retour**, ce qui rend difficile le traçage du propriétaire d'origine. Cependant, cela nécessite de faire confiance au service pour ne pas conserver de journaux et pour restituer effectivement les bitcoins. Les options de mélange alternatives incluent les casinos Bitcoin.

## CoinJoin

**CoinJoin** fusionne plusieurs transactions de différents utilisateurs en une seule, compliquant le processus pour quiconque essaie de faire correspondre les entrées avec les sorties. Malgré son efficacité, les transactions avec des tailles d'entrée et de sortie uniques peuvent encore potentiellement être traçables.

Des transactions d'exemple qui ont peut-être utilisé CoinJoin incluent `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Pour plus d'informations, visitez [CoinJoin](https://coinjoin.io/en). Pour un service similaire sur Ethereum, consultez [Tornado Cash](https://tornado.cash), qui anonymise les transactions avec des fonds provenant des mineurs.

## PayJoin

Une variante de CoinJoin, **PayJoin** (ou P2EP), déguise la transaction entre deux parties (par exemple, un client et un commerçant) comme une transaction normale, sans les sorties égales caractéristiques de CoinJoin. Cela le rend extrêmement difficile à détecter et pourrait invalider l'heuristique de propriété d'entrée commune utilisée par les entités de surveillance des transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Les transactions comme celle ci-dessus pourraient être des PayJoin, améliorant la confidentialité tout en restant indiscernables des transactions standard de Bitcoin.

**L'utilisation de PayJoin pourrait perturber significativement les méthodes de surveillance traditionnelles**, en faisant un développement prometteur dans la quête de la confidentialité des transactions.


# Meilleures pratiques pour la confidentialité dans les cryptomonnaies

## **Techniques de synchronisation de portefeuille**

Pour maintenir la confidentialité et la sécurité, la synchronisation des portefeuilles avec la blockchain est cruciale. Deux méthodes se distinguent :

- **Nœud complet** : En téléchargeant l'intégralité de la blockchain, un nœud complet garantit une confidentialité maximale. Toutes les transactions jamais effectuées sont stockées localement, rendant impossible pour les adversaires d'identifier quelles transactions ou adresses l'utilisateur est intéressé.
- **Filtrage de bloc côté client** : Cette méthode implique la création de filtres pour chaque bloc de la blockchain, permettant aux portefeuilles d'identifier les transactions pertinentes sans exposer des intérêts spécifiques aux observateurs du réseau. Les portefeuilles légers téléchargent ces filtres, ne récupérant que les blocs complets lorsqu'une correspondance avec les adresses de l'utilisateur est trouvée.

## **Utilisation de Tor pour l'anonymat**

Étant donné que Bitcoin fonctionne sur un réseau pair-à-pair, l'utilisation de Tor est recommandée pour masquer votre adresse IP, améliorant la confidentialité lors de l'interaction avec le réseau.

## **Prévention de la réutilisation d'adresse**

Pour protéger la confidentialité, il est vital d'utiliser une nouvelle adresse pour chaque transaction. La réutilisation d'adresses peut compromettre la confidentialité en reliant les transactions à la même entité. Les portefeuilles modernes découragent la réutilisation d'adresses par leur conception.

## **Stratégies pour la confidentialité des transactions**

- **Multiples transactions** : Diviser un paiement en plusieurs transactions peut obscurcir le montant de la transaction, contrecarrant les attaques contre la confidentialité.
- **Éviter le rendu de monnaie** : Opter pour des transactions ne nécessitant pas de rendu de monnaie améliore la confidentialité en perturbant les méthodes de détection de rendu de monnaie.
- **Multiples rendus de monnaie** : Si éviter le rendu de monnaie n'est pas possible, générer plusieurs rendus de monnaie peut quand même améliorer la confidentialité.

# **Monero : Un phare de l'anonymat**

Monero répond au besoin d'anonymat absolu dans les transactions numériques, établissant une norme élevée pour la confidentialité.

# **Ethereum : Gaz et Transactions**

## **Compréhension du gaz**

Le gaz mesure l'effort de calcul nécessaire pour exécuter des opérations sur Ethereum, tarifé en **gwei**. Par exemple, une transaction coûtant 2 310 000 gwei (ou 0,00231 ETH) implique une limite de gaz et des frais de base, avec un pourboire pour inciter les mineurs. Les utilisateurs peuvent définir un frais maximal pour s'assurer de ne pas payer en excès, l'excédent étant remboursé.

## **Exécution des transactions**

Les transactions sur Ethereum impliquent un expéditeur et un destinataire, qui peuvent être des adresses d'utilisateur ou de contrat intelligent. Elles nécessitent des frais et doivent être minées. Les informations essentielles dans une transaction incluent le destinataire, la signature de l'expéditeur, la valeur, des données optionnelles, la limite de gaz et les frais. Notamment, l'adresse de l'expéditeur est déduite de la signature, éliminant ainsi le besoin de l'inclure dans les données de la transaction.

Ces pratiques et mécanismes sont fondamentaux pour quiconque souhaite s'engager avec les cryptomonnaies tout en priorisant la confidentialité et la sécurité.


## Références

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le groupe Discord](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
