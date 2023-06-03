<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Terminologie de base

* **Smart contract**: Les smart contracts sont simplement des **programmes stockés sur une blockchain qui s'exécutent lorsque des conditions prédéterminées sont remplies**. Ils sont généralement utilisés pour automatiser l'**exécution** d'un **accord** afin que tous les participants puissent être immédiatement certains du résultat, sans l'intervention ou la perte de temps d'un intermédiaire. (De [ici](https://www.ibm.com/topics/smart-contracts)).
  * En gros, un smart contract est un **morceau de code** qui sera exécuté lorsque les gens accèdent et acceptent le contrat. Les smart contracts **s'exécutent dans les blockchains** (donc les résultats sont stockés de manière immuable) et peuvent être lus par les gens avant de les accepter.
* **dApps**: Les **applications décentralisées** sont implémentées sur le dessus des **smart contracts**. Elles ont généralement une interface utilisateur où l'utilisateur peut interagir avec l'application, le **back-end** est public (afin qu'il puisse être audité) et est implémenté sous forme de **smart contract**. Parfois, l'utilisation d'une base de données est nécessaire, la blockchain Ethereum alloue un certain stockage à chaque compte.
* **Tokens & coins**: Une **coin** est une crypto-monnaie qui agit comme de l'**argent numérique** et un **token** est quelque chose qui **représente** une certaine **valeur** mais ce n'est pas une pièce de monnaie.
  * **Tokens utilitaires**: Ces tokens permettent à l'utilisateur d'**accéder à certains services plus tard** (c'est quelque chose qui a une certaine valeur dans un environnement spécifique).
  * **Tokens de sécurité**: Ils représentent la **propriété** ou un actif.
* **DeFi**: **Finance décentralisée**.
* **DEX: Plateformes d'échange décentralisées**.
* **DAOs**: **Organisations autonomes décentralisées**.

# Mécanismes de consensus

Pour qu'une transaction de blockchain soit reconnue, elle doit être **ajoutée** à la **blockchain**. Les validateurs (mineurs) effectuent cet ajout ; dans la plupart des protocoles, ils **reçoivent une récompense** pour le faire. Pour que la blockchain reste sécurisée, elle doit avoir un mécanisme pour **empêcher un utilisateur ou un groupe malveillant de prendre le contrôle de la majorité de la validation**.

La preuve de travail, un autre mécanisme de consensus couramment utilisé, utilise une validation de la puissance de calcul pour vérifier les transactions, exigeant qu'un attaquant potentiel acquière une grande fraction de la puissance de calcul du réseau de validation.

## Preuve de travail (PoW)

Cela utilise une **validation de la puissance de calcul** pour vérifier les transactions, exigeant qu'un attaquant potentiel acquière une grande fraction de la puissance de calcul du réseau de validation.\
Les **mineurs** vont **sélectionner plusieurs transactions** et commencer à **calculer la preuve de travail**. Le **mineur avec les plus grandes ressources de calcul** est plus susceptible de **terminer plus tôt** la preuve de travail et d'obtenir les frais de toutes les transactions.

## Preuve d'enjeu (PoS)

PoS y parvient en **exigeant que les validateurs aient une certaine quantité de jetons de blockchain**, exigeant que **les attaquants potentiels acquièrent une grande fraction des jetons** sur la blockchain pour monter une attaque.\
Dans ce type de consensus, plus un mineur a de jetons, plus il est probable qu'il sera invité à créer le prochain bloc.\
Comparé à PoW, cela a considérablement **réduit la consommation d'énergie** que les mineurs dépensent.

# Bitcoin

## Transactions

Une **transaction** simple est un **mouvement d'argent** d'une adresse à une autre.\
Une **adresse** en bitcoin est le hachage de la **clé publique**, donc, pour qu'une transaction soit effectuée, il faut connaître la clé privée associée à cette clé publique (l'adresse).\
Ensuite, lorsqu'une **transaction** est effectuée, elle est **signée** avec la clé privée de l'adresse pour montrer que la transaction est **légitime**.

La première partie de la production d'une signature numérique en Bitcoin peut être représentée mathématiquement de la manière suivante :\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Où :

* \_d\_
## Détection d'adresse de changement UTXO

**UTXO** signifie **Unspent Transaction Outputs** (sorties de transaction non dépensées). Dans une transaction qui utilise la sortie d'une transaction précédente en tant qu'entrée, **toute la sortie doit être dépensée** (pour éviter les attaques de double dépense). Par conséquent, si l'intention était de **envoyer** seulement **une partie** de l'argent de cette sortie à une adresse et de **garder** l'**autre** **partie**, **2 sorties différentes** apparaîtront : celle **prévue** et une **nouvelle adresse de changement aléatoire** où le reste de l'argent sera enregistré.

Ensuite, un observateur peut supposer que **la nouvelle adresse de changement générée appartient au propriétaire de l'UTXO**.

## Réseaux sociaux et forums

Certaines personnes donnent des données sur leurs adresses bitcoin sur différents sites web sur Internet. **Cela rend assez facile l'identification du propriétaire d'une adresse**.

## Graphes de transaction

En représentant les transactions sous forme de graphes, il est possible de savoir avec une certaine probabilité où l'argent d'un compte se trouvait. Par conséquent, il est possible de savoir quelque chose sur les **utilisateurs** qui sont **liés** dans la blockchain.

## **Heuristique d'entrée inutile**

Aussi appelée "heuristique de changement optimal". Considérez cette transaction bitcoin. Elle a deux entrées valant 2 BTC et 3 BTC et deux sorties valant 4 BTC et 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
En supposant qu'une des sorties est le changement et l'autre sortie est le paiement. Il y a deux interprétations : la sortie de paiement est soit la sortie de 4 BTC, soit la sortie de 1 BTC. Mais si la sortie de 1 BTC est le montant du paiement, alors l'entrée de 3 BTC est inutile, car le portefeuille aurait pu dépenser seulement l'entrée de 2 BTC et payer des frais de transaction plus bas pour le faire. Cela indique que la véritable sortie de paiement est de 4 BTC et que 1 BTC est la sortie de changement.

Ceci est un problème pour les transactions qui ont plus d'une entrée. Une façon de corriger cette fuite est d'ajouter plus d'entrées jusqu'à ce que la sortie de changement soit supérieure à toute entrée, par exemple :
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Réutilisation forcée d'adresse

La **réutilisation forcée d'adresse** ou **réutilisation d'adresse incitative** est lorsque l'attaquant paie une petite somme de bitcoins à des adresses qui ont déjà été utilisées sur la chaîne de blocs. L'attaquant espère que les utilisateurs ou leur logiciel de portefeuille **utiliseront les paiements comme entrées pour une transaction plus importante qui révélera d'autres adresses via l'heuristique de propriété d'entrée commune**. Ces paiements peuvent être compris comme un moyen de contraindre le propriétaire de l'adresse à une réutilisation involontaire d'adresse.

Cette attaque est parfois incorrectement appelée une **attaque de poussière**.

Le comportement correct des portefeuilles est de ne pas dépenser les pièces qui ont atterri sur des adresses vides déjà utilisées.

## Autres analyses de blockchain

* **Montants de paiement exacts**: Pour éviter les transactions avec un changement, le paiement doit être égal à l'UTXO (ce qui est très improbable). Par conséquent, une **transaction sans adresse de changement est probablement un transfert entre 2 adresses du même utilisateur**.
* **Nombres ronds**: Dans une transaction, si l'une des sorties est un "**nombre rond**", il est très probable que ce soit un **paiement à un humain qui a mis ce** "nombre rond" **de prix**, donc l'autre partie doit être le reste.
* **Empreinte de portefeuille:** Un analyste attentif peut parfois déduire quel logiciel a créé une certaine transaction, car les **différents logiciels de portefeuille ne créent pas toujours des transactions exactement de la même manière**. L'empreinte de portefeuille peut être utilisée pour détecter les sorties de changement car une sortie de changement est celle dépensée avec la même empreinte de portefeuille.
* **Corrélations de montants et de temps**: Si la personne qui a effectué la transaction **divulgue** l'**heure** et/ou le **montant** de la transaction, cela peut être facilement **découvert**.

## Analyse de trafic

Certaines organisations qui **espionnent votre trafic** peuvent voir que vous communiquez dans le réseau Bitcoin.\
Si l'attaquant voit une transaction ou un bloc **sortir de votre nœud qui n'est pas entré auparavant**, il peut savoir avec une quasi-certitude que **la transaction a été effectuée par vous ou que le bloc a été miné par vous**. Comme les connexions Internet sont impliquées, l'attaquant pourra **lier l'adresse IP aux informations Bitcoin découvertes**.

Un attaquant qui n'est pas en mesure d'espionner tout le trafic Internet mais qui a **beaucoup de nœuds Bitcoin** pour rester **plus proche** des sources pourrait être en mesure de connaître les adresses IP qui annoncent des transactions ou des blocs.\
De plus, certains portefeuilles rebroadcastent périodiquement leurs transactions non confirmées afin qu'elles se propagent plus largement dans le réseau et soient exploitées.

## Autres attaques pour trouver des informations sur le propriétaire des adresses

Pour plus d'attaques, lire [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins anonymes

## Obtenir des Bitcoins anonymement

* **Transactions en espèces:** Acheter des bitcoins en espèces.
* **Substitut d'espèces:** Acheter des cartes-cadeaux ou similaires et les échanger contre des bitcoins en ligne.
* **Minage:** Le minage est le moyen le plus anonyme d'obtenir des bitcoins. Cela s'applique au minage en solo car les [pools de minage](https://en.bitcoin.it/wiki/Pooled\_mining) connaissent généralement l'adresse IP du hacheur.
* **Vol:** En théorie, une autre façon d'obtenir des bitcoins anonymes est de les voler.

## Mélangeurs

Un utilisateur **enverrait des bitcoins à un service de mélange** et le service **enverrait des bitcoins différents à l'utilisateur**, moins des frais. En théorie, un adversaire observant la blockchain serait **incapable de lier** les transactions entrantes et sortantes.

Cependant, l'utilisateur doit faire confiance au service de mélange pour retourner les bitcoins et aussi pour ne pas enregistrer de journaux sur les relations entre l'argent reçu et envoyé.\
D'autres services peuvent également être utilisés comme mélangeurs, comme les casinos Bitcoin où vous pouvez envoyer des bitcoins et les récupérer plus tard.

## CoinJoin

**CoinJoin** va **mélanger plusieurs transactions de différents utilisateurs en une seule** afin de rendre plus **difficile** pour un observateur de trouver **quelle entrée est liée à quelle sortie**.\
Cela offre un nouveau niveau de confidentialité, cependant, **certaines** **transactions** où certains montants d'entrée et de sortie sont corrélés ou sont très différents du reste des entrées et sorties **peuvent encore être corrélées** par l'observateur externe.

Des exemples d'identifiants de transactions CoinJoin (probables) sur la blockchain de Bitcoin sont `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similaire à CoinJoin mais mieux et pour Ethereum, vous avez** [**Tornado Cash**](https://tornado.cash) **(l'argent est donné par les mineurs, donc il apparaît simplement dans votre portefeuille).**

## PayJoin

Le type de CoinJoin discuté dans la section précédente peut être facilement identifié comme tel en vérifiant les sorties multiples avec la même valeur.

PayJoin (également appelé pay-to-end-point ou P2EP) est un type spécial de CoinJoin entre deux parties où une partie paie l'autre. La transaction **n'a alors pas les sorties multiples distinctives** avec la même valeur, et donc n'est pas clairement visible comme un CoinJoin à sortie égale. Considérez cette transaction:
```
2 btc --> 3 btc
5 btc     4 btc
```
Il est possible d'interpréter cette transaction comme une simple transaction payant quelque part avec de la monnaie restante (ignorons pour l'instant la question de savoir quelle sortie est un paiement et laquelle est un changement). Une autre façon d'interpréter cette transaction est que les 2 BTC en entrée appartiennent à un marchand et que les 5 BTC appartiennent à leur client, et que cette transaction implique que le client paie 1 BTC au marchand. Il n'y a aucun moyen de dire quelle de ces deux interprétations est correcte. Le résultat est une transaction de coinjoin qui rompt l'heuristique de propriété d'entrée commune et améliore la confidentialité, mais qui est également **indétectable et indiscernable de toute transaction bitcoin régulière**.

Si les transactions PayJoin devenaient même modérément utilisées, cela rendrait l'heuristique de propriété d'entrée commune complètement défectueuse en pratique. Comme elles sont indétectables, nous ne saurions même pas si elles sont utilisées aujourd'hui. Comme les entreprises de surveillance de transactions dépendent principalement de cette heuristique, depuis 2019, il y a une grande excitation autour de l'idée de PayJoin.

# Bonnes pratiques de confidentialité Bitcoin

## Synchronisation de portefeuille

Les portefeuilles Bitcoin doivent obtenir des informations sur leur solde et leur historique. À la fin de 2018, les solutions les plus pratiques et les plus privées existantes sont d'utiliser un **portefeuille de nœud complet** (qui est maximale privé) et un **filtrage de bloc côté client** (qui est très bon).

* **Nœud complet :** Les nœuds complets téléchargent l'intégralité de la blockchain qui contient toutes les [transactions](https://en.bitcoin.it/wiki/Transaction) sur la chaîne de blocs qui ont jamais eu lieu dans Bitcoin. Ainsi, un adversaire qui surveille la connexion Internet de l'utilisateur ne pourra pas savoir quelles transactions ou adresses l'utilisateur recherche.
* **Filtrage de bloc côté client :** Le filtrage de bloc côté client fonctionne en créant des **filtres** qui contiennent toutes les **adresses** pour chaque transaction dans un bloc. Les filtres peuvent tester si un **élément est dans l'ensemble** ; les faux positifs sont possibles mais pas les faux négatifs. Un portefeuille léger **téléchargerait** tous les filtres pour chaque **bloc** dans la **blockchain** et vérifierait les correspondances avec ses propres **adresses**. Les blocs qui contiennent des correspondances seraient téléchargés en entier depuis le réseau pair-à-pair, et ces blocs seraient utilisés pour obtenir l'historique et le solde actuel du portefeuille.

## Tor

Le réseau Bitcoin utilise un réseau pair-à-pair, ce qui signifie que d'autres pairs peuvent apprendre votre adresse IP. C'est pourquoi il est recommandé de **se connecter via Tor chaque fois que vous voulez interagir avec le réseau Bitcoin**.

## Éviter la réutilisation d'adresses

**La réutilisation d'adresses est très dommageable pour la confidentialité car cela relie plus de transactions blockchain avec la preuve qu'elles ont été créées par la même entité**. La façon la plus privée et la plus sûre d'utiliser Bitcoin est d'envoyer une **nouvelle adresse à chaque personne qui vous paie**. Après que les pièces reçues ont été dépensées, l'adresse ne doit jamais être réutilisée. De plus, une nouvelle adresse Bitcoin doit être demandée lors de l'envoi de Bitcoin. Tous les bons portefeuilles Bitcoin ont une interface utilisateur qui décourage la réutilisation d'adresses.

## Transactions multiples

**Payer** quelqu'un avec **plus d'une transaction sur la chaîne de blocs** peut grandement réduire la puissance des attaques de confidentialité basées sur le montant, telles que la corrélation des montants et les nombres ronds. Par exemple, si l'utilisateur veut payer 5 BTC à quelqu'un et qu'il ne veut pas que la valeur de 5 BTC soit facilement recherchée, il peut envoyer deux transactions pour la valeur de 2 BTC et 3 BTC qui ensemble s'élèvent à 5 BTC.

## Éviter le changement

L'évitement du changement consiste à choisir soigneusement les entrées et les sorties de transaction pour ne pas nécessiter de sortie de changement du tout. **Ne pas avoir de sortie de changement est excellent pour la confidentialité**, car cela rompt les heuristiques de détection de changement.

## Sorties de changement multiples

Si l'évitement du changement n'est pas une option, **la création de plus d'une sortie de changement peut améliorer la confidentialité**. Cela rompt également les heuristiques de détection de changement qui supposent généralement qu'il n'y a qu'une seule sortie de changement. Comme cette méthode utilise plus d'espace de bloc que d'habitude, l'évitement du changement est préférable.

# Monero

Lorsque Monero a été développé, le besoin béant d'**anonymat complet** était ce qu'il cherchait à résoudre, et dans une large mesure, il a comblé ce vide.

# Ethereum

## Gaz

Le gaz fait référence à l'unité qui mesure la **quantité d'effort de calcul** requise pour exécuter des opérations spécifiques sur le réseau Ethereum. Le gaz fait référence aux **frais** requis pour effectuer avec succès une **transaction** sur Ethereum.

Les prix du gaz sont exprimés en **gwei**, qui est lui-même une dénomination d'ETH - chaque gwei est égal à **0,000000001 ETH** (10-9 ETH). Par exemple, au lieu de dire que votre gaz coûte 0,000000001 ether, vous pouvez dire que votre gaz coûte 1 gwei. Le mot 'gwei' lui-même signifie 'giga-wei', et il est égal à **1 000 000 000 wei**. Wei lui-même est la **plus petite unité d'ETH**.

Pour calculer le gaz qu'une transaction va coûter, lisez cet exemple :

Supposons que Jordan doit payer à Taylor 1 ETH. Dans la transaction, la limite de gaz est de 21 000 unités et le tarif de base est de 100 gwei. Jordan inclut un pourboire de 10 gwei.

En utilisant la formule ci-dessus, nous pouvons calculer cela comme `21 000 * (100 + 10) = 2 310 000 gwei` ou 0,00231 ETH.

Lorsque Jordan envoie l'argent, 1,00231 ETH seront déduits du compte de Jordan. Taylor sera crédité de 1,0000 ETH. Le mineur reçoit le pourboire de 0,00021 ETH. Les frais de base de 0
