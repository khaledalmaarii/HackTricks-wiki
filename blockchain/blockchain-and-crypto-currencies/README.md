<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# Terminologie de base

* **Contrat intelligent** : Les contrats intelligents sont simplement des **programmes stockés sur une blockchain qui s'exécutent lorsque des conditions prédéterminées sont remplies**. Ils sont généralement utilisés pour automatiser l'**exécution** d'un **accord** afin que tous les participants puissent être immédiatement certains du résultat, sans l'intervention d'un intermédiaire ou de perte de temps. (De [ici](https://www.ibm.com/topics/smart-contracts)).
* Fondamentalement, un contrat intelligent est un **morceau de code** qui sera exécuté lorsque les gens accèdent et acceptent le contrat. Les contrats intelligents **s'exécutent dans des blockchains** (donc les résultats sont stockés de manière immuable) et peuvent être lus par les personnes avant de les accepter.
* **dApps** : Les **applications décentralisées** sont mises en œuvre sur des **contrats** **intelligents**. Elles ont généralement une interface utilisateur où l'utilisateur peut interagir avec l'application, le **back-end** est public (donc il peut être audité) et est implémenté sous forme de **contrat intelligent**. Parfois, l'utilisation d'une base de données est nécessaire, la blockchain Ethereum alloue un certain stockage à chaque compte.
* **Jetons & pièces** : Une **pièce** est une cryptomonnaie qui agit comme de l'**argent** **numérique** et un **jeton** est quelque chose qui **représente** une **valeur** mais ce n'est pas une pièce.
* **Jetons d'utilité** : Ces jetons permettent à l'utilisateur d'**accéder à certains services ultérieurement** (c'est quelque chose qui a de la valeur dans un environnement spécifique).
* **Jetons de sécurité** : Ils représentent la **propriété** ou un actif.
* **DeFi** : **Finance décentralisée**.
* **DEX : Plateformes d'échange décentralisées**.
* **DAOs** : **Organisations autonomes décentralisées**.

# Mécanismes de consensus

Pour qu'une transaction blockchain soit reconnue, elle doit être **ajoutée** à la **blockchain**. Les validateurs (mineurs) effectuent cet ajout ; dans la plupart des protocoles, ils **reçoivent une récompense** pour le faire. Pour que la blockchain reste sécurisée, elle doit avoir un mécanisme pour **empêcher un utilisateur ou un groupe malveillant de prendre le contrôle de la majorité de la validation**.

La preuve de travail, un autre mécanisme de consensus couramment utilisé, utilise une validation de la puissance de calcul pour vérifier les transactions, exigeant qu'un attaquant potentiel acquière une grande fraction de la puissance de calcul du réseau de validateurs.

## Preuve de travail (PoW)

Cela utilise une **validation de la puissance de calcul** pour vérifier les transactions, exigeant qu'un attaquant potentiel acquière une grande fraction de la puissance de calcul du réseau de validateurs.\
Les **mineurs** vont **sélectionner plusieurs transactions** puis commencer à **calculer la preuve de travail**. Le **mineur avec les ressources de calcul les plus importantes** a plus de chances de **terminer** plus rapidement la preuve de travail et de recevoir les frais de toutes les transactions.

## Preuve d'enjeu (PoS)

Le PoS réalise cela en **exigeant que les validateurs aient une certaine quantité de jetons blockchain**, obligeant les **attaquants potentiels à acquérir une grande fraction des jetons** sur la blockchain pour lancer une attaque.\
Dans ce type de consensus, plus un mineur a de jetons, plus il est probable que le mineur sera invité à créer le prochain bloc.\
Comparé au PoW, cela a grandement **réduit la consommation d'énergie** que les mineurs dépensent.

# Bitcoin

## Transactions

Une **transaction** simple est un **mouvement d'argent** d'une adresse à une autre.\
Une **adresse** bitcoin est le hachage de la **clé publique**, donc, pour effectuer une transaction à partir d'une adresse, il faut connaître la clé privée associée à cette clé publique (l'adresse).\
Ensuite, lorsqu'une **transaction** est effectuée, elle est **signée** avec la clé privée de l'adresse pour montrer que la transaction est **légitime**.

La première partie de la production d'une signature numérique en Bitcoin peut être représentée mathématiquement de la manière suivante :\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Où :

* \_d\_A est la **clé privée** de signature
* _m_ est la **transaction**
* Fhash est la fonction de hachage
* Fsig est l'algorithme de signature
* Sig est la signature résultante

La fonction de signature (Fsig) produit une signature (Sig) qui comprend deux valeurs : R et S :

* Sig = (R, S)

Une fois que R et S ont été calculés, ils sont sérialisés dans un flux d'octets qui est encodé à l'aide d'un schéma d'encodage standard international appelé Règles d'encodage distinguées (ou DER). Pour vérifier que la signature est valide, un algorithme de vérification de signature est utilisé. La vérification d'une signature numérique nécessite les éléments suivants :

* Signature (R et S)
* Hachage de la transaction
* La clé publique correspondant à la clé privée qui a été utilisée pour créer la signature

La vérification d'une signature signifie effectivement que seul le propriétaire de la clé privée (qui a généré la clé publique) aurait pu produire la signature sur la transaction. L'algorithme de vérification de signature renverra « TRUE » si la signature est effectivement valide.

### Transactions multi-signatures

Une **adresse multi-signatures** est une adresse associée à plus d'une clé privée ECDSA. Le type le plus simple est une adresse m-sur-n - elle est associée à n clés privées, et envoyer des bitcoins depuis cette adresse nécessite des signatures d'au moins m clés. Une **transaction multi-signatures** est une transaction qui envoie des fonds depuis une adresse multi-signatures.

### Champs des transactions

Chaque transaction bitcoin a plusieurs champs :

* **Entrées** : Le montant et l'adresse **de** laquelle les **bitcoins** sont **transférés**
* **Sorties** : L'adresse et les montants qui sont **transférés** à **chaque** **sortie**
* **Frais** : Le montant d'**argent** qui est **payé** au **mineur** de la transaction
* **Script\_sig** : Signature de script de la transaction
* **Script\_type** : Type de transaction

Il existe **2 principaux types** de transactions :

* **P2PKH : "Pay To Public Key Hash"** : C'est ainsi que les transactions sont effectuées. Vous exigez que l'**expéditeur** fournisse une **signature** valide (à partir de la clé privée) et de la **clé** **publique**. Le script de sortie de transaction utilisera la signature et la clé publique et, à travers certaines fonctions cryptographiques, vérifiera **si elle correspond** au hachage de la clé publique, si c'est le cas, alors les **fonds** seront **dépensables**. Cette méthode masque votre clé publique sous forme de hachage pour une sécurité supplémentaire.
* **P2SH : "Pay To Script Hash"** : Les sorties d'une transaction sont simplement des **scripts** (cela signifie que la personne qui souhaite cet argent envoie un script) qui, s'ils sont **exécutés avec des paramètres spécifiques, donneront un booléen de `true` ou `false`**. Si un mineur exécute le script de sortie avec les paramètres fournis et que cela donne `true`, l'**argent sera envoyé à la sortie souhaitée**. `P2SH` est utilisé pour les portefeuilles **multi-signatures** rendant les scripts de sortie **logique qui vérifie plusieurs signatures avant d'accepter la transaction**. `P2SH` peut également être utilisé pour permettre à quiconque, ou à personne, de dépenser les fonds. Si le script de sortie d'une transaction P2SH est simplement `1` pour vrai, alors tenter de dépenser la sortie sans fournir de paramètres donnera simplement `1`, rendant l'argent dépensable par quiconque essaie. Cela s'applique également aux scripts qui renvoient `0`, rendant la sortie dépensable par personne.

## Réseau Lightning

Ce protocole aide à **effectuer plusieurs transactions vers un canal** et à **envoyer** **simplement** **l'état** **final** à la blockchain pour l'enregistrer.\
Cela **améliore** la **vitesse** de la blockchain Bitcoin (elle ne permet que 7 paiements par seconde) et permet de créer des **transactions plus difficiles à tracer** car le canal est créé via des nœuds de la blockchain Bitcoin :

![](<../../.gitbook/assets/image (611).png>)

L'utilisation normale du réseau Lightning consiste à **ouvrir un canal de paiement** en engageant une transaction de financement à la blockchain de base pertinente (couche 1), suivi de la réalisation de **n'importe quel nombre** de transactions du réseau Lightning qui mettent à jour la distribution provisoire des fonds du canal **sans les diffuser à la blockchain**, suivi éventuellement de la fermeture du canal de paiement en **diffusant** la **version finale** de la transaction de règlement pour distribuer les fonds du canal.

Notez que l'un des deux membres du canal peut arrêter et envoyer à tout moment l'état final du canal à la blockchain.

# Attaques de confidentialité Bitcoin

## Entrée commune

Théoriquement, les entrées d'une transaction peuvent appartenir à différents utilisateurs, mais en réalité, c'est inhabituel car cela nécessite des étapes supplémentaires. Par conséquent, il est souvent possible de supposer que **2 adresses d'entrée dans la même transaction appartiennent au même propriétaire**.

## Détection de l'adresse de changement UTXO

**UTXO** signifie **Unspent Transaction Outputs** (UTXOs). Dans une transaction qui utilise la sortie d'une transaction précédente comme entrée, **toute la sortie doit être dépensée** (pour éviter les attaques de double dépense). Par conséquent, si l'intention était d'**envoyer** juste **une partie** de l'argent de cette sortie à une adresse et de **conserver** l'**autre** **partie**, **2 sorties différentes** apparaîtront : celle **prévue** et une **nouvelle adresse de changement aléatoire** où le reste de l'argent sera enregistré.

Ensuite, un observateur peut supposer que **la nouvelle adresse de changement générée appartient au propriétaire de l'UTXO**.

## Réseaux sociaux et forums

Certaines personnes donnent des données sur leurs adresses bitcoin sur différents sites Web sur Internet. **Cela rend assez facile d'identifier le propriétaire d'une adresse**.

## Graphiques de transactions

En représentant les transactions sous forme de graphiques, il est possible de savoir avec une certaine probabilité où l'argent d'un compte a été. Par conséquent, il est possible de savoir quelque chose sur les **utilisateurs** qui sont **liés** dans la blockchain.

## **Heuristique d'entrée inutile**

Aussi appelée "heuristique de changement optimal". Considérez cette transaction bitcoin. Elle a deux entrées valant 2 BTC et 3 BTC et deux sorties valant 4 BTC et 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Supposons qu'une des sorties est le changement et l'autre sortie est le paiement. Il y a deux interprétations : la sortie de paiement est soit la sortie de 4 BTC, soit la sortie de 1 BTC. Mais si la sortie de 1 BTC est le montant du paiement, alors l'entrée de 3 BTC est inutile, car le portefeuille aurait pu dépenser seulement l'entrée de 2 BTC et payer des frais de mineurs moins élevés pour le faire. Cela indique que la vraie sortie de paiement est de 4 BTC et que 1 BTC est la sortie de changement.

Ceci est un problème pour les transactions qui ont plus d'une entrée. Une façon de corriger cette fuite est d'ajouter plus d'entrées jusqu'à ce que la sortie de changement soit supérieure à n'importe quelle entrée, par exemple :
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Réutilisation forcée d'adresse

La **réutilisation forcée d'adresse** ou **réutilisation d'adresse incitative** est lorsque un adversaire paie une petite quantité de bitcoins à des adresses qui ont déjà été utilisées sur la chaîne de blocs. L'adversaire espère que les utilisateurs ou leur logiciel de portefeuille **utiliseront les paiements comme entrées pour une transaction plus importante qui révélera d'autres adresses via l'heuristique de propriété d'entrée commune**. Ces paiements peuvent être compris comme un moyen de contraindre le propriétaire de l'adresse à une réutilisation involontaire de l'adresse.

Cette attaque est parfois incorrectement appelée une **attaque de poussière**.

Le comportement correct des portefeuilles est de ne pas dépenser les pièces qui ont atterri sur des adresses vides déjà utilisées.

## Autres analyses de la blockchain

* **Montants de paiement exacts** : Pour éviter les transactions avec un changement, le paiement doit être égal à l'UTXO (ce qui est très improbable). Par conséquent, une **transaction sans adresse de changement est probablement un transfert entre 2 adresses du même utilisateur**.
* **Nombres ronds** : Dans une transaction, si l'une des sorties est un "**nombre rond**", il est très probable que ce soit un **paiement à un humain qui a fixé ce** "nombre rond" **comme prix**, donc l'autre partie doit être le reste.
* **Empreinte digitale du portefeuille** : Un analyste attentif peut parfois déduire quel logiciel a créé une certaine transaction, car les nombreux **logiciels de portefeuille différents ne créent pas toujours des transactions de la même manière**. L'empreinte digitale du portefeuille peut être utilisée pour détecter les sorties de changement car une sortie de changement est celle dépensée avec la même empreinte digitale du portefeuille.
* **Corrélations de montants et de timing** : Si la personne qui a effectué la transaction **divulgue** l'**heure** et/ou le **montant** de la transaction, cela peut être facilement **découvert**.

## Analyse du trafic

Certaines organisations **espionnant votre trafic** peuvent vous voir communiquer sur le réseau bitcoin.\
Si l'adversaire voit une transaction ou un bloc **sortir de votre nœud sans être entré auparavant**, alors il peut savoir avec quasi-certitude que **la transaction a été effectuée par vous ou que le bloc a été miné par vous**. Comme des connexions Internet sont impliquées, l'adversaire pourra **lier l'adresse IP aux informations bitcoin découvertes**.

Un attaquant qui n'est pas en mesure d'espionner tout le trafic Internet mais qui possède **beaucoup de nœuds Bitcoin** afin de rester **plus proche** des sources pourrait être en mesure de connaître les adresses IP qui annoncent les transactions ou les blocs.\
De plus, certains portefeuilles rebroadcastent périodiquement leurs transactions non confirmées afin qu'elles aient plus de chances de se propager largement à travers le réseau et d'être minées.

## Autres attaques pour trouver des informations sur le propriétaire des adresses

Pour plus d'attaques, consultez [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins anonymes

## Obtenir des Bitcoins de manière anonyme

* **Échanges en espèces** : Acheter des bitcoins en espèces.
* **Substitut d'espèces** : Acheter des cartes-cadeaux ou similaires et les échanger contre des bitcoins en ligne.
* **Minage** : Le minage est le moyen le plus anonyme d'obtenir des bitcoins. Cela s'applique au minage en solo car les [pools de minage](https://en.bitcoin.it/wiki/Pooled\_mining) connaissent généralement l'adresse IP du mineur.
* **Vol** : En théorie, un autre moyen d'obtenir des bitcoins de manière anonyme est de les voler.

## Mélangeurs

Un utilisateur **envoie des bitcoins à un service de mélange** et le service **renvoie des bitcoins différents à l'utilisateur**, moins des frais. En théorie, un adversaire observant la blockchain ne serait **pas en mesure de relier** les transactions entrantes et sortantes.

Cependant, l'utilisateur doit faire confiance au service de mélange pour lui rendre les bitcoins et aussi pour ne pas enregistrer de journaux sur les relations entre l'argent reçu et envoyé.\
D'autres services peuvent également être utilisés comme des mélangeurs, comme les casinos Bitcoin où vous pouvez envoyer des bitcoins et les récupérer plus tard.

## CoinJoin

**CoinJoin** va **mélanger plusieurs transactions de différents utilisateurs en une seule** afin de rendre plus difficile pour un observateur de savoir **quelle entrée est liée à quelle sortie**.\
Cela offre un nouveau niveau de confidentialité, cependant, **certaines** **transactions** où certains montants d'entrée et de sortie sont corrélés ou sont très différents du reste des entrées et sorties **peuvent encore être corrélées** par l'observateur externe.

Des exemples d'identifiants de transactions (probablement) CoinJoin sur la blockchain de Bitcoin sont `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similaire à CoinJoin mais meilleur, pour Ethereum vous avez** [**Tornado Cash**](https://tornado.cash) **(l'argent est donné par les mineurs, donc il apparaît simplement dans votre portefeuille).**

## PayJoin

Le type de CoinJoin discuté dans la section précédente peut être facilement identifié en vérifiant les multiples sorties avec la même valeur.

PayJoin (également appelé pay-to-end-point ou P2EP) est un type spécial de CoinJoin entre deux parties où une partie paie l'autre. La transaction n'a alors pas les multiples sorties distinctives avec la même valeur, et n'est donc pas clairement visible comme un CoinJoin à sortie égale. Considérez cette transaction :
```
2 btc --> 3 btc
5 btc     4 btc
```
Il pourrait être interprété comme une simple transaction payant quelque part avec de la monnaie restante (ignorer pour l'instant la question de savoir quel est le paiement et quel est le reste). Une autre façon d'interpréter cette transaction est que l'entrée de 2 BTC est détenue par un commerçant et 5 BTC est détenue par son client, et que cette transaction implique que le client paie 1 BTC au commerçant. Il n'y a aucun moyen de dire quelle de ces deux interprétations est correcte. Le résultat est une transaction de coinjoin qui casse l'heuristique de propriété d'entrée commune et améliore la confidentialité, mais est également **indétectable et indiscernable de toute transaction bitcoin régulière**.

Si les transactions PayJoin devenaient même modérément utilisées, cela rendrait l'**heuristique de propriété d'entrée commune complètement défectueuse en pratique**. Comme elles sont indétectables, nous ne saurions même pas si elles sont utilisées aujourd'hui. Comme les entreprises de surveillance des transactions dépendent principalement de cette heuristique, en 2019, il y a une grande excitation autour de l'idée de PayJoin.

# Bonnes pratiques de confidentialité Bitcoin

## Synchronisation du portefeuille

Les portefeuilles Bitcoin doivent d'une manière ou d'une autre obtenir des informations sur leur solde et leur historique. À la fin de 2018, les solutions existantes les plus pratiques et privées sont d'utiliser un **portefeuille de nœud complet** (qui est maximale privée) et **le filtrage de bloc côté client** (qui est très bon).

* **Nœud complet :** Les nœuds complets téléchargent l'intégralité de la blockchain qui contient chaque [transaction](https://en.bitcoin.it/wiki/Transaction) sur la blockchain Bitcoin. Ainsi, un adversaire surveillant la connexion Internet de l'utilisateur ne pourra pas savoir quelles transactions ou adresses l'utilisateur s'intéresse.
* **Filtrage de bloc côté client :** Le filtrage de bloc côté client fonctionne en ayant des **filtres** créés qui contiennent toutes les **adresses** pour chaque transaction dans un bloc. Les filtres peuvent tester si un **élément est dans l'ensemble** ; les faux positifs sont possibles mais pas les faux négatifs. Un portefeuille léger **téléchargerait** tous les filtres pour chaque **bloc** dans la **blockchain** et vérifierait les correspondances avec ses **propres** **adresses**. Les blocs contenant des correspondances seraient téléchargés en entier depuis le réseau pair-à-pair, et ces blocs seraient utilisés pour obtenir l'historique et le solde actuel du portefeuille.

## Tor

Le réseau Bitcoin utilise un réseau pair-à-pair, ce qui signifie que d'autres pairs peuvent connaître votre adresse IP. C'est pourquoi il est recommandé de **se connecter via Tor chaque fois que vous souhaitez interagir avec le réseau Bitcoin**.

## Éviter la réutilisation d'adresses

**La réutilisation d'adresses plus d'une fois est très préjudiciable à la confidentialité car cela relie davantage de transactions blockchain avec la preuve qu'elles ont été créées par la même entité**. La manière la plus privée et sécurisée d'utiliser Bitcoin est d'envoyer une **nouvelle adresse à chaque personne qui vous paie**. Après que les pièces reçues ont été dépensées, l'adresse ne doit jamais être réutilisée. De plus, une toute nouvelle adresse Bitcoin doit être demandée lors de l'envoi de Bitcoin. Tous les bons portefeuilles Bitcoin ont une interface utilisateur qui décourage la réutilisation d'adresses.

## Multiples transactions

**Payer** quelqu'un avec **plus d'une transaction sur la blockchain** peut grandement réduire le pouvoir des attaques de confidentialité basées sur le montant telles que la corrélation des montants et les montants ronds. Par exemple, si l'utilisateur veut payer 5 BTC à quelqu'un et ne veut pas que la valeur de 5 BTC soit facilement recherchée, il peut envoyer deux transactions pour une valeur de 2 BTC et 3 BTC qui ensemble totalisent 5 BTC.

## Éviter le rendu de monnaie

Éviter le rendu de monnaie consiste à choisir soigneusement les entrées et les sorties de transaction de manière à ne pas nécessiter du tout de sortie de rendu de monnaie. **Ne pas avoir de sortie de rendu de monnaie est excellent pour la confidentialité**, car cela casse les heuristiques de détection de rendu de monnaie.

## Multiples sorties de rendu de monnaie

Si l'évitement du rendu de monnaie n'est pas une option, **créer plus d'une sortie de rendu de monnaie peut améliorer la confidentialité**. Cela casse également les heuristiques de détection de rendu de monnaie qui supposent généralement qu'il n'y a qu'une seule sortie de rendu de monnaie. Comme cette méthode utilise plus d'espace de bloc que d'habitude, l'évitement du rendu de monnaie est préférable.

# Monero

Lorsque Monero a été développé, le besoin béant d'**anonymat complet** était ce qu'il cherchait à résoudre, et dans une large mesure, il a comblé ce vide.

# Ethereum

## Gas

Le gas fait référence à l'unité qui mesure la **quantité** d'**effort de calcul** nécessaire pour exécuter des opérations spécifiques sur le réseau Ethereum. Le gas fait référence aux **frais** nécessaires pour effectuer avec succès une **transaction** sur Ethereum.

Les prix du gas sont indiqués en **gwei**, qui est lui-même une dénomination de l'ETH - chaque gwei est égal à **0,000000001 ETH** (10-9 ETH). Par exemple, au lieu de dire que votre gas coûte 0,000000001 ether, vous pouvez dire que votre gas coûte 1 gwei. Le mot 'gwei' lui-même signifie 'giga-wei', et il est égal à **1 000 000 000 wei**. Wei lui-même est la **plus petite unité d'ETH**.

Pour calculer le gas qu'une transaction va coûter, lisez cet exemple :

Disons que Jordan doit payer 1 ETH à Taylor. Dans la transaction, la limite de gas est de 21 000 unités et le frais de base est de 100 gwei. Jordan inclut un pourboire de 10 gwei.

En utilisant la formule ci-dessus, nous pouvons calculer cela comme `21 000 * (100 + 10) = 2 310 000 gwei` ou 0,00231 ETH.

Lorsque Jordan envoie l'argent, 1,00231 ETH sera déduit du compte de Jordan. Taylor sera crédité de 1,0000 ETH. Le mineur reçoit le pourboire de 0,00021 ETH. Le frais de base de 0,0021 ETH est brûlé.

De plus, Jordan peut également définir un frais max (`maxFeePerGas`) pour la transaction. La différence entre le frais max et le frais réel est remboursée à Jordan, c'est-à-dire `remboursement = frais max - (frais de base + frais de priorité)`. Jordan peut définir un montant maximum à payer pour que la transaction s'exécute et ne pas s'inquiéter de payer en trop "au-delà" du frais de base lorsque la transaction est exécutée.

Comme le frais de base est calculé par le réseau en fonction de la demande d'espace de bloc, ce dernier paramètre : maxFeePerGas aide à contrôler le frais maximum qui va être payé.

## Transactions

Remarquez que dans le réseau **Ethereum**, une transaction est effectuée entre 2 adresses et celles-ci peuvent être des **adresses d'utilisateur ou de contrat intelligent**.\
Les **Contrats Intelligents** sont stockés dans le grand livre distribué via une **transaction spéciale**.

Les transactions, qui modifient l'état de l'EVM, doivent être diffusées à l'ensemble du réseau. N'importe quel nœud peut diffuser une demande pour qu'une transaction soit exécutée sur l'EVM ; après cela, un **mineur** exécutera la **transaction** et propagera le changement d'état résultant au reste du réseau.\
Les transactions nécessitent des **frais** et doivent être minées pour devenir valides.

Une transaction soumise comprend les informations suivantes :

* `destinataire` – l'adresse de réception (si un compte détenu par un utilisateur, la transaction transférera de la valeur. Si un compte de contrat, la transaction exécutera le code du contrat)
* `signature` – l'identifiant de l'expéditeur. Cela est généré lorsque la clé privée de l'expéditeur signe la transaction et confirme que l'expéditeur a autorisé cette transaction
* `valeur` – montant d'ETH à transférer de l'expéditeur au destinataire (en WEI, une dénomination de l'ETH)
* `données` – champ facultatif pour inclure des données arbitraires
* `gasLimit` – la quantité maximale d'unités de gas qui peuvent être consommées par la transaction. Les unités de gas représentent des étapes de calcul
* `maxPriorityFeePerGas` - la quantité maximale de gas à inclure en tant que pourboire au mineur
* `maxFeePerGas` - la quantité maximale de gas prête à être payée pour la transaction (incluant `baseFeePerGas` et `maxPriorityFeePerGas`)

Notez qu'il n'y a pas de champ pour l'adresse d'origine, car celle-ci peut être extrapolée à partir de la signature.

# Références

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
