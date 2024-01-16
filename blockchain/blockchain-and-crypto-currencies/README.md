<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Terminologie de base

* **Smart contract** : Les smart contracts sont simplement des **programmes stockés sur une blockchain qui s'exécutent lorsque des conditions prédéterminées sont remplies**. Ils sont généralement utilisés pour automatiser l'**exécution** d'un **accord** afin que tous les participants puissent être immédiatement certains du résultat, sans l'intervention d'un intermédiaire ou la perte de temps. (Depuis [ici](https://www.ibm.com/topics/smart-contracts)).
* En gros, un smart contract est un **morceau de code** qui va être exécuté lorsque les gens accèdent et acceptent le contrat. Les smart contracts **s'exécutent dans des blockchains** (donc les résultats sont stockés de manière immuable) et peuvent être lus par les gens avant de les accepter.
* **dApps** : Les **applications décentralisées** sont mises en œuvre sur des **smart contracts**. Elles ont généralement une interface utilisateur où l'utilisateur peut interagir avec l'application, le **back-end** est public (donc il peut être audité) et est implémenté comme un **smart contract**. Parfois, l'utilisation d'une base de données est nécessaire, la blockchain Ethereum alloue un certain stockage à chaque compte.
* **Tokens & coins** : Une **coin** est une cryptomonnaie qui agit comme de l'**argent numérique** et un **token** est quelque chose qui **représente** une **valeur** mais ce n'est pas une coin.
* **Utility Tokens** : Ces tokens permettent à l'utilisateur d'**accéder à un service ultérieurement** (c'est quelque chose qui a de la valeur dans un environnement spécifique).
* **Security Tokens** : Ces tokens représentent la **propriété** ou un actif.
* **DeFi** : **Finance Décentralisée**.
* **DEX** : **Plateformes d'Échange Décentralisées**.
* **DAOs** : **Organisations Autonomes Décentralisées**.

# Mécanismes de Consensus

Pour qu'une transaction blockchain soit reconnue, elle doit être **ajoutée** à la **blockchain**. Les validateurs (mineurs) effectuent cet ajout ; dans la plupart des protocoles, ils **reçoivent une récompense** pour cela. Pour que la blockchain reste sécurisée, elle doit avoir un mécanisme pour **empêcher un utilisateur malveillant ou un groupe de prendre le contrôle de la majorité de la validation**.

Le Proof of Work, un autre mécanisme de consensus couramment utilisé, utilise une validation de la puissance de calcul pour vérifier les transactions, obligeant un attaquant potentiel à acquérir une grande partie de la puissance de calcul du réseau de validateurs.

## Proof Of Work (PoW)

Cela utilise une **validation de la puissance de calcul** pour vérifier les transactions, obligeant un attaquant potentiel à acquérir une grande partie de la puissance de calcul du réseau de validateurs.\
Les **mineurs** vont **sélectionner plusieurs transactions** puis commencer à **calculer le Proof Of Work**. Le **mineur avec les plus grandes ressources de calcul** est plus probable de **terminer** **plus tôt** le Proof Of Work et d'obtenir les frais de toutes les transactions.

## Proof Of Stake (PoS)

Le PoS y parvient en **exigeant que les validateurs possèdent une certaine quantité de tokens de la blockchain**, obligeant les **attaquants potentiels à acquérir une grande partie des tokens** sur la blockchain pour lancer une attaque.\
Dans ce type de consensus, plus un mineur a de tokens, plus il sera probable qu'il sera choisi pour créer le prochain bloc.\
Comparé au PoW, cela réduit considérablement la **consommation d'énergie** que les mineurs dépensent.

# Bitcoin

## Transactions

Une **transaction** simple est un **mouvement d'argent** d'une adresse à une autre.\
Une **adresse** dans Bitcoin est le hash de la **clé publique**, donc, pour effectuer une transaction à partir d'une adresse, il faut connaître la clé privée associée à cette clé publique (l'adresse).\
Ensuite, lorsqu'une **transaction** est effectuée, elle est **signée** avec la clé privée de l'adresse pour montrer que la transaction est **légitime**.

La première partie de la production d'une signature numérique dans Bitcoin peut être représentée mathématiquement de la manière suivante :\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Où :

* \_d\_A est la **clé privée** de signature
* _m_ est la **transaction**
* Fhash est la fonction de hachage
* Fsig est l'algorithme de signature
* Sig est la signature résultante

La fonction de signature (Fsig) produit une signature (Sig) qui comprend deux valeurs : R et S :

* Sig = (R, S)

Une fois R et S calculés, ils sont sérialisés en un flux d'octets qui est encodé en utilisant un schéma d'encodage standard international connu sous le nom de Distinguished Encoding Rules (ou DER). Pour vérifier que la signature est valide, un algorithme de vérification de signature est utilisé. La vérification d'une signature numérique nécessite les éléments suivants :

* Signature (R et S)
* Hash de la transaction
* La clé publique correspondant à la clé privée qui a été utilisée pour créer la signature

La vérification d'une signature signifie effectivement que seul le propriétaire de la clé privée (qui a généré la clé publique) aurait pu produire la signature sur la transaction. L'algorithme de vérification de signature retournera 'TRUE' si la signature est en effet valide.

### Transactions Multisignature

Une **adresse multisignature** est une adresse qui est associée à plus d'une clé privée ECDSA. Le type le plus simple est une adresse m-de-n - elle est associée à n clés privées, et l'envoi de bitcoins depuis cette adresse nécessite des signatures d'au moins m clés. Une **transaction multisignature** est celle qui envoie des fonds depuis une adresse multisignature.

### Champs des Transactions

Chaque transaction Bitcoin a plusieurs champs :

* **Inputs** : La quantité et l'adresse **d'où** les **bitcoins** sont **transférés**
* **Outputs** : L'adresse et les montants qui sont **transférés** à **chaque** **sortie**
* **Fee** : La quantité d'**argent** qui est **payée** au **mineur** de la transaction
* **Script\_sig** : Script signature de la transaction
* **Script\_type** : Type de transaction

Il y a **2 types principaux** de transactions :

* **P2PKH : "Pay To Public Key Hash"** : C'est ainsi que les transactions sont effectuées. Vous exigez du **destinataire** de fournir une **signature valide** (de la clé privée) et une **clé publique**. Le script de sortie de la transaction utilisera la signature et la clé publique et, à travers certaines fonctions cryptographiques, vérifiera **si elle correspond** au hash de la clé publique, si c'est le cas, alors les **fonds** seront **dépensables**. Cette méthode dissimule votre clé publique sous forme de hash pour une sécurité supplémentaire.
* **P2SH : "Pay To Script Hash"** : Les sorties d'une transaction sont juste des **scripts** (cela signifie que la personne qui veut cet argent envoie un script) qui, s'ils sont **exécutés avec des paramètres spécifiques, aboutiront à un booléen de `true` ou `false`**. Si un mineur exécute le script de sortie avec les paramètres fournis et aboutit à `true`, l'**argent sera envoyé à la sortie souhaitée**. `P2SH` est utilisé pour les portefeuilles **multisignature** rendant les scripts de sortie **logique qui vérifie plusieurs signatures avant d'accepter la transaction**. `P2SH` peut également être utilisé pour permettre à quiconque, ou à personne, de dépenser les fonds. Si le script de sortie d'une transaction P2SH est juste `1` pour vrai, alors tenter de dépenser la sortie sans fournir de paramètres résultera juste en `1` rendant l'argent dépensable par quiconque essaie. Cela s'applique également aux scripts qui retournent `0`, rendant la sortie dépensable par personne.

## Lightning Network

Ce protocole aide à **effectuer plusieurs transactions vers un canal** et **à envoyer** seulement **l'état final** à la blockchain pour le sauvegarder.\
Cela **améliore** la **vitesse** de la blockchain Bitcoin (elle ne permet que 7 paiements par seconde) et permet de créer des **transactions plus difficiles à tracer** car le canal est créé via des nœuds de la blockchain Bitcoin :

![](<../../.gitbook/assets/image (611).png>)

L'utilisation normale du Lightning Network consiste à **ouvrir un canal de paiement** en engageant une transaction de financement sur la blockchain de base pertinente (couche 1), suivie par la réalisation d'**un nombre quelconque** de transactions Lightning Network qui mettent à jour la distribution provisoire des fonds du canal **sans les diffuser sur la blockchain**, éventuellement suivie par la fermeture du canal de paiement en **diffusant** la **version finale** de la transaction de règlement pour distribuer les fonds du canal.

Notez que l'un des deux membres du canal peut arrêter et envoyer l'état final du canal à la blockchain à tout moment.

# Attaques sur la Confidentialité de Bitcoin

## Entrée Commune

Théoriquement, les entrées d'une transaction peuvent appartenir à différents utilisateurs, mais en réalité, cela est inhabituel car cela nécessite des étapes supplémentaires. Par conséquent, très souvent, on peut supposer que **2 adresses d'entrée dans la même transaction appartiennent au même propriétaire**.

## Détection d'Adresse de Changement UTXO

**UTXO** signifie **Sorties de Transaction Non Dépensées** (UTXOs). Dans une transaction qui utilise la sortie d'une transaction précédente comme entrée, **toute la sortie doit être dépensée** (pour éviter les attaques de double dépense). Par conséquent, si l'intention était d'**envoyer** juste **une partie** de l'argent de cette sortie à une adresse et de **garder** l'**autre partie**, **2 sorties différentes** apparaîtront : la **destinée** et une **nouvelle adresse de changement aléatoire** où le reste de l'argent sera sauvegardé.

Ensuite, un observateur peut supposer que **la nouvelle adresse de changement générée appartient au propriétaire de l'UTXO**.

## Réseaux Sociaux & Forums

Certaines personnes donnent des informations sur leurs adresses Bitcoin sur différents sites Internet. **Cela rend assez facile d'identifier le propriétaire d'une adresse**.

## Graphes de Transactions

En représentant les transactions dans des graphes, **il est possible de savoir avec une certaine probabilité où l'argent d'un compte a été**. Par conséquent, il est possible de savoir quelque chose sur les **utilisateurs** qui sont **liés** dans la blockchain.

## **Heuristique d'entrée inutile**

Aussi appelée l'"heuristique de changement optimal". Considérez cette transaction Bitcoin. Elle a deux entrées valant 2 BTC et 3 BTC et deux sorties valant 4 BTC et 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
En supposant que l'une des sorties soit la monnaie rendue et l'autre le paiement. Il y a deux interprétations : la sortie de paiement est soit celle de 4 BTC, soit celle de 1 BTC. Mais si la sortie de 1 BTC est le montant du paiement, alors l'entrée de 3 BTC est inutile, car le portefeuille aurait pu dépenser seulement l'entrée de 2 BTC et payer des frais de mineurs moins élevés pour le faire. Cela indique que la véritable sortie de paiement est de 4 BTC et que 1 BTC est la sortie de monnaie rendue.

Ceci est un problème pour les transactions qui ont plus d'une entrée. Une façon de corriger cette fuite est d'ajouter plus d'entrées jusqu'à ce que la sortie de monnaie rendue soit supérieure à n'importe quelle entrée, par exemple :
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Réutilisation forcée d'adresse

La **réutilisation forcée d'adresse** ou **réutilisation d'adresse incitée** se produit lorsqu'un adversaire envoie une petite quantité de bitcoin à des adresses qui ont déjà été utilisées sur la blockchain. L'adversaire espère que les utilisateurs ou leur logiciel de portefeuille **utiliseront les paiements comme entrées pour une transaction plus importante, ce qui révélera d'autres adresses via l'heuristique de propriété d'entrée commune**. Ces paiements peuvent être interprétés comme un moyen de contraindre le propriétaire de l'adresse à réutiliser l'adresse sans le vouloir.

Cette attaque est parfois incorrectement appelée une **attaque de poussière**.

Le comportement correct des portefeuilles est de ne pas dépenser les pièces qui ont atterri sur des adresses déjà utilisées et vides.

## Autres analyses de la Blockchain

* **Montants de paiement exacts** : Pour éviter les transactions avec de la monnaie, le paiement doit être égal à l'UTXO (ce qui est très inattendu). Par conséquent, une **transaction sans adresse de monnaie est probablement un transfert entre 2 adresses du même utilisateur**.
* **Nombres ronds** : Dans une transaction, si l'une des sorties est un **"nombre rond"**, il est très probable que ce soit un **paiement à un humain qui a fixé ce prix "nombre rond"**, donc l'autre partie doit être le reste.
* **Empreinte de portefeuille** : Un analyste attentif peut parfois déduire quel logiciel a créé une certaine transaction, car les **différents logiciels de portefeuille ne créent pas toujours les transactions de la même manière**. L'empreinte de portefeuille peut être utilisée pour détecter les sorties de monnaie, car une sortie de monnaie est celle qui est dépensée avec la même empreinte de portefeuille.
* **Corrélations de montant et de timing** : Si la personne qui a effectué la transaction **divulgue** le **moment** et/ou le **montant** de la transaction, elle peut être facilement **découverte**.

## Analyse du trafic

Une organisation **espionnant votre trafic** peut vous voir communiquer dans le réseau bitcoin.\
Si l'adversaire voit une transaction ou un bloc **sortir de votre nœud qui n'y est pas entré auparavant**, il peut savoir avec quasi-certitude que **la transaction a été faite par vous ou que le bloc a été miné par vous**. Comme des connexions Internet sont impliquées, l'adversaire sera capable de **lier l'adresse IP avec les informations bitcoin découvertes**.

Un attaquant qui n'est pas capable d'espionner tout le trafic Internet mais qui possède **beaucoup de nœuds Bitcoin** afin de rester **plus proche** des **sources** pourrait être capable de connaître l'adresse IP qui annonce des transactions ou des blocs.\
De plus, certains portefeuilles rebroadcastent périodiquement leurs transactions non confirmées afin qu'elles soient plus susceptibles de se propager largement à travers le réseau et d'être minées.

## Autres attaques pour trouver des informations sur le propriétaire d'adresses

Pour plus d'attaques, lire [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anonymes

## Obtenir des Bitcoins de manière anonyme

* **Échanges en espèces** : Acheter du bitcoin en espèces.
* **Substitut d'espèces** : Acheter des cartes-cadeaux ou similaires et les échanger contre des bitcoins en ligne.
* **Minage** : Le minage est le moyen le plus anonyme d'obtenir des bitcoins. Cela s'applique au minage en solo car les [pools de minage](https://en.bitcoin.it/wiki/Pooled\_mining) connaissent généralement l'adresse IP du mineur.
* **Vol** : En théorie, une autre manière d'obtenir des bitcoins anonymement est de les voler.

## Mixeurs

Un utilisateur envoie des bitcoins à un service de mixage et le service renvoie des bitcoins différents à l'utilisateur, moins des frais. En théorie, un adversaire observant la blockchain serait **incapable de lier** les transactions entrantes et sortantes.

Cependant, l'utilisateur doit faire confiance au service de mixage pour retourner les bitcoins et aussi pour ne pas sauvegarder de logs sur les relations entre l'argent reçu et envoyé.\
D'autres services peuvent également être utilisés comme mixeurs, comme les casinos Bitcoin où vous pouvez envoyer des bitcoins et les récupérer plus tard.

## CoinJoin

**CoinJoin** va **mélanger plusieurs transactions de différents utilisateurs en une seule** afin de rendre plus **difficile** pour un observateur de déterminer **quelle entrée est liée à quelle sortie**.\
Cela offre un nouveau niveau de confidentialité, cependant, **certaines** **transactions** où certains montants d'entrée et de sortie sont corrélés ou sont très différents du reste des entrées et sorties **peuvent toujours être corrélés** par l'observateur externe.

Exemples d'identifiants de transactions (probablement) CoinJoin sur la blockchain de bitcoin sont `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` et `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similaire à CoinJoin mais meilleur et pour Ethereum, vous avez** [**Tornado Cash**](https://tornado.cash) **(l'argent provient des mineurs, donc il apparaît juste dans votre portefeuille).**

## PayJoin

Le type de CoinJoin discuté dans la section précédente peut être facilement identifié en vérifiant les multiples sorties de même valeur.

PayJoin (également appelé paiement à destination ou P2EP) est un type spécial de CoinJoin entre deux parties où une partie paie l'autre. La transaction n'a alors **pas les multiples sorties distinctives** de même valeur, et donc n'est pas visiblement identifiable comme un CoinJoin à sorties égales. Considérez cette transaction :
```
2 btc --> 3 btc
5 btc     4 btc
```
```markdown
Il pourrait être interprété comme une simple transaction payant quelque part avec de la monnaie restante (ignorons pour l'instant la question de savoir quel est le paiement de sortie et quel est le changement). Une autre façon d'interpréter cette transaction est que l'entrée de 2 BTC appartient à un commerçant et 5 BTC à leur client, et que cette transaction implique que le client paie 1 BTC au commerçant. Il n'y a aucun moyen de dire laquelle de ces deux interprétations est correcte. Le résultat est une transaction coinjoin qui rompt l'heuristique de propriété d'entrée commune et améliore la confidentialité, mais est également **indétectable et indiscernable de toute transaction bitcoin régulière**.

Si les transactions PayJoin devenaient même modérément utilisées, cela rendrait l'**heuristique de propriété d'entrée commune complètement erronée en pratique**. Comme elles sont indétectables, nous ne saurions même pas si elles sont utilisées aujourd'hui. Comme les entreprises de surveillance des transactions dépendent principalement de cette heuristique, en 2019, il y a un grand enthousiasme pour l'idée PayJoin.

# Bonnes Pratiques de Confidentialité Bitcoin

## Synchronisation de Portefeuille

Les portefeuilles Bitcoin doivent obtenir des informations sur leur solde et leur historique. Fin 2018, les solutions existantes les plus pratiques et privées sont d'utiliser un **portefeuille de nœud complet** (qui est le plus privé) et un **filtrage de bloc côté client** (qui est très bon).

* **Nœud complet :** Les nœuds complets téléchargent l'intégralité de la blockchain qui contient chaque [transaction](https://en.bitcoin.it/wiki/Transaction) sur chaîne qui a jamais eu lieu dans Bitcoin. Ainsi, un adversaire observant la connexion Internet de l'utilisateur ne pourra pas apprendre quelles transactions ou adresses intéressent l'utilisateur.
* **Filtrage de bloc côté client :** Le filtrage de bloc côté client fonctionne en ayant des **filtres** créés qui contiennent toutes les **adresses** pour chaque transaction dans un bloc. Les filtres peuvent tester si un **élément fait partie de l'ensemble** ; des faux positifs sont possibles mais pas des faux négatifs. Un portefeuille léger téléchargerait tous les filtres pour chaque **bloc** dans la **blockchain** et vérifierait les correspondances avec ses **propres** **adresses**. Les blocs contenant des correspondances seraient téléchargés en entier depuis le réseau pair-à-pair, et ces blocs seraient utilisés pour obtenir l'historique et le solde actuel du portefeuille.

## Tor

Le réseau Bitcoin utilise un réseau pair-à-pair, ce qui signifie que d'autres pairs peuvent apprendre votre adresse IP. C'est pourquoi il est recommandé de **se connecter via Tor chaque fois que vous souhaitez interagir avec le réseau Bitcoin**.

## Éviter la réutilisation d'adresses

**L'utilisation d'adresses plus d'une fois est très dommageable pour la confidentialité car cela lie ensemble plus de transactions sur la blockchain avec la preuve qu'elles ont été créées par la même entité**. La manière la plus privée et sécurisée d'utiliser Bitcoin est d'envoyer une **nouvelle adresse à chaque personne qui vous paie**. Après que les pièces reçues aient été dépensées, l'adresse ne devrait plus jamais être utilisée. De plus, une nouvelle adresse Bitcoin devrait être exigée lors de l'envoi de Bitcoin. Tous les bons portefeuilles Bitcoin ont une interface utilisateur qui décourage la réutilisation d'adresses.

## Transactions multiples

**Payer** quelqu'un avec **plus d'une transaction sur chaîne** peut grandement réduire la puissance des attaques de confidentialité basées sur les montants telles que la corrélation des montants et les nombres ronds. Par exemple, si l'utilisateur veut payer 5 BTC à quelqu'un et qu'il ne veut pas que la valeur de 5 BTC soit facilement recherchable, alors il peut envoyer deux transactions pour la valeur de 2 BTC et 3 BTC qui, ensemble, s'additionnent à 5 BTC.

## Évitement de monnaie

L'évitement de monnaie est lorsque les entrées et sorties de transaction sont soigneusement choisies pour ne pas nécessiter de sortie de monnaie du tout. **Ne pas avoir de sortie de monnaie est excellent pour la confidentialité**, car cela rompt les heuristiques de détection de monnaie.

## Sorties de monnaie multiples

Si l'évitement de monnaie n'est pas une option, alors **créer plus d'une sortie de monnaie peut améliorer la confidentialité**. Cela rompt également les heuristiques de détection de monnaie qui supposent généralement qu'il n'y a qu'une seule sortie de monnaie. Comme cette méthode utilise plus d'espace de bloc que d'habitude, l'évitement de monnaie est préférable.

# Monero

Lorsque Monero a été développé, le besoin criant d'**anonymat complet** était ce qu'il cherchait à résoudre, et dans une large mesure, il a comblé ce vide.

# Ethereum

## Gas

Le gas fait référence à l'unité qui mesure la **quantité** d'**effort computationnel** requis pour exécuter des opérations spécifiques sur le réseau Ethereum. Le gas fait référence aux **frais** requis pour mener à bien une **transaction** sur Ethereum.

Les prix du gas sont indiqués en **gwei**, qui est lui-même une dénomination de l'ETH - chaque gwei est égal à **0,000000001 ETH** (10-9 ETH). Par exemple, au lieu de dire que votre gas coûte 0,000000001 ether, vous pouvez dire que votre gas coûte 1 gwei. Le mot 'gwei' signifie lui-même 'giga-wei', et il est égal à **1 000 000 000 wei**. Le wei est lui-même la **plus petite unité de l'ETH**.

Pour calculer le gas qu'une transaction va coûter, lisez cet exemple :

Disons que Jordan doit payer Taylor 1 ETH. Dans la transaction, la limite de gas est de 21 000 unités et les frais de base sont de 100 gwei. Jordan inclut un pourboire de 10 gwei.

En utilisant la formule ci-dessus, nous pouvons calculer cela comme `21 000 * (100 + 10) = 2 310 000 gwei` ou 0,00231 ETH.

Lorsque Jordan envoie l'argent, 1,00231 ETH seront déduits du compte de Jordan. Taylor sera crédité de 1,0000 ETH. Le mineur reçoit le pourboire de 0,00021 ETH. Les frais de base de 0,0021 ETH sont brûlés.

De plus, Jordan peut également fixer des frais maximaux (`maxFeePerGas`) pour la transaction. La différence entre les frais maximaux et les frais réels est remboursée à Jordan, c'est-à-dire `remboursement = frais maximaux - (frais de base + frais de priorité)`. Jordan peut fixer un montant maximum à payer pour l'exécution de la transaction et ne pas s'inquiéter de payer "au-delà" des frais de base lorsque la transaction est exécutée.

Étant donné que les frais de base sont calculés par le réseau en fonction de la demande d'espace de bloc, ce dernier paramètre : maxFeePerGas aide à contrôler les frais maximaux qui vont être payés.

## Transactions

Notez que dans le réseau **Ethereum**, une transaction est effectuée entre 2 adresses et celles-ci peuvent être des **adresses d'utilisateur ou de contrat intelligent**.\
Les **Contrats Intelligents** sont stockés dans le grand livre distribué via une **transaction spéciale**.

Les transactions, qui changent l'état de l'EVM, doivent être diffusées sur l'ensemble du réseau. N'importe quel nœud peut diffuser une demande d'exécution d'une transaction sur l'EVM ; après cela, un **mineur** va **exécuter** la **transaction** et propager le changement d'état résultant au reste du réseau.\
Les transactions nécessitent des **frais** et doivent être minées pour devenir valides.

Une transaction soumise comprend les informations suivantes :

* `recipient` – l'adresse du destinataire (si un compte externe, la transaction transférera de la valeur. Si un compte de contrat, la transaction exécutera le code du contrat)
* `signature` – l'identifiant de l'expéditeur. Cela est généré lorsque la clé privée de l'expéditeur signe la transaction et confirme que l'expéditeur a autorisé cette transaction
* `value` – montant d'ETH à transférer de l'expéditeur au destinataire (en WEI, une dénomination de l'ETH)
* `data` – champ facultatif pour inclure des données arbitraires
* `gasLimit` – la quantité maximale d'unités de gas qui peut être consommée par la transaction. Les unités de gas représentent des étapes computationnelles
* `maxPriorityFeePerGas` - le montant maximum de gas à inclure comme pourboire au mineur
* `maxFeePerGas` - le montant maximum de gas prêt à être payé pour la transaction (y compris `baseFeePerGas` et `maxPriorityFeePerGas`)

Notez qu'il n'y a aucun champ pour l'adresse d'origine, car cela peut être extrapolé de la signature.

# Références

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux repos github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
