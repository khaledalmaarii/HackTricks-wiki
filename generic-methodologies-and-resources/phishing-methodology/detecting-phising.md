# Détection du phishing

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing utilisées de nos jours**. Sur la page parente de ce post, vous pouvez trouver ces informations, donc si vous n'êtes pas au courant des techniques utilisées aujourd'hui, je vous recommande d'aller sur la page parente et de lire au moins cette section.

Ce post est basé sur l'idée que les **attaquants essaieront d'une manière ou d'une autre de mimer ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes victime de phishing en utilisant un nom de domaine complètement différent pour une raison quelconque comme `youwonthelottery.com`, ces techniques ne le découvriront pas.

## Variations de noms de domaine

Il est assez **facile** de **découvrir** ces **tentatives de phishing** qui utiliseront un **nom de domaine similaire** dans l'e-mail.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant pourrait utiliser et de **vérifier** s'ils sont **enregistrés** ou simplement de vérifier s'il y a une **IP** qui l'utilise.

### Recherche de domaines suspects

À cette fin, vous pouvez utiliser l'un des outils suivants. Notez que ces outils effectueront également automatiquement des requêtes DNS pour vérifier si le domaine a une IP qui lui est attribuée :

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Vous pouvez trouver une brève explication de cette technique sur la page parente. Ou lisez la recherche originale sur** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Par exemple, une modification de 1 bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines de bit-flipping que possible liés à la victime pour rediriger les utilisateurs légitimes vers leur infrastructure**.

**Tous les noms de domaine possibles de bit-flipping devraient également être surveillés.**

### Vérifications de base

Une fois que vous avez une liste de noms de domaine suspects potentiels, vous devriez les **vérifier** (principalement les ports HTTP et HTTPS) pour **voir s'ils utilisent un formulaire de connexion similaire** à celui du domaine de la victime.\
Vous pourriez également vérifier le port 3333 pour voir s'il est ouvert et exécute une instance de `gophish`.\
Il est également intéressant de savoir **depuis combien de temps chaque domaine suspect découvert existe**, plus il est récent, plus il est risqué.\
Vous pouvez également obtenir des **captures d'écran** de la page web HTTP et/ou HTTPS suspecte pour voir si elle est suspecte et dans ce cas, **y accéder pour examiner de plus près**.

### Vérifications avancées

Si vous voulez aller plus loin, je vous recommanderais de **surveiller ces domaines suspects et de rechercher plus** de temps en temps (chaque jour ? cela ne prend que quelques secondes/minutes). Vous devriez également **vérifier** les **ports** ouverts des IPs associées et **rechercher des instances de `gophish` ou d'outils similaires** (oui, les attaquants font aussi des erreurs) et **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** pour voir s'ils ont copié un formulaire de connexion des pages web de la victime.\
Pour **automatiser cela**, je recommanderais d'avoir une liste de formulaires de connexion des domaines de la victime, de crawler les pages web suspectes et de comparer chaque formulaire de connexion trouvé à l'intérieur des domaines suspects avec chaque formulaire de connexion du domaine de la victime en utilisant quelque chose comme `ssdeep`.\
Si vous avez localisé les formulaires de connexion des domaines suspects, vous pouvez essayer d'**envoyer des identifiants bidon** et **vérifier s'ils vous redirigent vers le domaine de la victime**.

## Noms de domaine utilisant des mots-clés

La page parente mentionne également une technique de variation de nom de domaine qui consiste à mettre le **nom de domaine de la victime à l'intérieur d'un domaine plus grand** (par exemple, paypal-financial.com pour paypal.com).

### Transparence des certificats

Il n'est pas possible d'adopter l'approche précédente de "Brute-Force", mais il est en fait **possible de découvrir de telles tentatives de phishing** grâce à la transparence des certificats. Chaque fois qu'un certificat est émis par une AC, les détails sont rendus publics. Cela signifie qu'en lisant la transparence des certificats ou même en la surveillant, il est **possible de trouver des domaines qui utilisent un mot-clé dans leur nom**. Par exemple, si un attaquant génère un certificat pour [https://paypal-financial.com](https://paypal-financial.com), en lisant le certificat, il est possible de trouver le mot-clé "paypal" et de savoir qu'un e-mail suspect est utilisé.

Le post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggère que vous pouvez utiliser Censys pour rechercher des certificats affectant un mot-clé spécifique et filtrer par date (uniquement les certificats "nouveaux") et par l'émetteur de CA "Let's Encrypt" :

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1112).png>)

Cependant, vous pouvez faire "la même chose" en utilisant le site web gratuit [**crt.sh**](https://crt.sh). Vous pouvez **rechercher le mot-clé** et **filtrer** les résultats **par date et CA** si vous le souhaitez.

![](<../../.gitbook/assets/image (516).png>)

En utilisant cette dernière option, vous pouvez même utiliser le champ Identités correspondantes pour voir si une identité du domaine réel correspond à l'un des domaines suspects (notez qu'un domaine suspect peut être un faux positif).

**Une autre alternative** est le projet fantastique appelé [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fournit un flux en temps réel des certificats nouvellement générés que vous pouvez utiliser pour détecter des mots-clés spécifiés en (quasi) temps réel. En fait, il existe un projet appelé [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) qui fait exactement cela.
### **Nouveaux domaines**

**Une dernière alternative** est de rassembler une liste de **domaines nouvellement enregistrés** pour certains TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fournit ce service) et **vérifier les mots-clés dans ces domaines**. Cependant, les domaines longs utilisent généralement un ou plusieurs sous-domaines, donc le mot-clé ne sera pas visible à l'intérieur du FLD et vous ne pourrez pas trouver le sous-domaine de phishing.
