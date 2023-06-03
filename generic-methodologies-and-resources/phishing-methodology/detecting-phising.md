# Détection de phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing qui sont utilisées de nos jours**. Sur la page parente de ce post, vous pouvez trouver cette information, donc si vous n'êtes pas au courant des techniques qui sont utilisées aujourd'hui, je vous recommande d'aller sur la page parente et de lire au moins cette section.

Ce post est basé sur l'idée que les **attaquants essaieront de quelque manière que ce soit de mimer ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes victime d'un phishing en utilisant un nom de domaine complètement différent pour une raison quelconque comme `youwonthelottery.com`, ces techniques ne le découvriront pas.

## Variations de noms de domaine

Il est assez **facile** de **découvrir** ces tentatives de **phishing** qui utiliseront un **nom de domaine similaire** à l'intérieur de l'e-mail.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant peut utiliser et de **vérifier** s'il est **enregistré** ou simplement de vérifier s'il y a une **IP** qui l'utilise.

### Trouver des domaines suspects

À cette fin, vous pouvez utiliser l'un des outils suivants. Notez que ces outils effectueront également des requêtes DNS automatiquement pour vérifier si le domaine a une adresse IP qui lui est assignée :

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

Dans le monde de l'informatique, tout est stocké en bits (zéros et uns) en mémoire en arrière-plan.\
Cela s'applique également aux domaines. Par exemple, _windows.com_ devient _01110111..._ dans la mémoire volatile de votre appareil informatique.\
Cependant, que se passe-t-il si l'un de ces bits est automatiquement inversé en raison d'une éruption solaire, de rayons cosmiques ou d'une erreur matérielle ? C'est-à-dire qu'un des 0 devient un 1 et vice versa.\
En appliquant ce concept aux requêtes DNS, il est possible que le **domaine demandé** qui arrive au serveur DNS **ne soit pas le même que le domaine initialement demandé**.

Par exemple, une modification de 1 bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines de basculement de bits que possible liés à la victime pour rediriger les utilisateurs légitimes vers leur infrastructure**.

Pour plus d'informations, consultez [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**Tous les noms de domaine de basculement de bits possibles doivent également être surveillés.**

### Vérifications de base

Une fois que vous avez une liste de noms de domaine suspects potentiels, vous devriez les **vérifier** (principalement les ports HTTP et HTTPS) pour **voir s'ils utilisent un formulaire de connexion similaire** à celui de la victime.\
Vous pouvez également vérifier le port 3333 pour voir s'il est ouvert et s'il exécute une instance de `gophish`.\
Il est également intéressant de savoir **depuis combien de temps chaque domaine suspect découvert existe**, plus il est jeune, plus il est risqué.\
Vous pouvez également obtenir des **captures d'écran** de la page web HTTP et/ou HTTPS suspecte pour voir si elle est suspecte et dans ce cas, **y accéder pour approfondir**.

### Vérifications avancées

Si vous voulez aller plus loin, je vous recommande de **surveiller ces domaines suspects et de rechercher plus** une fois de temps
