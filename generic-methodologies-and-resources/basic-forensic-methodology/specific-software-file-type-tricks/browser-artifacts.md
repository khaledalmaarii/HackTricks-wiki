# Artéfacts du navigateur

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts) pour construire et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

## Artéfacts des navigateurs <a href="#id-3def" id="id-3def"></a>

Les artéfacts des navigateurs incluent divers types de données stockées par les navigateurs Web, tels que l'historique de navigation, les favoris et les données de cache. Ces artéfacts sont conservés dans des dossiers spécifiques du système d'exploitation, différant en emplacement et en nom selon les navigateurs, mais stockant généralement des types de données similaires.

Voici un résumé des artéfacts de navigateur les plus courants :

* **Historique de navigation** : Suit les visites des utilisateurs sur les sites Web, utile pour identifier les visites sur des sites malveillants.
* **Données d'autocomplétion** : Suggestions basées sur des recherches fréquentes, offrant des informations lorsqu'elles sont combinées avec l'historique de navigation.
* **Favoris** : Sites enregistrés par l'utilisateur pour un accès rapide.
* **Extensions et modules complémentaires** : Extensions de navigateur ou modules complémentaires installés par l'utilisateur.
* **Cache** : Stocke le contenu Web (par exemple, images, fichiers JavaScript) pour améliorer les temps de chargement du site, précieux pour l'analyse forensique.
* **Connexions** : Identifiants de connexion enregistrés.
* **Favicons** : Icônes associées aux sites Web, apparaissant dans les onglets et les favoris, utiles pour obtenir des informations supplémentaires sur les visites des utilisateurs.
* **Sessions de navigateur** : Données relatives aux sessions de navigateur ouvertes.
* **Téléchargements** : Enregistrements des fichiers téléchargés via le navigateur.
* **Données de formulaire** : Informations saisies dans les formulaires Web, enregistrées pour des suggestions de remplissage automatique ultérieures.
* **Miniatures** : Images de prévisualisation des sites Web.
* **Dictionnaire personnalisé.txt** : Mots ajoutés par l'utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur dans des profils, stockés à des emplacements spécifiques en fonction du système d'exploitation :

* **Linux** : `~/.mozilla/firefox/`
* **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` dans ces répertoires répertorie les profils utilisateur. Les données de chaque profil sont stockées dans un dossier nommé d'après la variable `Path` dans `profiles.ini`, situé dans le même répertoire que `profiles.ini` lui-même. Si un dossier de profil est manquant, il a peut-être été supprimé.

Dans chaque dossier de profil, vous pouvez trouver plusieurs fichiers importants :

* **places.sqlite** : Stocke l'historique, les favoris et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) sur Windows peuvent accéder aux données d'historique.
* Utilisez des requêtes SQL spécifiques pour extraire les informations d'historique et de téléchargements.
* **bookmarkbackups** : Contient des sauvegardes de favoris.
* **formhistory.sqlite** : Stocke les données de formulaire Web.
* **handlers.json** : Gère les gestionnaires de protocole.
* **persdict.dat** : Mots du dictionnaire personnalisé.
* **addons.json** et **extensions.sqlite** : Informations sur les modules complémentaires et extensions installés.
* **cookies.sqlite** : Stockage des cookies, avec [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible pour inspection sur Windows.
* **cache2/entries** ou **startupCache** : Données de cache, accessibles via des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite** : Stocke les favicons.
* **prefs.js** : Paramètres et préférences utilisateur.
* **downloads.sqlite** : Ancienne base de données de téléchargements, désormais intégrée à places.sqlite.
* **miniatures** : Miniatures de sites Web.
* **logins.json** : Informations de connexion chiffrées.
* **key4.db** ou **key3.db** : Stocke les clés de chiffrement pour sécuriser les informations sensibles.

De plus, vérifier les paramètres anti-hameçonnage du navigateur peut se faire en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, indiquant si les fonctionnalités de navigation sécurisée sont activées ou désactivées.

Pour essayer de décrypter le mot de passe principal, vous pouvez utiliser [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Avec le script et l'appel suivants, vous pouvez spécifier un fichier de mot de passe pour la force brute :

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chrome stocke les profils d'utilisateurs dans des emplacements spécifiques en fonction du système d'exploitation :

* **Linux** : `~/.config/google-chrome/`
* **Windows** : `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS** : `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur peuvent être trouvées dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données significatives :

* **Historique** : Contient des URL, des téléchargements et des mots-clés de recherche. Sur Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) peut être utilisé pour lire l'historique. La colonne "Type de transition" a diverses significations, y compris les clics des utilisateurs sur des liens, les URL saisies, les soumissions de formulaires et les rechargements de pages.
* **Cookies** : Stocke les cookies. Pour l'inspection, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) est disponible.
* **Cache** : Contient des données mises en cache. Pour l'inspection, les utilisateurs de Windows peuvent utiliser [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
* **Signets** : Signets de l'utilisateur.
* **Données Web** : Contient l'historique des formulaires.
* **Favicons** : Stocke les favicons des sites web.
* **Données de connexion** : Inclut les informations de connexion telles que les noms d'utilisateur et les mots de passe.
* **Session actuelle**/**Onglets actuels** : Données sur la session de navigation actuelle et les onglets ouverts.
* **Dernière session**/**Derniers onglets** : Informations sur les sites actifs lors de la dernière session avant la fermeture de Chrome.
* **Extensions** : Répertoires pour les extensions et les modules complémentaires du navigateur.
* **Miniatures** : Stocke les miniatures des sites web.
* **Préférences** : Un fichier riche en informations, comprenant des paramètres pour les plugins, les extensions, les pop-ups, les notifications, et plus encore.
* **Anti-hameçonnage intégré du navigateur** : Pour vérifier si la protection contre le hameçonnage et les logiciels malveillants est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.

## **Récupération de données de base de données SQLite**

Comme vous pouvez l'observer dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer des entrées supprimées en utilisant l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à travers différents emplacements, facilitant la séparation des informations stockées et de leurs détails correspondants pour un accès et une gestion faciles.

### Stockage des métadonnées

Les métadonnées d'Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (avec VX étant V01, V16 ou V24). En complément, le fichier `V01.log` peut montrer des divergences de temps de modification avec `WebcacheVX.data`, indiquant un besoin de réparation en utilisant `esentutl /r V01 /d`. Ces métadonnées, hébergées dans une base de données ESE, peuvent être récupérées et inspectées à l'aide d'outils tels que photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), respectivement. Dans la table **Containers**, on peut discerner les tables ou conteneurs spécifiques où chaque segment de données est stocké, y compris les détails du cache pour d'autres outils Microsoft tels que Skype.

### Inspection du cache

L'outil [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) permet d'inspecter le cache, en nécessitant l'emplacement du dossier d'extraction des données de cache. Les métadonnées du cache incluent le nom de fichier, le répertoire, le nombre d'accès, l'origine de l'URL, et les horodatages indiquant les temps de création, d'accès, de modification et d'expiration du cache.

### Gestion des cookies

Les cookies peuvent être explorés en utilisant [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), avec des métadonnées comprenant des noms, des URLs, des comptes d'accès, et divers détails liés au temps. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles via [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), avec des conteneurs spécifiques contenant des données telles que l'URL, le type de fichier, et l'emplacement de téléchargement. Les fichiers physiques peuvent être trouvés sous `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour examiner l'historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) peut être utilisé, nécessitant l'emplacement des fichiers d'historique extraits et la configuration pour Internet Explorer. Les métadonnées incluent ici les temps de modification et d'accès, ainsi que les comptes d'accès. Les fichiers d'historique sont situés dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs saisies

Les URLs saisies et leurs horaires d'utilisation sont stockés dans le registre sous `NTUSER.DAT` à `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`, suivant les 50 dernières URLs saisies par l'utilisateur et leurs derniers horaires d'entrée.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins pour différents types de données sont :

* **Chemin du profil** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **Historique, Cookies et Téléchargements** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Paramètres, Signets et Liste de lecture** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Dernières sessions actives** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées à `/Users/$User/Library/Safari`. Les fichiers clés incluent :

* **History.db** : Contient les tables `history_visits` et `history_items` avec des URLs et des horodatages de visite. Utilisez `sqlite3` pour interroger.
* **Downloads.plist** : Informations sur les fichiers téléchargés.
* **Bookmarks.plist** : Stocke les URLs des signets.
* **TopSites.plist** : Sites les plus visités.
* **Extensions.plist** : Liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour récupérer.
* **UserNotificationPermissions.plist** : Domaines autorisés à envoyer des notifications push. Utilisez `plutil` pour analyser.
* **LastSession.plist** : Onglets de la dernière session. Utilisez `plutil` pour analyser.
* **Anti-hameçonnage intégré du navigateur** : Vérifiez en utilisant `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse de 1 indique que la fonctionnalité est active.

## Opera

Les données d'Opera résident dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera` et partagent le format de Chrome pour l'historique et les téléchargements.

* **Anti-hameçonnage intégré du navigateur** : Vérifiez si `fraud_protection_enabled` dans le fichier Preferences est défini sur `true` en utilisant `grep`.

Ces chemins et commandes sont cruciaux pour accéder et comprendre les données de navigation stockées par différents navigateurs web.

## Références

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Livre : OS X Incident Response: Scripting and Analysis By Jaron Bradley page 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
