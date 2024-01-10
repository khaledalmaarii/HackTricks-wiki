# Artéfacts de Navigateur

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) pour construire et **automatiser des workflows** grâce aux outils communautaires **les plus avancés**.\
Accédez-y dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artéfacts des Navigateurs <a href="#id-3def" id="id-3def"></a>

Quand nous parlons d'artéfacts de navigateur, nous faisons référence à l'historique de navigation, aux favoris, à la liste des fichiers téléchargés, aux données en cache, etc.

Ces artéfacts sont des fichiers stockés dans des dossiers spécifiques du système d'exploitation.

Chaque navigateur stocke ses fichiers dans un emplacement différent des autres navigateurs et ils ont tous des noms différents, mais ils stockent tous (la plupart du temps) le même type de données (artéfacts).

Examinons les artéfacts les plus couramment stockés par les navigateurs.

* **Historique de Navigation :** Contient des données sur l'historique de navigation de l'utilisateur. Peut être utilisé pour vérifier si l'utilisateur a visité des sites malveillants par exemple.
* **Données d'Autocomplétion :** Ce sont les données que le navigateur suggère en fonction de ce que vous recherchez le plus. Peut être utilisé en tandem avec l'historique de navigation pour obtenir plus d'informations.
* **Favoris :** Explicite.
* **Extensions et Add-ons :** Explicite.
* **Cache :** Lors de la navigation sur des sites web, le navigateur crée toutes sortes de données en cache (images, fichiers javascript, etc.) pour de nombreuses raisons. Par exemple, pour accélérer le temps de chargement des sites web. Ces fichiers en cache peuvent être une excellente source de données lors d'une enquête forensique.
* **Connexions :** Explicite.
* **Favicons :** Ce sont les petites icônes trouvées dans les onglets, les URL, les favoris, etc. Elles peuvent être utilisées comme une autre source pour obtenir plus d'informations sur le site web ou les endroits visités par l'utilisateur.
* **Sessions de Navigateur :** Explicite.
* **Téléchargements :** Explicite.
* **Données de Formulaire :** Tout ce qui est tapé dans les formulaires est souvent stocké par le navigateur, de sorte que la prochaine fois que l'utilisateur saisit quelque chose dans un formulaire, le navigateur peut suggérer des données précédemment entrées.
* **Miniatures :** Explicite.
* **Custom Dictionary.txt :** Mots ajoutés au dictionnaire par l'utilisateur.

## Firefox

Firefox crée le dossier des profils dans \~/_**.mozilla/firefox/**_ (Linux), dans **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dans ce dossier, le fichier _**profiles.ini**_ devrait apparaître avec le(s) nom(s) du ou des profil(s) utilisateur(s).\
Chaque profil a une variable "**Path**" avec le nom du dossier où ses données vont être stockées. Le dossier devrait être **présent dans le même répertoire où le \_profiles.ini**\_\*\* existe\*\*. S'il ne l'est pas, alors, probablement il a été supprimé.

Dans le dossier **de chaque profil** (_\~/.mozilla/firefox/\<ProfileName>/_) vous devriez pouvoir trouver les fichiers intéressants suivants :

* _**places.sqlite**_ : Historique (moz\_\_places), favoris (moz\_bookmarks), et téléchargements (moz\_\_annos). Sous Windows, l'outil [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé pour lire l'historique dans _**places.sqlite**_.
* Requête pour extraire l'historique : `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Notez qu'un type de lien est un nombre qui indique :
* 1: L'utilisateur a suivi un lien
* 2: L'utilisateur a écrit l'URL
* 3: L'utilisateur a utilisé un favori
* 4: Chargé depuis un Iframe
* 5: Accédé via une redirection HTTP 301
* 6: Accédé via une redirection HTTP 302
* 7: Fichier téléchargé
* 8: L'utilisateur a suivi un lien dans un Iframe
* Requête pour extraire les téléchargements : `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Sauvegardes des favoris
* _**formhistory.sqlite**_ : **Données de formulaire web** (comme les emails)
* _**handlers.json**_ : Gestionnaires de protocole (comme, quelle application va gérer le protocole _mailto://_)
* _**persdict.dat**_ : Mots ajoutés au dictionnaire
* _**addons.json**_ et \_**extensions.sqlite** \_ : Addons et extensions installés
* _**cookies.sqlite**_ : Contient **les cookies.** [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) peut être utilisé sous Windows pour inspecter ce fichier.
*   _**cache2/entries**_ ou _**startupCache**_ : Données en cache (\~350MB). Des astuces comme le **data carving** peuvent également être utilisées pour obtenir les fichiers sauvegardés dans le cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) peut être utilisé pour voir les **fichiers sauvegardés dans le cache**.

Informations qui peuvent être obtenues :

* URL, nombre de récupérations, nom de fichier, type de contenu, taille de fichier, heure de dernière modification, heure de dernière récupération, dernière modification du serveur, réponse du serveur
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Paramètres et préférences
* _**downloads.sqlite**_ : Ancienne base de données de téléchargements (maintenant c'est dans places.sqlite)
* _**thumbnails/**_ : Miniatures
* _**logins.json**_ : Noms d'utilisateur et mots de passe chiffrés
* **Anti-phishing intégré au navigateur :** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Retournera "safebrowsing.malware.enabled" et "phishing.enabled" comme faux si les paramètres de recherche sécurisée ont été désactivés
* _**key4.db**_ ou _**key3.db**_ : Clé principale ?

Pour essayer de décrypter le mot de passe principal, vous pouvez utiliser [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Avec le script suivant et l'appel, vous pouvez spécifier un fichier de mots de passe pour forcer le brute force :

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
```markdown
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome crée le profil dans le répertoire personnel de l'utilisateur _**\~/.config/google-chrome/**_ (Linux), dans _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou dans _**/Users/$USER/Library/Application Support/Google/Chrome/**_ (MacOS).
La plupart des informations seront sauvegardées dans les dossiers _**Default/**_ ou _**ChromeDefaultData/**_ dans les chemins indiqués précédemment. Vous pouvez y trouver les fichiers intéressants suivants :

* _**History**_ : URLs, téléchargements et même mots-clés recherchés. Sous Windows, vous pouvez utiliser l'outil [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) pour lire l'historique. La colonne "Type de Transition" signifie :
  * Link : L'utilisateur a cliqué sur un lien
  * Typed : L'URL a été saisie
  * Auto Bookmark
  * Auto Subframe : Ajout
  * Start page : Page d'accueil
  * Form Submit : Un formulaire a été rempli et envoyé
  * Reloaded
* _**Cookies**_ : Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) peut être utilisé pour inspecter les cookies.
* _**Cache**_ : Cache. Sous Windows, vous pouvez utiliser l'outil [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) pour inspecter le cache.
* _**Bookmarks**_ : Favoris
* _**Web Data**_ : Historique des formulaires
* _**Favicons**_ : Favicons
* _**Login Data**_ : Informations de connexion (noms d'utilisateur, mots de passe...)
* _**Current Session**_ et _**Current Tabs**_ : Données de la session actuelle et onglets actuels
* _**Last Session**_ et _**Last Tabs**_ : Ces fichiers contiennent les sites qui étaient actifs dans le navigateur lorsque Chrome a été fermé pour la dernière fois.
* _**Extensions**_ : Dossier des extensions et addons
* **Thumbnails** : Miniatures
* **Preferences** : Ce fichier contient une multitude de bonnes informations telles que les plugins, les extensions, les sites utilisant la géolocalisation, les popups, les notifications, le préchargement DNS, les exceptions de certificat, et bien plus encore. Si vous essayez de rechercher si un paramètre Chrome spécifique était activé, vous trouverez probablement ce paramètre ici.
* **Protection anti-hameçonnage intégrée au navigateur :** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Vous pouvez simplement rechercher "**safebrowsing**" et chercher `{"enabled: true,"}` dans le résultat pour indiquer que la protection anti-hameçonnage et contre les logiciels malveillants est activée.

## **Récupération de données SQLite DB**

Comme vous pouvez le constater dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer des entrées supprimées en utilisant l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer stocke les **données** et les **métadonnées** dans différents emplacements. Les métadonnées permettront de trouver les données.

Les **métadonnées** peuvent être trouvées dans le dossier `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` où VX peut être V01, V16 ou V24.
Dans le dossier précédent, vous pouvez également trouver le fichier V01.log. Si le **temps modifié** de ce fichier et du fichier WebcacheVX.data **sont différents**, vous devrez peut-être exécuter la commande `esentutl /r V01 /d` pour **corriger** d'éventuelles **incompatibilités**.

Une fois cet artefact **récupéré** (c'est une base de données ESE, photorec peut la récupérer avec les options Exchange Database ou EDB), vous pouvez utiliser le programme [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) pour l'ouvrir. Une fois **ouvert**, allez à la table nommée "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dans cette table, vous pouvez trouver dans quelles autres tables ou conteneurs chaque partie des informations stockées est sauvegardée. En suivant cela, vous pouvez trouver les **emplacements des données** stockées par les navigateurs et les **métadonnées** qui sont à l'intérieur.

**Notez que cette table indique également les métadonnées du cache pour d'autres outils Microsoft (par exemple, skype)**

### Cache

Vous pouvez utiliser l'outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) pour inspecter le cache. Vous devez indiquer le dossier où vous avez extrait les données du cache.

#### Métadonnées

Les informations de métadonnées sur le cache stockent :

* Nom de fichier sur le disque
* SecureDIrectory : Emplacement du fichier dans les répertoires de cache
* AccessCount : Nombre de fois qu'il a été enregistré dans le cache
* URL : L'origine de l'URL
* CreationTime : Première fois qu'il a été mis en cache
* AccessedTime : Moment où le cache a été utilisé
* ModifiedTime : Dernière version de la page Web
* ExpiryTime : Moment où le cache expirera

#### Fichiers

Les informations du cache peuvent être trouvées dans _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ et _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

Les informations à l'intérieur de ces dossiers sont un **instantané de ce que l'utilisateur voyait**. Les caches ont une taille de **250 Mo** et les horodatages indiquent quand la page a été visitée (première fois, date de création du NTFS, dernière fois, heure de modification du NTFS).

### Cookies

Vous pouvez utiliser l'outil [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) pour inspecter les cookies. Vous devez indiquer le dossier où vous avez extrait les cookies.

#### **Métadonnées**

Les informations de métadonnées sur les cookies stockés :

* Nom du cookie dans le système de fichiers
* URL
* AccessCount : Nombre de fois que les cookies ont été envoyés au serveur
* CreationTime : Première fois que le cookie a été créé
* ModifiedTime : Dernière fois que le cookie a été modifié
* AccessedTime : Dernière fois que le cookie a été accédé
* ExpiryTime : Moment d'expiration du cookie

#### Fichiers

Les données des cookies peuvent être trouvées dans _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ et _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Les cookies de session résideront en mémoire et les cookies persistants sur le disque.

### Téléchargements

#### **Métadonnées**

En vérifiant l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), vous pouvez trouver le conteneur avec les métadonnées des téléchargements :

![](<../../../.gitbook/assets/image (445).png>)

En obtenant les informations de la colonne "ResponseHeaders", vous pouvez transformer ces informations hexadécimales et obtenir l'URL, le type de fichier et l'emplacement du fichier téléchargé.

#### Fichiers

Cherchez dans le chemin _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Historique**

L'outil [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé pour lire l'historique. Mais d'abord, vous devez indiquer le navigateur dans les options avancées et l'emplacement des fichiers d'historique extraits.

#### **Métadonnées**

* ModifiedTime : Première fois qu'une URL est trouvée
* AccessedTime : Dernière fois
* AccessCount : Nombre de fois accédé

#### **Fichiers**

Cherchez dans _**%userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ et _**%userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs tapées**

Cette information peut être trouvée dans le registre NTDUSER.DAT dans le chemin :

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Stocke les 50 dernières URLs saisies par l'utilisateur
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* dernière fois que l'URL a été saisie

## Microsoft Edge

Pour analyser les artefacts de Microsoft Edge, toutes les **explications sur le cache et les emplacements de la section précédente (IE 11) restent valables** avec la seule différence que l'emplacement de base, dans ce cas, est _**%userprofile%\Appdata\Local\Packages**_ (comme on peut le voir dans les chemins suivants) :

* Chemin du profil : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC**_
* Historique, Cookies et Téléchargements : _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Paramètres, Favoris et Liste de lecture : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache : _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Dernières sessions actives : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Les bases de données peuvent être trouvées dans `/Users/$User/Library/Safari`

* **History.db** : Les tables `history_visits` _et_ `history_items` contiennent des informations sur l'historique et les horodatages.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist** : Contient les informations sur les fichiers téléchargés.
* **Bookmarks.plist** : URLs des favoris.
* **TopSites.plist** : Liste des sites Web les plus visités que l'utilisateur consulte.
* **Extensions.plist** : Pour récupérer une ancienne liste d'extensions de navigateur Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist** : Domaines autorisés à envoyer des notifications.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist** : Onglets qui étaient ouverts la dernière fois que l'utilisateur a quitté Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Protection anti-hameçonnage intégrée au navigateur :** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* La réponse devrait être 1 pour indiquer que le paramètre est actif

## Opera

Les bases de données peuvent être trouvées dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

Opera **stocke l'historique du navigateur et les données de téléchargement exactement dans le même format que Google Chrome**. Cela s'applique aux noms de fichiers ainsi qu'aux noms des tables.

* **Protection anti-hameçonnage intégrée au navigateur :** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud_protection_enabled** devrait être **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires **les plus avancés**.
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
