# Artéfacts du navigateur

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser des flux de travail** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez un accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artéfacts des navigateurs <a href="#3def" id="3def"></a>

Lorsque nous parlons des artéfacts des navigateurs, nous parlons de l'historique de navigation, des favoris, de la liste des fichiers téléchargés, des données de cache, etc.

Ces artéfacts sont des fichiers stockés dans des dossiers spécifiques du système d'exploitation.

Chaque navigateur stocke ses fichiers à un endroit différent des autres navigateurs et ils ont tous des noms différents, mais ils stockent tous (la plupart du temps) le même type de données (artéfacts).

Jetons un coup d'œil aux artéfacts les plus courants stockés par les navigateurs.

* **Historique de navigation :** Contient des données sur l'historique de navigation de l'utilisateur. Peut être utilisé pour retracer si l'utilisateur a visité des sites malveillants, par exemple.
* **Données d'autocomplétion :** Ce sont les données que le navigateur suggère en fonction de ce que vous recherchez le plus. Peut être utilisé en tandem avec l'historique de navigation pour obtenir plus d'informations.
* **Favoris :** Auto-explicatif.
* **Extensions et modules complémentaires :** Auto-explicatif.
* **Cache :** Lors de la navigation sur des sites Web, le navigateur crée toutes sortes de données de cache (images, fichiers JavaScript, etc.) pour de nombreuses raisons. Par exemple, pour accélérer le temps de chargement des sites Web. Ces fichiers de cache peuvent être une excellente source de données lors d'une enquête forensique.
* **Connexions :** Auto-explicatif.
* **Favicons :** Ce sont les petites icônes que l'on trouve dans les onglets, les URL, les favoris, etc. Ils peuvent être utilisés comme une autre source pour obtenir plus d'informations sur le site Web ou les endroits visités par l'utilisateur.
* **Sessions du navigateur :** Auto-explicatif.
* **Téléchargements :** Auto-explicatif.
* **Données de formulaire :** Tout ce qui est saisi dans les formulaires est souvent stocké par le navigateur, afin que la prochaine fois que l'utilisateur saisisse quelque chose dans un formulaire, le navigateur puisse suggérer les données précédemment saisies.
* **Miniatures :** Auto-explicatif.
* **Custom Dictionary.txt :** Mots ajoutés au dictionnaire par l'utilisateur.

## Firefox

Firefox crée le dossier des profils dans \~/_**.mozilla/firefox/**_ (Linux), dans **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
À l'intérieur de ce dossier, le fichier _**profiles.ini**_ devrait apparaître avec le(s) nom(s) du(des) profil(s) utilisateur(s).\
Chaque profil a une variable "**Path**" avec le nom du dossier où ses données vont être stockées. Le dossier devrait être **présent dans le même répertoire que le \_profiles.ini**\_\*\* existe\*\*. S'il ne l'est pas, alors il a probablement été supprimé.

À l'intérieur du dossier **de chaque profil** (_\~/.mozilla/firefox/\<NomDuProfil>/_), vous devriez pouvoir trouver les fichiers intéressants suivants :

* _**places.sqlite**_ : Historique (moz\_\_places), favoris (moz\_bookmarks) et téléchargements (moz\_\_annos). Sous Windows, l'outil [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) peut être utilisé pour lire l'historique à l'intérieur de _**places.sqlite**_.
* Requête pour extraire l'historique : `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Notez qu'un type de lien est un nombre qui indique :
* 1 : L'utilisateur a suivi un lien
* 2 : L'utilisateur a saisi l'URL
* 3 : L'utilisateur a utilisé un favori
* 4 : Chargé depuis un iframe
* 5 : Accédé via une redirection HTTP 301
* 6 : Accédé via une redirection HTTP 302
* 7 : Fichier téléchargé
* 8 : L'utilisateur a suivi un lien à l'intérieur d'un iframe
* Requête pour extraire les téléchargements : `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Sauvegardes des favoris
* _**formhistory.sqlite**_ : **Données de formulaire Web** (comme les e-mails)
* _**handlers.json**_ : Gestionnaires de protocole (par exemple, quelle application va gérer le protocole _mailto://_)
* _**persdict.dat**_ : Mots ajoutés au dictionnaire
* _**addons.json**_ et \_**extensions.sqlite** \_ : Modules complémentaires et extensions installés
* _**cookies.sqlite**_ : Contient les **cookies**. [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) peut être utilisé sous Windows pour inspecter ce fichier.
*   _**cache2/entries**_ ou _**startupCache**_ : Données de cache (\~350 Mo). Des astuces comme **l'extraction de données** peuvent également être utilisées pour obtenir les fichiers enregistrés dans le cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) peut être utilisé pour voir les **fichiers enregistrés dans le cache**.

Informations pouvant être obtenues :

* URL, nombre de récupérations, nom de fichier, type de contenu, taille du fichier, heure de dernière modification, heure de dernière récupération, dernière modification du serveur, réponse du serveur
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Paramètres et préférences
* _**downloads.sqlite**_ : Ancienne base de données de téléchargements (maintenant elle se trouve dans places.sqlite)
* _**thumbnails/**_ : Miniatures
* _**logins.json**_ : Noms d'utilisateur et mots de passe chiffrés
* **Anti-phishing intégré au navigateur :** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Renvoie "safebrowsing.malware.enabled" et "phishing.enabled" comme faux si les paramètres de recherche sécurisée ont été désactivés
* _**key4.db**_ ou _**key3.db**_ : Clé maîtresse ?

Pour essayer de décrypter le mot de passe maître, vous pouvez utiliser [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Avec le script et l'appel suivants, vous pouvez spécifier un fichier de mots de passe à forcer :

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

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome crée le profil à l'intérieur du répertoire de l'utilisateur _**\~/.config/google-chrome/**_ (Linux), dans _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou dans \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
La plupart des informations seront enregistrées dans les dossiers _**Default/**_ ou _**ChromeDefaultData/**_ dans les chemins indiqués précédemment. Vous pouvez y trouver les fichiers intéressants suivants :

* _**History**_ : URLs, téléchargements et même mots-clés recherchés. Sous Windows, vous pouvez utiliser l'outil [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) pour lire l'historique. La colonne "Transition Type" signifie :
* Link : L'utilisateur a cliqué sur un lien
* Typed : L'URL a été saisie
* Auto Bookmark
* Auto Subframe : Ajouter
* Start page : Page d'accueil
* Form Submit : Un formulaire a été rempli et envoyé
* Reloaded
* _**Cookies**_ : Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) peut être utilisé pour inspecter les cookies.
* _**Cache**_ : Cache. Sous Windows, vous pouvez utiliser l'outil [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) pour inspecter le cache.
* _**Bookmarks**_ : Signets
* _**Web Data**_ : Historique des formulaires
* _**Favicons**_ : Favicons
* _**Login Data**_ : Informations de connexion (noms d'utilisateur, mots de passe...)
* _**Current Session**_ et _**Current Tabs**_ : Données de session en cours et onglets en cours
* _**Last Session**_ et _**Last Tabs**_ : Ces fichiers contiennent les sites qui étaient actifs dans le navigateur lorsque Chrome a été fermé pour la dernière fois.
* _**Extensions**_ : Dossier des extensions et des modules complémentaires
* **Thumbnails** : Miniatures
* **Preferences** : Ce fichier contient une multitude d'informations utiles telles que les plugins, les extensions, les sites utilisant la géolocalisation, les popups, les notifications, le prefetching DNS, les exceptions de certificat, et bien plus encore. Si vous essayez de savoir si un paramètre spécifique de Chrome était activé ou non, vous le trouverez probablement ici.
* **Anti-phishing intégré au navigateur** : `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Vous pouvez simplement utiliser la commande grep pour rechercher "safebrowsing" et rechercher `{"enabled: true,"}` dans le résultat pour indiquer que la protection anti-phishing et anti-malware est activée.

## Récupération des données de la base de données SQLite

Comme vous pouvez le constater dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer les entrées supprimées à l'aide de l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## Internet Explorer 11

Internet Explorer stocke les **données** et les **métadonnées** dans différents emplacements. Les métadonnées permettront de trouver les données.

Les **métadonnées** peuvent être trouvées dans le dossier `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` où VX peut être V01, V16 ou V24.\
Dans le dossier précédent, vous pouvez également trouver le fichier V01.log. Si l'heure de modification de ce fichier et du fichier WebcacheVX.data est différente, vous devrez peut-être exécuter la commande `esentutl /r V01 /d` pour **corriger** les éventuelles **incompatibilités**.

Une fois cet artefact récupéré (il s'agit d'une base de données ESE, photorec peut la récupérer avec les options Base de données Exchange ou EDB), vous pouvez utiliser le programme [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) pour l'ouvrir. Une fois ouvert, accédez à la table intitulée "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dans cette table, vous pouvez trouver dans quelles autres tables ou conteneurs chaque partie des informations stockées est enregistrée. En suivant cela, vous pouvez trouver les **emplacements des données** stockées par les navigateurs et les **métadonnées** qui s'y trouvent.

**Notez que cette table indique également les métadonnées du cache pour d'autres outils Microsoft (par exemple, Skype)**

### Cache

Vous pouvez utiliser l'outil [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) pour inspecter le cache. Vous devez indiquer le dossier où vous avez extrait les données du cache.

#### Métadonnées

Les informations métadonnées sur le cache stockent :

* Nom de fichier sur le disque
* SecureDIrectory : Emplacement du fichier dans les répertoires de cache
* AccessCount : Nombre de fois où il a été enregistré dans le cache
* URL : L'URL d'origine
* CreationTime : Première fois où il a été mis en cache
* AccessedTime : Heure à laquelle le cache a été utilisé
* ModifiedTime : Dernière version de la page web
* ExpiryTime : Heure à laquelle le cache expirera

#### Fichiers

Les informations de cache peuvent être trouvées dans _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ et _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

Les informations à l'intérieur de ces dossiers sont une **capture instantanée de ce que l'utilisateur voyait**. Les caches ont une taille de **250 Mo** et les horodatages indiquent quand la page a été visitée (première fois, date de création du NTFS, dernière fois, heure de modification du NTFS).

### Cookies

Vous pouvez utiliser l'outil [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) pour inspecter les cookies. Vous devez indiquer le dossier où vous avez extrait les cookies.

#### Métadonnées

Les informations métadonnées sur les cookies stockées :

* Nom du cookie dans le système de fichiers
* URL
* AccessCount : Nombre de fois que les cookies ont été envoyés au serveur
* CreationTime : Première fois que le cookie a été créé
* ModifiedTime : Dernière fois que le cookie a été modifié
* AccessedTime : Dernière fois que le cookie a été consulté
* ExpiryTime : Heure d'expiration du cookie

#### Fichiers

Les données des cookies peuvent être trouvées dans _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ et _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Les cookies de session résident en mémoire et les cookies persistants sur le disque.
### Téléchargements

#### **Métadonnées**

En vérifiant l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), vous pouvez trouver le conteneur avec les métadonnées des téléchargements :

![](<../../../.gitbook/assets/image (445).png>)

En obtenant les informations de la colonne "ResponseHeaders", vous pouvez convertir ces informations depuis l'hexadécimal et obtenir l'URL, le type de fichier et l'emplacement du fichier téléchargé.

#### Fichiers

Recherchez dans le chemin _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Historique**

L'outil [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) peut être utilisé pour lire l'historique. Mais d'abord, vous devez indiquer le navigateur dans les options avancées et l'emplacement des fichiers d'historique extraits.

#### **Métadonnées**

* ModifiedTime : Première fois qu'une URL est trouvée
* AccessedTime : Dernière fois
* AccessCount : Nombre de fois consulté

#### **Fichiers**

Recherchez dans _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ et _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs saisies**

Ces informations peuvent être trouvées dans le registre NTDUSER.DAT dans le chemin :

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Stocke les 50 dernières URLs saisies par l'utilisateur
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* Dernière fois que l'URL a été saisie

## Microsoft Edge

Pour analyser les artefacts de Microsoft Edge, toutes les **explications sur le cache et les emplacements de la section précédente (IE 11) restent valables**, à la seule différence que l'emplacement de base, dans ce cas, est _**%userprofile%\Appdata\Local\Packages**_ (comme on peut l'observer dans les chemins suivants) :

* Chemin du profil : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* Historique, cookies et téléchargements : _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Paramètres, favoris et liste de lecture : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache : _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Dernières sessions actives : _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Les bases de données peuvent être trouvées dans `/Users/$User/Library/Safari`

* **History.db** : Les tables `history_visits` et `history_items` contiennent des informations sur l'historique et les horodatages.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist** : Contient les informations sur les fichiers téléchargés.
* **Book-marks.plist** : URLs mises en signet.
* **TopSites.plist** : Liste des sites les plus visités par l'utilisateur.
* **Extensions.plist** : Pour récupérer une liste d'anciennes extensions du navigateur Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist** : Domaines autorisés à envoyer des notifications.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist** : Onglets ouverts la dernière fois que l'utilisateur a quitté Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Anti-phishing intégré au navigateur** : `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* La réponse devrait être 1 pour indiquer que le paramètre est actif

## Opera

Les bases de données peuvent être trouvées dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

Opera **stocke l'historique du navigateur et les données de téléchargement dans le même format que Google Chrome**. Cela s'applique aux noms de fichiers ainsi qu'aux noms de table.

* **Anti-phishing intégré au navigateur** : `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled** devrait être **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) pour créer et **automatiser facilement des flux de travail** basés sur les outils communautaires les plus avancés au monde.\
Accédez dès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
