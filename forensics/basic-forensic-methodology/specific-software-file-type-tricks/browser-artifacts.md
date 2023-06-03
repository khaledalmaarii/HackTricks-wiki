# Artéfacts de navigateur

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utilisez [**Trickest**](https://trickest.io/) pour créer et **automatiser des workflows** alimentés par les outils communautaires les plus avancés au monde.\
Obtenez l'accès aujourd'hui :

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artéfacts de navigateurs <a href="#3def" id="3def"></a>

Lorsque nous parlons d'artéfacts de navigateur, nous parlons de l'historique de navigation, des favoris, de la liste des fichiers téléchargés, des données de cache, etc.

Ces artéfacts sont des fichiers stockés dans des dossiers spécifiques du système d'exploitation.

Chaque navigateur stocke ses fichiers dans un endroit différent des autres navigateurs et ils ont tous des noms différents, mais ils stockent tous (la plupart du temps) le même type de données (artéfacts).

Examinons les artéfacts les plus courants stockés par les navigateurs.

* **Historique de navigation :** Contient des données sur l'historique de navigation de l'utilisateur. Peut être utilisé pour suivre si l'utilisateur a visité des sites malveillants, par exemple.
* **Données d'autocomplétion :** Ce sont les données que le navigateur suggère en fonction de ce que vous recherchez le plus. Peut être utilisé en tandem avec l'historique de navigation pour obtenir plus d'informations.
* **Favoris :** Auto-explicatif.
* **Extensions et modules complémentaires :** Auto-explicatif.
* **Cache :** Lors de la navigation sur des sites Web, le navigateur crée toutes sortes de données de cache (images, fichiers JavaScript, etc.) pour de nombreuses raisons. Par exemple, pour accélérer le temps de chargement des sites Web. Ces fichiers de cache peuvent être une excellente source de données lors d'une enquête judiciaire.
* **Connexions :** Auto-explicatif.
* **Favicons :** Ce sont les petites icônes que l'on trouve dans les onglets, les URL, les favoris, etc. Ils peuvent être utilisés comme autre source pour obtenir plus d'informations sur le site Web ou les endroits visités par l'utilisateur.
* **Sessions de navigateur :** Auto-explicatif.
* **Téléchargements :** Auto-explicatif.
* **Données de formulaire :** Tout ce qui est tapé dans les formulaires est souvent stocké par le navigateur, de sorte que la prochaine fois que l'utilisateur entre quelque chose dans un formulaire, le navigateur peut suggérer des données précédemment saisies.
* **Miniatures :** Auto-explicatif.
* **Custom Dictionary.txt :** Mots ajoutés au dictionnaire par l'utilisateur.

## Firefox

Firefox crée le dossier de profils dans \~/_**.mozilla/firefox/**_ (Linux), dans **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dans ce dossier, le fichier _**profiles.ini**_ doit apparaître avec le nom du ou des profils d'utilisateur.\
Chaque profil a une variable "**Path**" avec le nom du dossier où ses données vont être stockées. Le dossier doit être **présent dans le même répertoire où se trouve le \_profiles.ini**\_\*\*. S'il ne l'est pas, alors il a probablement été supprimé.

Dans le dossier **de chaque profil** (_\~/.mozilla/firefox/\<ProfileName>/_) vous devriez être en mesure de trouver les fichiers intéressants suivants :

* _**places.sqlite**_ : Historique (moz\_\_places), favoris (moz\_bookmarks), et téléchargements (moz\_\_annos). Dans Windows, l'outil [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) peut être utilisé pour lire l'historique à l'intérieur de _**places.sqlite**_.
  * Requête pour extraire l'historique : `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
    * Notez qu'un type de lien est un nombre qui indique :
      * 1 : L'utilisateur a suivi un lien
      * 2 : L'utilisateur a écrit l'URL
      * 3 : L'utilisateur a utilisé un favori
      * 4 : Chargé depuis Iframe
      * 5 : Accédé via une redirection HTTP 301
      * 6 : Accédé via une redirection HTTP 302
      * 7 : Fichier téléchargé
      * 8 : L'utilisateur a suivi un lien à l'intérieur d'un Iframe
  * Requête pour extraire les téléchargements : `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
  *
* _**bookmarkbackups/**_ : Sauvegardes de favoris
* _**formhistory.sqlite**_ : **Données de formulaire Web** (comme les e-mails)
* _**handlers.json**_ : Gestionnaires de protocoles (comme, quelle application va gérer le protocole _mailto://_)
* _**persdict.dat**_ : Mots ajoutés au dictionnaire
* _**addons.json**_ et \_**extensions.sqlite** \_ : Modules complémentaires et extensions installés
* _**cookies.sqlite**_ : Contient des **cookies**. [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) peut être utilisé sous Windows pour inspecter ce fichier.
*   _**cache2/entries**_ ou _**startupCache**_ : Données de cache (\~350MB). Des astuces comme la **récupération de données** peuvent également être utilisées pour obtenir les fichiers enregistrés dans le cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) peut être utilisé pour voir les **fichiers en
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

Google Chrome crée le profil à l'intérieur du dossier de l'utilisateur _**\~/.config/google-chrome/**_ (Linux), dans _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou dans \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
La plupart des informations seront enregistrées dans les dossiers _**Default/**_ ou _**ChromeDefaultData/**_ dans les chemins indiqués précédemment. Vous pouvez y trouver les fichiers intéressants suivants :

* _**History**_ : URLs, téléchargements et même mots-clés recherchés. Sous Windows, vous pouvez utiliser l'outil [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) pour lire l'historique. La colonne "Transition Type" signifie :
  * Link : L'utilisateur a cliqué sur un lien
  * Typed : L'URL a été écrite
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
* _**Extensions**_ : Dossier d'extensions et d'addons
* **Thumbnails** : Miniatures
* **Preferences** : Ce fichier contient une pléthore d'informations utiles telles que les plugins, les extensions, les sites utilisant la géolocalisation, les popups, les notifications, le prefetching DNS, les exceptions de certificat, et bien plus encore. Si vous essayez de rechercher si un paramètre spécifique de Chrome était activé ou non, vous trouverez probablement ce paramètre ici.
* **Anti-phishing intégré au navigateur** : `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
  * Vous pouvez simplement rechercher "safebrowsing" et chercher `{"enabled: true,"}` dans le résultat pour indiquer que la protection anti-phishing et anti-malware est activée.

## Récupération de données de base de données SQLite

Comme vous pouvez l'observer dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer les entrées supprimées à l'aide de l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## Internet Explorer 11

Internet Explorer stocke les **données** et les **métadonnées** dans différents emplacements. Les métadonnées permettront de trouver les données.

Les **métadonnées** peuvent être trouvées dans le dossier `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` où VX peut être V01, V16 ou V24.\
Dans le dossier
