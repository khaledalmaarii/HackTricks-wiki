# Artefatti del Browser

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della comunità più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatti dei Browser <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e i dati della cache. Questi artefatti sono conservati in cartelle specifiche all'interno del sistema operativo, differendo per posizione e nome tra i browser, ma generalmente memorizzando tipi di dati simili.

Ecco un riassunto dei più comuni artefatti del browser:

* **Cronologia di Navigazione**: Traccia le visite dell'utente ai siti web, utile per identificare visite a siti dannosi.
* **Dati di Autocompletamento**: Suggerimenti basati su ricerche frequenti, offrendo approfondimenti quando combinati con la cronologia di navigazione.
* **Segnalibri**: Siti salvati dall'utente per un accesso rapido.
* **Estensioni e Componenti Aggiuntivi**: Estensioni del browser o componenti aggiuntivi installati dall'utente.
* **Cache**: Memorizza contenuti web (ad esempio, immagini, file JavaScript) per migliorare i tempi di caricamento del sito, preziosi per l'analisi forense.
* **Accessi**: Credenziali di accesso memorizzate.
* **Favicons**: Icone associate ai siti web, che appaiono in schede e segnalibri, utili per informazioni aggiuntive sulle visite dell'utente.
* **Sessioni del Browser**: Dati relativi alle sessioni del browser aperte.
* **Download**: Registrazioni di file scaricati tramite il browser.
* **Dati dei Moduli**: Informazioni inserite nei moduli web, salvate per suggerimenti di autocompletamento futuri.
* **Miniature**: Immagini di anteprima dei siti web.
* **Custom Dictionary.txt**: Parole aggiunte dall'utente al dizionario del browser.

## Firefox

Firefox organizza i dati dell'utente all'interno di profili, memorizzati in posizioni specifiche in base al sistema operativo:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` all'interno di queste directory elenca i profili utente. I dati di ciascun profilo sono memorizzati in una cartella denominata con la variabile `Path` all'interno di `profiles.ini`, situata nella stessa directory di `profiles.ini` stesso. Se manca la cartella di un profilo, potrebbe essere stata eliminata.

All'interno di ciascuna cartella del profilo, è possibile trovare diversi file importanti:

* **places.sqlite**: Memorizza la cronologia, i segnalibri e i download. Strumenti come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) su Windows possono accedere ai dati della cronologia.
* Utilizzare query SQL specifiche per estrarre informazioni sulla cronologia e sui download.
* **bookmarkbackups**: Contiene i backup dei segnalibri.
* **formhistory.sqlite**: Memorizza i dati dei moduli web.
* **handlers.json**: Gestisce i gestori di protocollo.
* **persdict.dat**: Parole del dizionario personalizzato.
* **addons.json** e **extensions.sqlite**: Informazioni sulle estensioni e i componenti aggiuntivi installati.
* **cookies.sqlite**: Archiviazione dei cookie, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponibile per l'ispezione su Windows.
* **cache2/entries** o **startupCache**: Dati della cache, accessibili tramite strumenti come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Memorizza i favicons.
* **prefs.js**: Impostazioni e preferenze dell'utente.
* **downloads.sqlite**: Vecchio database dei download, ora integrato in places.sqlite.
* **thumbnails**: Miniature dei siti web.
* **logins.json**: Informazioni di accesso crittografate.
* **key4.db** o **key3.db**: Memorizza le chiavi di crittografia per proteggere informazioni sensibili.

Inoltre, verificare le impostazioni anti-phishing del browser può essere fatto cercando voci `browser.safebrowsing` in `prefs.js`, indicando se le funzionalità di navigazione sicura sono abilitate o disabilitate.

Per provare a decifrare la password principale, è possibile utilizzare [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Con lo script e la chiamata seguenti è possibile specificare un file password per il brute force:

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

Google Chrome memorizza i profili utente in posizioni specifiche in base al sistema operativo:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati utente può essere trovata nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati significativi:

* **History**: Contiene URL, download e parole chiave di ricerca. Su Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) può essere utilizzato per leggere la cronologia. La colonna "Tipo di transizione" ha vari significati, tra cui clic dell'utente su link, URL digitati, invio di moduli e ricariche della pagina.
* **Cookies**: Memorizza i cookie. Per l'ispezione, è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html).
* **Cache**: Contiene dati memorizzati nella cache. Per l'ispezione, gli utenti Windows possono utilizzare [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
* **Segnalibri**: Segnalibri dell'utente.
* **Web Data**: Contiene la cronologia dei moduli.
* **Favicons**: Memorizza le icone dei siti web.
* **Login Data**: Include credenziali di accesso come nomi utente e password.
* **Sessione corrente**/**Schede correnti**: Dati sulla sessione di navigazione corrente e schede aperte.
* **Ultima sessione**/**Ultimi tab**: Informazioni sui siti attivi durante l'ultima sessione prima della chiusura di Chrome.
* **Estensioni**: Directory per estensioni e componenti aggiuntivi del browser.
* **Miniature**: Memorizza le miniature dei siti web.
* **Preferenze**: Un file ricco di informazioni, inclusi impostazioni per plugin, estensioni, popup, notifiche e altro ancora.
* **Antiphishing integrato del browser**: Per verificare se l'antiphishing e la protezione da malware sono abilitati, eseguire `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Cercare `{"enabled: true,"}` nell'output.

## **Recupero dati da database SQLite**

Come si può osservare nelle sezioni precedenti, sia Chrome che Firefox utilizzano database **SQLite** per memorizzare i dati. È possibile **recuperare voci eliminate utilizzando lo strumento** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i suoi dati e metadati in varie posizioni, aiutando a separare le informazioni memorizzate e i relativi dettagli per un facile accesso e gestione.

### Archiviazione dei metadati

I metadati per Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (con VX che può essere V01, V16 o V24). Inoltre, il file `V01.log` potrebbe mostrare discrepanze di tempo di modifica con `WebcacheVX.data`, indicando la necessità di riparazione utilizzando `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e ispezionati utilizzando strumenti come photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), rispettivamente. All'interno della tabella **Containers**, è possibile distinguere le tabelle o i contenitori specifici in cui è memorizzato ciascun segmento di dati, inclusi dettagli della cache per altri strumenti Microsoft come Skype.

### Ispezione della cache

Lo strumento [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) consente l'ispezione della cache, richiedendo la posizione della cartella di estrazione dei dati della cache. I metadati per la cache includono nome file, directory, conteggio accessi, origine URL e timestamp che indicano i tempi di creazione, accesso, modifica e scadenza della cache.

### Gestione dei cookie

I cookie possono essere esplorati utilizzando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadati che includono nomi, URL, conteggio accessi e vari dettagli temporali. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre i cookie di sessione risiedono in memoria.

### Dettagli dei download

I metadati dei download sono accessibili tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), con contenitori specifici che contengono dati come URL, tipo di file e posizione di download. I file fisici possono essere trovati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Cronologia di navigazione

Per rivedere la cronologia di navigazione, è possibile utilizzare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html), richiedendo la posizione dei file di cronologia estratti e la configurazione per Internet Explorer. I metadati qui includono tempi di modifica e accesso, insieme ai conteggi di accesso. I file di cronologia si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL digitati

Gli URL digitati e i relativi tempi di utilizzo sono memorizzati nel registro di sistema in `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, tracciando gli ultimi 50 URL inseriti dall'utente e i loro ultimi tempi di input.

## Microsoft Edge

Microsoft Edge memorizza i dati utente in `%userprofile%\Appdata\Local\Packages`. I percorsi per vari tipi di dati sono:

* **Percorso del profilo**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **Cronologia, Cookie e Download**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Impostazioni, Segnalibri e Elenco di lettura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Ultima sessione attiva**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. I file chiave includono:

* **History.db**: Contiene tabelle `history_visits` e `history_items` con URL e timestamp di visita. Utilizzare `sqlite3` per interrogare.
* **Downloads.plist**: Informazioni sui file scaricati.
* **Bookmarks.plist**: Memorizza gli URL dei segnalibri.
* **TopSites.plist**: Siti più visitati.
* **Extensions.plist**: Elenco delle estensioni del browser Safari. Utilizzare `plutil` o `pluginkit` per recuperare.
* **UserNotificationPermissions.plist**: Domini autorizzati a inviare notifiche push. Utilizzare `plutil` per analizzare.
* **LastSession.plist**: Schede dell'ultima sessione. Utilizzare `plutil` per analizzare.
* **Antiphishing integrato del browser**: Verificare utilizzando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta di 1 indica che la funzionalità è attiva.

## Opera

I dati di Opera risiedono in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e condividono il formato di Chrome per la cronologia e i download.

* **Antiphishing integrato del browser**: Verificare controllando se `fraud_protection_enabled` nel file delle Preferenze è impostato su `true` utilizzando `grep`.

Questi percorsi e comandi sono cruciali per accedere e comprendere i dati di navigazione memorizzati dai diversi browser web.

## Riferimenti

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Libro: OS X Incident Response: Scripting and Analysis di Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilizza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare facilmente flussi di lavoro** supportati dagli strumenti della community più avanzati al mondo.\
Ottieni l'accesso oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
