# Artefatti del browser

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) per creare e **automatizzare flussi di lavoro** con gli strumenti comunitari più avanzati al mondo.\
Ottieni l'accesso oggi stesso:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatti del browser <a href="#id-3def" id="id-3def"></a>

Gli artefatti del browser includono vari tipi di dati memorizzati dai browser web, come la cronologia di navigazione, i segnalibri e i dati della cache. Questi artefatti sono conservati in cartelle specifiche all'interno del sistema operativo, con posizione e nome diversi a seconda del browser, ma generalmente memorizzano tipi di dati simili.

Ecco un riassunto degli artefatti del browser più comuni:

- **Cronologia di navigazione**: Traccia le visite dell'utente ai siti web, utile per identificare le visite a siti maligni.
- **Dati di autocompletamento**: Suggerimenti basati su ricerche frequenti, offrendo informazioni utili quando combinati con la cronologia di navigazione.
- **Segnalibri**: Siti salvati dall'utente per un accesso rapido.
- **Estensioni e componenti aggiuntivi**: Estensioni del browser o componenti aggiuntivi installati dall'utente.
- **Cache**: Memorizza contenuti web (ad esempio, immagini, file JavaScript) per migliorare i tempi di caricamento del sito web, preziosi per l'analisi forense.
- **Accessi**: Credenziali di accesso memorizzate.
- **Favicon**: Icone associate ai siti web, che appaiono nelle schede e nei segnalibri, utili per ulteriori informazioni sulle visite dell'utente.
- **Sessioni del browser**: Dati relativi alle sessioni del browser aperte.
- **Download**: Registrazioni dei file scaricati tramite il browser.
- **Dati dei moduli**: Informazioni inserite nei moduli web, salvate per suggerimenti di autocompletamento futuri.
- **Thumbnail**: Immagini di anteprima dei siti web.
- **Custom Dictionary.txt**: Parole aggiunte dall'utente al dizionario del browser.


## Firefox

Firefox organizza i dati dell'utente all'interno dei profili, memorizzati in posizioni specifiche in base al sistema operativo:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un file `profiles.ini` all'interno di queste directory elenca i profili degli utenti. I dati di ogni profilo sono memorizzati in una cartella denominata nella variabile `Path` all'interno di `profiles.ini`, situata nella stessa directory di `profiles.ini` stesso. Se la cartella di un profilo è mancante, potrebbe essere stata eliminata.

All'interno di ogni cartella del profilo, è possibile trovare diversi file importanti:

- **places.sqlite**: Memorizza la cronologia, i segnalibri e i download. Strumenti come [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) su Windows possono accedere ai dati della cronologia.
- Utilizzare query SQL specifiche per estrarre informazioni sulla cronologia e sui download.
- **bookmarkbackups**: Contiene backup dei segnalibri.
- **formhistory.sqlite**: Memorizza i dati dei moduli web.
- **handlers.json**: Gestisce i gestori di protocollo.
- **persdict.dat**: Parole personalizzate del dizionario.
- **addons.json** e **extensions.sqlite**: Informazioni sulle estensioni e i componenti aggiuntivi installati.
- **cookies.sqlite**: Archiviazione dei cookie, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponibile per l'ispezione su Windows.
- **cache2/entries** o **startupCache**: Dati della cache, accessibili tramite strumenti come [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Memorizza le favicon.
- **prefs.js**: Impostazioni e preferenze dell'utente.
- **downloads.sqlite**: Database dei download più vecchio, ora integrato in places.sqlite.
- **thumbnails**: Anteprime dei siti web.
- **logins.json**: Informazioni di accesso crittografate.
- **key4.db** o **key3.db**: Archivia le chiavi di crittografia per proteggere informazioni sensibili.

Inoltre, è possibile verificare le impostazioni anti-phishing del browser cercando le voci `browser.safebrowsing` in `prefs.js`, che indicano se le funzionalità di navigazione sicura sono abilitate o disabilitate.


Per cercare di decrittare la password principale, è possibile utilizzare [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Con lo script e la chiamata seguenti è possibile specificare un file di password per forzare la decrittazione:

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

Google Chrome memorizza i profili degli utenti in posizioni specifiche in base al sistema operativo:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

All'interno di queste directory, la maggior parte dei dati degli utenti può essere trovata nelle cartelle **Default/** o **ChromeDefaultData/**. I seguenti file contengono dati significativi:

- **History**: Contiene URL, download e parole chiave di ricerca. Su Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) può essere utilizzato per leggere la cronologia. La colonna "Transition Type" ha vari significati, tra cui clic dell'utente sui link, URL digitati, invio di moduli e ricariche della pagina.
- **Cookies**: Memorizza i cookie. Per l'ispezione, è disponibile [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene dati memorizzati nella cache. Gli utenti di Windows possono utilizzare [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) per l'ispezione.
- **Bookmarks**: Segnalibri dell'utente.
- **Web Data**: Contiene la cronologia dei form.
- **Favicons**: Memorizza le icone dei siti web.
- **Login Data**: Include le credenziali di accesso come nomi utente e password.
- **Current Session**/**Current Tabs**: Dati sulla sessione di navigazione corrente e sulle schede aperte.
- **Last Session**/**Last Tabs**: Informazioni sui siti attivi durante l'ultima sessione prima della chiusura di Chrome.
- **Extensions**: Directory per le estensioni e i componenti aggiuntivi del browser.
- **Thumbnails**: Memorizza le miniature dei siti web.
- **Preferences**: Un file ricco di informazioni, tra cui impostazioni per plugin, estensioni, popup, notifiche e altro ancora.
- **Anti-phishing integrato nel browser**: Per verificare se l'anti-phishing e la protezione da malware sono abilitati, eseguire il comando `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Cercare `{"enabled: true,"}` nell'output.


## **Recupero dati da database SQLite**

Come si può osservare nelle sezioni precedenti, sia Chrome che Firefox utilizzano database **SQLite** per memorizzare i dati. È possibile **recuperare voci eliminate utilizzando lo strumento** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestisce i suoi dati e metadati in varie posizioni, facilitando la separazione delle informazioni memorizzate e dei relativi dettagli per un facile accesso e gestione.

### Archiviazione dei metadati
I metadati per Internet Explorer sono memorizzati in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (dove VX può essere V01, V16 o V24). Inoltre, il file `V01.log` potrebbe mostrare discrepanze di orario di modifica rispetto a `WebcacheVX.data`, indicando la necessità di riparazione utilizzando `esentutl /r V01 /d`. Questi metadati, contenuti in un database ESE, possono essere recuperati e ispezionati utilizzando strumenti come photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), rispettivamente. All'interno della tabella **Containers**, è possibile individuare le tabelle o i contenitori specifici in cui viene memorizzato ogni segmento di dati, inclusi i dettagli della cache per altri strumenti Microsoft come Skype.

### Ispezione della cache
Lo strumento [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) consente di ispezionare la cache, richiedendo la posizione della cartella di estrazione dei dati della cache. I metadati della cache includono il nome del file, la directory, il conteggio di accesso, l'origine dell'URL e i timestamp che indicano la creazione, l'accesso, la modifica e la scadenza della cache.

### Gestione dei cookie
I cookie possono essere esplorati utilizzando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadati che comprendono nomi, URL, conteggio di accesso e vari dettagli relativi all'orario. I cookie persistenti sono memorizzati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mentre i cookie di sessione risiedono in memoria.

### Dettagli dei download
I metadati dei download sono accessibili tramite [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con contenitori specifici che contengono dati come URL, tipo di file e posizione di download. I file fisici possono essere trovati in `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Cronologia di navigazione
Per visualizzare la cronologia di navigazione, è possibile utilizzare [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), che richiede la posizione dei file di cronologia estratti e la configurazione per Internet Explorer. I metadati qui includono orari di modifica e accesso, insieme a conteggi di accesso. I file di cronologia si trovano in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL digitati
Gli URL digitati e i relativi tempi di utilizzo sono memorizzati nel registro di sistema in `NTUSER.DAT` in `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, tenendo traccia degli ultimi 50 URL inseriti dall'utente e dei loro ultimi tempi di input.


## Microsoft Edge

Microsoft Edge memorizza i dati degli utenti in `%userprofile%\Appdata\Local\Packages`. I percorsi per vari tipi di dati sono:

- **Percorso del profilo**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Cronologia, Cookie e Download**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Impostazioni, Segnalibri e Lista di lettura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Sessioni attive precedenti**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

I dati di Safari sono memorizzati in `/Users/$User/Library/Safari`. I file chiave includono:

- **History.db**: Contiene le tabelle `history_visits` e `history_items` con URL e timestamp delle visite. Utilizzare `sqlite3` per le query.
- **Downloads.plist**: Informazioni sui file scaricati.
- **Bookmarks.plist**: Memorizza gli URL dei segnalibri.
- **TopSites.plist**: Siti più visitati.
- **Extensions.plist**: Elenco delle estensioni del browser Safari. Utilizzare `plutil` o `pluginkit` per recuperare.
- **UserNotificationPermissions.plist**: Domini autorizzati a inviare notifiche. Utilizzare `plutil` per l'analisi.
- **LastSession.plist**: Schede dell'ultima sessione. Utilizzare `plutil` per l'analisi.
- **Anti-phishing integrato nel browser**: Verificare utilizzando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una risposta di 1 indica che la funzione è attiva.

## Opera

I dati di Opera si trovano in `/Users/$USER/Library
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi.
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
