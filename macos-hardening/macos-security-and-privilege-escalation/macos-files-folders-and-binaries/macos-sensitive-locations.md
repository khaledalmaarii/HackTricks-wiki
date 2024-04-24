# Posizioni Sensibili di macOS e Daemon Interessanti

<details>

<summary><strong>Impara l'hacking su AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Passwords

### Password Ombra

La password ombra è memorizzata insieme alla configurazione dell'utente in plists situati in **`/var/db/dslocal/nodes/Default/users/`**.\
Il seguente oneliner può essere utilizzato per estrarre **tutte le informazioni sugli utenti** (incluso l'hash): 

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) può essere utilizzato per trasformare l'hash nel **formato hashcat**.

Un'alternativa one-liner che dumpa le credenziali di tutti gli account non di servizio nel formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Dump delle chiavi

Si noti che quando si utilizza il binario di sicurezza per **scaricare le password decifrate**, verranno visualizzati diversi prompt che chiederanno all'utente di consentire questa operazione.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Basandosi su questo commento [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sembra che questi strumenti non funzionino più in Big Sur.
{% endhint %}

### Panoramica di Keychaindump

Uno strumento chiamato **keychaindump** è stato sviluppato per estrarre password dalle chiavi di macOS, ma presenta limitazioni sulle versioni più recenti di macOS come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede che l'attaccante ottenga accesso ed elevi i privilegi a **root**. Lo strumento sfrutta il fatto che la chiave sia sbloccata per impostazione predefinita all'avvio dell'utente per comodità, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare la propria chiave dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** opera prendendo di mira un processo specifico chiamato **securityd**, descritto da Apple come un demone per operazioni di autorizzazione e crittografia, fondamentale per accedere alla chiave. Il processo di estrazione coinvolge l'individuazione di una **Chiave Principale** derivata dalla password di accesso dell'utente. Questa chiave è essenziale per leggere il file della chiave. Per individuare la **Chiave Principale**, **keychaindump** esamina l'heap di memoria di **securityd** utilizzando il comando `vmmap`, cercando potenziali chiavi nelle aree contrassegnate come `MALLOC_TINY`. Il seguente comando viene utilizzato per ispezionare queste posizioni di memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato le potenziali chiavi principali, **keychaindump** cerca tra gli heap un pattern specifico (`0x0000000000000018`) che indica un candidato per la chiave principale. Sono necessari ulteriori passaggi, inclusa la deobfuscation, per utilizzare questa chiave, come descritto nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su questa area dovrebbero notare che i dati cruciali per decrittare il portachiavi sono memorizzati all'interno della memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere utilizzato per estrarre i seguenti tipi di informazioni da un portachiavi OSX in modo forense:

* Password del portachiavi hashata, adatta per il cracking con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
* Password Internet
* Password generiche
* Chiavi private
* Chiavi pubbliche
* Certificati X509
* Note sicure
* Password Appleshare

Con la password di sblocco del portachiavi, una chiave principale ottenuta utilizzando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un file di sblocco come SystemKey, Chainbreaker fornirà anche le password in chiaro.

Senza uno di questi metodi per sbloccare il portachiavi, Chainbreaker visualizzerà tutte le altre informazioni disponibili.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Scaricare le chiavi del portachiavi (con le password) con SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) per crackare l'hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) con dump di memoria**

[Seguire questi passaggi](../#dumping-memory-with-osxpmem) per eseguire un **dump di memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Scaricare le chiavi del portachiavi (con le password) utilizzando la password dell'utente**

Se conosci la password dell'utente, puoi utilizzarla per **scaricare e decrittografare i portachiavi che appartengono all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Il file **kcpassword** è un file che contiene la **password di accesso dell'utente**, ma solo se il proprietario del sistema ha **abilitato l'accesso automatico**. Pertanto, l'utente verrà automaticamente effettuato il login senza essere richiesto di inserire una password (il che non è molto sicuro).

La password è memorizzata nel file **`/etc/kcpassword`** xored con la chiave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password degli utenti è più lunga della chiave, la chiave verrà riutilizzata.\
Ciò rende la password piuttosto facile da recuperare, ad esempio utilizzando script come [**questo**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informazioni Interessanti nei Database

### Messaggi
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifiche

Puoi trovare i dati delle Notifiche in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La maggior parte delle informazioni interessanti si troverà nel **blob**. Quindi dovrai **estrarre** quel contenuto e **trasformarlo** in un formato **leggibile** per l'utente o utilizzare **`strings`**. Per accedervi puoi fare:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Note

Le note degli utenti possono essere trovate in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Preferenze

Nelle app macOS le preferenze si trovano in **`$HOME/Library/Preferences`** e in iOS sono in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

In macOS lo strumento cli **`defaults`** può essere utilizzato per **modificare il file delle preferenze**.

**`/usr/sbin/cfprefsd`** gestisce i servizi XPC `com.apple.cfprefsd.daemon` e `com.apple.cfprefsd.agent` e può essere chiamato per eseguire azioni come modificare le preferenze.

## Notifiche di Sistema

### Notifiche Darwin

Il daemon principale per le notifiche è **`/usr/sbin/notifyd`**. Per ricevere notifiche, i client devono registrarsi attraverso la porta Mach `com.apple.system.notification_center` (verificarli con `sudo lsmp -p <pid notifyd>`). Il daemon è configurabile con il file `/etc/notify.conf`.

I nomi utilizzati per le notifiche sono notazioni univoche DNS inverse e quando viene inviata una notifica a uno di essi, il/i client che hanno indicato di poterla gestire la riceveranno.

È possibile visualizzare lo stato attuale (e vedere tutti i nomi) inviando il segnale SIGUSR2 al processo notifyd e leggendo il file generato: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Centro Notifiche Distribuito

Il **Centro Notifiche Distribuito** il cui principale binario è **`/usr/sbin/distnoted`**, è un altro modo per inviare notifiche. Espone alcuni servizi XPC e effettua alcuni controlli per cercare di verificare i client.

### Notifiche Push di Apple (APN)

In questo caso, le applicazioni possono registrarsi per **argomenti**. Il client genererà un token contattando i server di Apple tramite **`apsd`**.\
Successivamente, i fornitori avranno generato anche un token e saranno in grado di connettersi ai server di Apple per inviare messaggi ai client. Questi messaggi verranno ricevuti localmente da **`apsd`** che inoltrerà la notifica all'applicazione in attesa di riceverla.

Le preferenze sono situate in `/Library/Preferences/com.apple.apsd.plist`.

Vi è un database locale di messaggi situato in macOS in `/Library/Application\ Support/ApplePushService/aps.db` e in iOS in `/var/mobile/Library/ApplePushService`. Esso ha 3 tabelle: `incoming_messages`, `outgoing_messages` e `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
È anche possibile ottenere informazioni sul daemon e sulle connessioni utilizzando:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifiche per l'utente

Queste sono le notifiche che l'utente dovrebbe vedere sullo schermo:

* **`CFUserNotification`**: Questa API fornisce un modo per mostrare sullo schermo un popup con un messaggio.
* **Il Bulletin Board**: Questo mostra in iOS un banner che scompare e verrà memorizzato nel Notification Center.
* **`NSUserNotificationCenter`**: Questo è il bulletin board di iOS in MacOS. Il database con le notifiche si trova in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
