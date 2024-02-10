# Red Teaming su macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Abuso di MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se riesci a **compromettere le credenziali di amministratore** per accedere alla piattaforma di gestione, puoi **potenzialmente compromettere tutti i computer** distribuendo il tuo malware nelle macchine.

Per il red teaming in ambienti MacOS, è altamente consigliato avere una comprensione di come funzionano i MDM:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Utilizzo di MDM come C2

Un MDM avrà il permesso di installare, interrogare o rimuovere profili, installare applicazioni, creare account amministratore locali, impostare la password del firmware, cambiare la chiave di FileVault...

Per eseguire il proprio MDM, è necessario **ottenere il proprio CSR firmato da un fornitore** che si potrebbe cercare di ottenere con [**https://mdmcert.download/**](https://mdmcert.download/). E per eseguire il proprio MDM per dispositivi Apple si potrebbe utilizzare [**MicroMDM**](https://github.com/micromdm/micromdm).

Tuttavia, per installare un'applicazione in un dispositivo registrato, è comunque necessario che sia firmata da un account sviluppatore... tuttavia, durante l'iscrizione al MDM il **dispositivo aggiunge il certificato SSL del MDM come CA fidata**, quindi ora puoi firmare qualsiasi cosa.

Per iscrivere il dispositivo a un MDM, è necessario installare un file **`mobileconfig`** come root, che potrebbe essere consegnato tramite un file **pkg** (puoi comprimerlo in zip e quando viene scaricato da Safari verrà decompresso).

**L'agente Mythic Orthrus** utilizza questa tecnica.

### Abuso di JAMF PRO

JAMF può eseguire **script personalizzati** (script sviluppati dall'amministratore di sistema), **payload nativi** (creazione di account locali, impostazione della password EFI, monitoraggio di file/processi...) e **MDM** (configurazioni del dispositivo, certificati del dispositivo...).

#### Auto-iscrizione JAMF

Vai a una pagina come `https://<nome-azienda>.jamfcloud.com/enroll/` per vedere se hanno **abilitata l'auto-iscrizione**. Se l'hanno, potrebbe **richiedere le credenziali per accedere**.

Potresti utilizzare lo script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) per eseguire un attacco di password spraying.

Inoltre, dopo aver trovato le credenziali corrette, potresti essere in grado di eseguire un attacco di forza bruta su altri nomi utente con il modulo successivo:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Autenticazione del dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Il binario **`jamf`** conteneva il segreto per aprire il portachiavi che al momento della scoperta era **condiviso** tra tutti ed era: **`jk23ucnq91jfu9aj`**.\
Inoltre, jamf **persiste** come **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Presa del controllo del dispositivo JAMF

L'URL del **JSS** (Jamf Software Server) che **`jamf`** utilizzerà si trova in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Questo file contiene fondamentalmente l'URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Quindi, un attaccante potrebbe inserire un pacchetto malevolo (`pkg`) che sovrascrive questo file quando viene installato impostando l'URL su un listener Mythic C2 da un agente Typhon per poter abusare di JAMF come C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Impersonazione di JAMF

Per **impersonare la comunicazione** tra un dispositivo e JMF hai bisogno di:

* L'**UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* La **keychain di JAMF** da: `/Library/Application\ Support/Jamf/JAMF.keychain` che contiene il certificato del dispositivo

Con queste informazioni, **crea una VM** con l'**UUID** dell'hardware **rubato** e con **SIP disabilitato**, copia la **keychain di JAMF**, **hook** l'agente Jamf e ruba le sue informazioni.

#### Furto di segreti

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Puoi anche monitorare la posizione `/Library/Application Support/Jamf/tmp/` per gli **script personalizzati** che gli amministratori potrebbero voler eseguire tramite Jamf in quanto vengono **posizionati qui, eseguiti e rimossi**. Questi script **potrebbero contenere credenziali**.

Tuttavia, le **credenziali** potrebbero essere passate a questi script come **parametri**, quindi dovresti monitorare `ps aux | grep -i jamf` (senza nemmeno essere root).

Lo script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) può ascoltare l'aggiunta di nuovi file e nuovi argomenti dei processi.

### Accesso remoto a macOS

E anche sui **protocolli di rete** **"speciali"** di **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In alcune occasioni potresti scoprire che il **computer MacOS è connesso a un AD**. In questo scenario dovresti provare a **enumerare** l'active directory come sei abituato a fare. Trova un po' di **aiuto** nelle seguenti pagine:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Uno **strumento locale di MacOS** che potrebbe aiutarti è `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Inoltre, ci sono alcuni strumenti preparati per MacOS per enumerare automaticamente l'AD e giocare con Kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound è un'estensione dello strumento di audit Bloodhound che consente di raccogliere e inglobare le relazioni dell'Active Directory su host MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost è un progetto Objective-C progettato per interagire con le API Heimdal krb5 su macOS. L'obiettivo del progetto è consentire un miglior testing della sicurezza attorno a Kerberos su dispositivi macOS utilizzando API native senza richiedere altri framework o pacchetti nel target.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Strumento JavaScript for Automation (JXA) per l'enumerazione dell'Active Directory.

### Informazioni sul dominio
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utenti

I tre tipi di utenti MacOS sono:

* **Utenti Locali** - Gestiti dal servizio locale OpenDirectory, non sono collegati in alcun modo all'Active Directory.
* **Utenti di Rete** - Utenti volatili dell'Active Directory che richiedono una connessione al server DC per l'autenticazione.
* **Utenti Mobili** - Utenti dell'Active Directory con un backup locale per le loro credenziali e file.

Le informazioni locali sugli utenti e sui gruppi sono memorizzate nella cartella _/var/db/dslocal/nodes/Default._\
Ad esempio, le informazioni sull'utente chiamato _mark_ sono memorizzate in _/var/db/dslocal/nodes/Default/users/mark.plist_ e le informazioni sul gruppo _admin_ sono in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oltre all'utilizzo dei collegamenti HasSession e AdminTo, **MacHound aggiunge tre nuovi collegamenti** al database Bloodhound:

* **CanSSH** - entità autorizzata a effettuare SSH sull'host
* **CanVNC** - entità autorizzata a effettuare VNC sull'host
* **CanAE** - entità autorizzata ad eseguire script AppleEvent sull'host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Ulteriori informazioni su [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Accesso alla Keychain

La Keychain contiene molto probabilmente informazioni sensibili che, se accessibili senza generare una richiesta, potrebbero aiutare a progredire in un esercizio di red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Servizi esterni

Il red teaming su MacOS è diverso dal red teaming su Windows perché di solito **MacOS è integrato direttamente con diverse piattaforme esterne**. Una configurazione comune di MacOS è quella di accedere al computer utilizzando **credenziali sincronizzate con OneLogin e accedere a diversi servizi esterni** (come github, aws...) tramite OneLogin.

## Tecniche varie di red teaming

### Safari

Quando viene scaricato un file in Safari, se è un file "sicuro", verrà **aperto automaticamente**. Quindi, ad esempio, se si **scarica un file zip**, verrà decompresso automaticamente:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Vieni dal lato oscuro, abbiamo le mele: trasformare la gestione di macOS in malefica**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "Una prospettiva degli attaccanti sulle configurazioni di Jamf" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) **e** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos.**

</details>
