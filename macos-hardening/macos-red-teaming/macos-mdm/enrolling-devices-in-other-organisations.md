# Iscrizione dei dispositivi in altre organizzazioni

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Introduzione

Come [**precedentemente commentato**](./#what-is-mdm-mobile-device-management)**,** per cercare di iscrivere un dispositivo in un'organizzazione **è necessario solo un numero di serie appartenente a quell'organizzazione**. Una volta iscritto il dispositivo, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe essere un punto di ingresso pericoloso per gli attaccanti se il processo di iscrizione non è correttamente protetto.

**Di seguito è riportato un riassunto della ricerca [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultalo per ulteriori dettagli tecnici!**

## Panoramica dell'analisi binaria DEP e MDM

Questa ricerca approfondisce le binarie associate al Device Enrollment Program (DEP) e al Mobile Device Management (MDM) su macOS. I componenti chiave includono:

- **`mdmclient`**: Comunica con i server MDM e attiva i check-in DEP su versioni di macOS precedenti alla 10.13.4.
- **`profiles`**: Gestisce i profili di configurazione e attiva i check-in DEP su versioni di macOS dalla 10.13.4 in poi.
- **`cloudconfigurationd`**: Gestisce le comunicazioni dell'API DEP e recupera i profili di iscrizione dei dispositivi.

I check-in DEP utilizzano le funzioni `CPFetchActivationRecord` e `CPGetActivationRecord` del framework privato Configuration Profiles per recuperare l'Activation Record, con `CPFetchActivationRecord` che coordina con `cloudconfigurationd` tramite XPC.

## Reverse Engineering del protocollo Tesla e dello schema Absinthe

Il check-in DEP coinvolge `cloudconfigurationd` che invia un payload JSON crittografato e firmato a _iprofiles.apple.com/macProfile_. Il payload include il numero di serie del dispositivo e l'azione "RequestProfileConfiguration". Lo schema di crittografia utilizzato è chiamato internamente "Absinthe". Svelare questo schema è complesso e comporta numerosi passaggi, che hanno portato all'esplorazione di metodi alternativi per inserire numeri di serie arbitrari nella richiesta di Activation Record.

## Proxying delle richieste DEP

I tentativi di intercettare e modificare le richieste DEP a _iprofiles.apple.com_ utilizzando strumenti come Charles Proxy sono stati ostacolati dalla crittografia del payload e dalle misure di sicurezza SSL/TLS. Tuttavia, abilitando la configurazione `MCCloudConfigAcceptAnyHTTPSCertificate` è possibile bypassare la convalida del certificato del server, anche se la natura crittografata del payload impedisce ancora la modifica del numero di serie senza la chiave di decrittazione.

## Strumentazione delle binarie di sistema che interagiscono con DEP

La strumentazione delle binarie di sistema come `cloudconfigurationd` richiede la disabilitazione della Protezione dell'Integrità del Sistema (SIP) su macOS. Con SIP disabilitato, è possibile utilizzare strumenti come LLDB per collegarsi ai processi di sistema e potenzialmente modificare il numero di serie utilizzato nelle interazioni dell'API DEP. Questo metodo è preferibile in quanto evita le complessità dei diritti e della firma del codice.

**Sfruttare l'Instrumentation binaria:**
La modifica del payload della richiesta DEP prima della serializzazione JSON in `cloudconfigurationd` si è rivelata efficace. Il processo ha coinvolto:

1. Collegare LLDB a `cloudconfigurationd`.
2. Individuare il punto in cui viene recuperato il numero di serie di sistema.
3. Iniettare un numero di serie arbitrario nella memoria prima che il payload venga crittografato e inviato.

Questo metodo ha permesso di recuperare profili DEP completi per numeri di serie arbitrari, dimostrando una potenziale vulnerabilità.

### Automazione dell'Instrumentation con Python

Il processo di sfruttamento è stato automatizzato utilizzando Python con l'API LLDB, rendendo possibile l'inserimento programmato di numeri di serie arbitrari e il recupero dei profili DEP corrispondenti.

### Possibili impatti delle vulnerabilità di DEP e MDM

La ricerca ha evidenziato significative preoccupazioni per la sicurezza:

1. **Divulgazione di informazioni**: Fornendo un numero di serie registrato in DEP, è possibile recuperare informazioni organizzative sensibili contenute nel profilo DEP.
2. **Iscrizione di DEP fraudolenta**: Senza un'adeguata autenticazione, un attaccante con un numero di serie registrato in DEP può iscrivere un dispositivo fraudolento nel server MDM di un'organizzazione, ottenendo potenzialmente accesso a dati sensibili e risorse di rete.

In conclusione, sebbene DEP e MDM offrano potenti strumenti per la gestione dei dispositivi Apple in ambienti aziendali, presentano anche potenziali vettori di attacco che devono essere protetti e monitorati.
