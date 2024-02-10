# euid, ruid, suid

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Variabili di identificazione dell'utente

- **`ruid`**: L'**ID utente reale** indica l'utente che ha avviato il processo.
- **`euid`**: Conosciuto come **ID utente effettivo**, rappresenta l'identità dell'utente utilizzata dal sistema per determinare i privilegi del processo. In generale, `euid` riflette `ruid`, ad eccezione di casi come l'esecuzione di un binario SetUID, in cui `euid` assume l'identità del proprietario del file, concedendo così specifici permessi operativi.
- **`suid`**: Questo **ID utente salvato** è fondamentale quando un processo ad alta privilegi (tipicamente in esecuzione come root) deve temporaneamente rinunciare ai suoi privilegi per eseguire determinati compiti, per poi recuperare successivamente il suo stato elevato iniziale.

#### Nota importante
Un processo che non opera come root può modificare solo il suo `euid` per corrispondere all'attuale `ruid`, `euid` o `suid`.

### Comprensione delle funzioni set*uid

- **`setuid`**: Contrariamente alle supposizioni iniziali, `setuid` modifica principalmente `euid` anziché `ruid`. In particolare, per i processi privilegiati, allinea `ruid`, `euid` e `suid` con l'utente specificato, spesso root, consolidando efficacemente questi ID a causa dell'override di `suid`. Informazioni dettagliate possono essere trovate nella [pagina man di setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: Queste funzioni consentono l'aggiustamento sfumato di `ruid`, `euid` e `suid`. Tuttavia, le loro capacità dipendono dal livello di privilegio del processo. Per i processi non root, le modifiche sono limitate ai valori correnti di `ruid`, `euid` e `suid`. Al contrario, i processi root o quelli con la capacità `CAP_SETUID` possono assegnare valori arbitrari a questi ID. Ulteriori informazioni possono essere ricavate dalla [pagina man di setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e dalla [pagina man di setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Queste funzionalità sono progettate non come meccanismo di sicurezza, ma per agevolare il flusso operativo previsto, ad esempio quando un programma adotta l'identità di un altro utente modificando il proprio ID utente effettivo.

È importante notare che, sebbene `setuid` possa essere una scelta comune per l'elevazione dei privilegi a root (poiché allinea tutti gli ID a root), differenziare tra queste funzioni è fondamentale per comprendere e manipolare i comportamenti degli ID utente in scenari diversi.

### Meccanismi di esecuzione dei programmi in Linux

#### Chiamata di sistema **`execve`**
- **Funzionalità**: `execve` avvia un programma, determinato dal primo argomento. Prende due argomenti di tipo array, `argv` per gli argomenti e `envp` per l'ambiente.
- **Comportamento**: Mantiene lo spazio di memoria del chiamante, ma aggiorna lo stack, l'heap e i segmenti di dati. Il codice del programma viene sostituito dal nuovo programma.
- **Preservazione dell'ID utente**:
- `ruid`, `euid` e gli ID dei gruppi supplementari rimangono inalterati.
- `euid` potrebbe subire cambiamenti sfumati se il nuovo programma ha il bit SetUID impostato.
- `suid` viene aggiornato da `euid` dopo l'esecuzione.
- **Documentazione**: Informazioni dettagliate possono essere trovate nella [pagina man di `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### Funzione **`system`**
- **Funzionalità**: A differenza di `execve`, `system` crea un processo figlio utilizzando `fork` ed esegue un comando all'interno di quel processo figlio utilizzando `execl`.
- **Esecuzione del comando**: Esegue il comando tramite `sh` con `execl("/bin/sh", "sh", "-c", comando, (char *) NULL);`.
- **Comportamento**: Poiché `execl` è una forma di `execve`, funziona in modo simile ma nel contesto di un nuovo processo figlio.
- **Documentazione**: Ulteriori approfondimenti possono essere ottenuti dalla [pagina man di `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### Comportamento di **`bash`** e **`sh`** con SUID
- **`bash`**:
- Ha un'opzione `-p` che influenza il trattamento di `euid` e `ruid`.
- Senza `-p`, `bash` imposta `euid` su `ruid` se inizialmente differiscono.
- Con `-p`, viene preservato l'`euid` iniziale.
- Ulteriori dettagli possono essere trovati nella [pagina man di `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Non possiede un meccanismo simile a `-p` in `bash`.
- Il comportamento riguardante gli ID utente non è menzionato esplicitamente, tranne nell'opzione `-i`, che sottolinea la preservazione dell'uguaglianza tra `euid` e `ruid`.
- Ulteriori informazioni sono disponibili nella [pagina man di `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Questi meccanismi, distinti nel loro funzionamento, offrono una vasta gamma di opzioni per l'esecuzione e la transizione tra programmi, con sfumature specifiche nel modo in cui gli ID utente vengono gestiti e preservati.

### Test dei comportamenti degli ID utente nelle esecuzioni

Esempi tratti da https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, controlla per ulteriori informazioni

#### Caso 1: Utilizzo di `setuid` con `system`

**Obiettivo**: Comprendere l'effetto di `setuid` in combinazione con `system` e `bash` come `sh`.

**Codice C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilazione e Permessi:**

When a program is compiled, it is assigned certain permissions that determine how it can be executed and accessed by users. These permissions are associated with the program's executable file.

Quando un programma viene compilato, vengono assegnati determinati permessi che determinano come può essere eseguito e accessibile dagli utenti. Questi permessi sono associati al file eseguibile del programma.

The permissions are divided into three categories: owner, group, and others. Each category has three types of permissions: read (r), write (w), and execute (x). The permissions can be represented using numbers as well: read (4), write (2), and execute (1).

I permessi sono divisi in tre categorie: proprietario, gruppo e altri. Ogni categoria ha tre tipi di permessi: lettura (r), scrittura (w) ed esecuzione (x). I permessi possono essere rappresentati anche utilizzando numeri: lettura (4), scrittura (2) ed esecuzione (1).

The permissions can be viewed using the `ls -l` command. The output will display the permissions for the owner, group, and others in the format `rwxrwxrwx`.

I permessi possono essere visualizzati utilizzando il comando `ls -l`. L'output mostrerà i permessi per il proprietario, il gruppo e gli altri nel formato `rwxrwxrwx`.

To change the permissions of a file, the `chmod` command is used. For example, to give the owner read and write permissions, the command `chmod u+rw file` can be used.

Per modificare i permessi di un file, viene utilizzato il comando `chmod`. Ad esempio, per dare al proprietario i permessi di lettura e scrittura, può essere utilizzato il comando `chmod u+rw file`.

It is important to note that changing the permissions of a file can have security implications. Giving excessive permissions to a file can make it vulnerable to unauthorized access or modification.

È importante notare che modificare i permessi di un file può avere implicazioni sulla sicurezza. Dare permessi eccessivi a un file può renderlo vulnerabile ad accessi o modifiche non autorizzate.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `ruid` e `euid` iniziano rispettivamente come 99 (nobody) e 1000 (frank).
* `setuid` allinea entrambi a 1000.
* `system` esegue `/bin/bash -c id` a causa del symlink da sh a bash.
* `bash`, senza `-p`, regola `euid` per corrispondere a `ruid`, risultando entrambi 99 (nobody).

#### Caso 2: Utilizzo di setreuid con system

**Codice C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilazione e Permessi:**

When a program is compiled, it is assigned certain permissions that determine how it can be executed and accessed by users. These permissions are associated with the program's executable file.

Quando un programma viene compilato, vengono assegnati determinati permessi che determinano come può essere eseguito e accessibile dagli utenti. Questi permessi sono associati al file eseguibile del programma.

The permissions are divided into three categories: owner, group, and others. Each category has three types of permissions: read (r), write (w), and execute (x). The permissions can be represented using numbers as well: read (4), write (2), and execute (1).

I permessi sono divisi in tre categorie: proprietario, gruppo e altri. Ogni categoria ha tre tipi di permessi: lettura (r), scrittura (w) ed esecuzione (x). I permessi possono essere rappresentati anche utilizzando numeri: lettura (4), scrittura (2) ed esecuzione (1).

The permissions can be viewed using the `ls -l` command. The output will display the permissions for the owner, group, and others in the format `rwxrwxrwx`.

I permessi possono essere visualizzati utilizzando il comando `ls -l`. L'output mostrerà i permessi per il proprietario, il gruppo e gli altri nel formato `rwxrwxrwx`.

To change the permissions of a file, the `chmod` command is used. For example, to give read, write, and execute permissions to the owner, and only read and execute permissions to the group and others, the command `chmod 755 filename` can be used.

Per modificare i permessi di un file, si utilizza il comando `chmod`. Ad esempio, per dare i permessi di lettura, scrittura ed esecuzione al proprietario e solo i permessi di lettura ed esecuzione al gruppo e agli altri, si può utilizzare il comando `chmod 755 nomefile`.

It is important to note that changing the permissions of a file can have security implications. Giving excessive permissions to a file can make it vulnerable to unauthorized access or modification.

È importante notare che modificare i permessi di un file può avere implicazioni sulla sicurezza. Dare permessi eccessivi a un file può renderlo vulnerabile ad accessi o modifiche non autorizzate.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `setreuid` imposta sia l'ruid che l'euid a 1000.
* `system` invoca bash, che mantiene gli ID utente a causa della loro uguaglianza, operando efficacemente come frank.

#### Caso 3: Utilizzo di setuid con execve
Obiettivo: Esplorare l'interazione tra setuid ed execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* `ruid` rimane 99, ma `euid` viene impostato a 1000, in linea con l'effetto di `setuid`.

**Esempio di codice C 2 (Chiamata a Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

* Anche se `euid` viene impostato a 1000 da `setuid`, `bash` reimposta `euid` a `ruid` (99) a causa dell'assenza di `-p`.

**Esempio di codice C 3 (Utilizzando bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Riferimenti
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata su HackTricks**? O vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al repository [hacktricks](https://github.com/carlospolop/hacktricks) e al repository [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
