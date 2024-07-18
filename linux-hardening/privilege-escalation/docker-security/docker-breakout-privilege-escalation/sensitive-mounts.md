# Mount sensibili

{% hint style="success" %}
Impara e pratica l'hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

L'esposizione di `/proc` e `/sys` senza un'adeguata isolamento dei namespace introduce rischi significativi per la sicurezza, inclusa l'espansione della superficie di attacco e la divulgazione di informazioni. Queste directory contengono file sensibili che, se configurati in modo errato o accessibili da un utente non autorizzato, possono portare alla fuga del container, alla modifica dell'host o fornire informazioni che facilitano ulteriori attacchi. Ad esempio, il montaggio non corretto di `-v /proc:/host/proc` può eludere la protezione di AppArmor a causa della sua natura basata sul percorso, lasciando `/host/proc` non protetto.

**Puoi trovare ulteriori dettagli su ciascuna potenziale vulnerabilità in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilità di procfs

### `/proc/sys`

Questa directory consente l'accesso per modificare le variabili del kernel, di solito tramite `sysctl(2)`, e contiene diverse sottodirectory di interesse:

#### **`/proc/sys/kernel/core_pattern`**

* Descritto in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Consente di definire un programma da eseguire alla generazione del file core con i primi 128 byte come argomenti. Ciò può portare all'esecuzione di codice se il file inizia con un pipe `|`.
*   **Esempio di test ed exploit**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Testa l'accesso in scrittura
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Imposta un gestore personalizzato
sleep 5 && ./crash & # Attiva il gestore
```

#### **`/proc/sys/kernel/modprobe`**

* Dettagliato in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Contiene il percorso al caricatore di moduli del kernel, invocato per il caricamento dei moduli del kernel.
*   **Esempio di controllo dell'accesso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Controlla l'accesso a modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Citato in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Un flag globale che controlla se il kernel va in panico o invoca l'OOM killer quando si verifica una condizione OOM.

#### **`/proc/sys/fs`**

* Come da [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contiene opzioni e informazioni sul file system.
* L'accesso in scrittura può consentire vari attacchi di negazione del servizio contro l'host.

#### **`/proc/sys/fs/binfmt_misc`**

* Consente di registrare interpreti per formati binari non nativi in base al loro numero magico.
* Può portare a escalation dei privilegi o accesso a shell root se `/proc/sys/fs/binfmt_misc/register` è scrivibile.
* Esploito e spiegato in modo dettagliato:
* [Rootkit artigianale tramite binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Tutorial approfondito: [Link al video](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Altri in `/proc`

#### **`/proc/config.gz`**

* Potrebbe rivelare la configurazione del kernel se `CONFIG_IKCONFIG_PROC` è abilitato.
* Utile per gli attaccanti per identificare vulnerabilità nel kernel in esecuzione.

#### **`/proc/sysrq-trigger`**

* Consente di invocare comandi Sysrq, potenzialmente causando riavvii immediati del sistema o altre azioni critiche.
*   **Esempio di riavvio dell'host**:

```bash
echo b > /proc/sysrq-trigger # Riavvia l'host
```

#### **`/proc/kmsg`**

* Espone i messaggi del buffer circolare del kernel.
* Può aiutare negli exploit del kernel, nelle fughe di indirizzi e nel fornire informazioni sensibili sul sistema.

#### **`/proc/kallsyms`**

* Elenca i simboli esportati dal kernel e i loro indirizzi.
* Fondamentale per lo sviluppo di exploit del kernel, specialmente per superare KASLR.
* Le informazioni sugli indirizzi sono limitate con `kptr_restrict` impostato su `1` o `2`.
* Dettagli in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Interfaccia con il dispositivo di memoria del kernel `/dev/mem`.
* Storicamente vulnerabile agli attacchi di escalation dei privilegi.
* Maggiori dettagli in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Rappresenta la memoria fisica del sistema in formato core ELF.
* La lettura può rivelare i contenuti della memoria dell'host e di altri container.
* Le dimensioni del file possono causare problemi di lettura o crash del software.
* Utilizzo dettagliato in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Interfaccia alternativa per `/dev/kmem`, rappresentante la memoria virtuale del kernel.
* Consente la lettura e la scrittura, quindi la modifica diretta della memoria del kernel.

#### **`/proc/mem`**

* Interfaccia alternativa per `/dev/mem`, rappresentante la memoria fisica.
* Consente la lettura e la scrittura, la modifica di tutta la memoria richiede la risoluzione degli indirizzi virtuali in fisici.

#### **`/proc/sched_debug`**

* Restituisce informazioni sulla pianificazione dei processi, aggirando le protezioni dello spazio dei PID.
* Espone nomi dei processi, ID e identificatori cgroup.

#### **`/proc/[pid]/mountinfo`**

* Fornisce informazioni sui punti di mount nel namespace di mount del processo.
* Espone la posizione del `rootfs` o dell'immagine del container.

### Vulnerabilità di `/sys`

#### **`/sys/kernel/uevent_helper`**

* Usato per gestire i `uevent` dei dispositivi del kernel.
* Scrivere su `/sys/kernel/uevent_helper` può eseguire script arbitrari al verificarsi dei `uevent`.
*   **Esempio di exploit**: %%%bash

#### Crea un payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Trova il percorso dell'host dal mount OverlayFS per il container

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### Imposta uevent\_helper su helper malizioso

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

#### Attiva un uevent

echo change > /sys/class/mem/null/uevent

#### Legge l'output

cat /output %%%
#### **`/sys/class/thermal`**

* Controlla le impostazioni della temperatura, potenzialmente causando attacchi DoS o danni fisici.

#### **`/sys/kernel/vmcoreinfo`**

* Rilascia gli indirizzi del kernel, compromettendo potenzialmente il KASLR.

#### **`/sys/kernel/security`**

* Contiene l'interfaccia `securityfs`, permettendo la configurazione dei Moduli di Sicurezza Linux come AppArmor.
* L'accesso potrebbe consentire a un container di disabilitare il suo sistema MAC.

#### **`/sys/firmware/efi/vars` e `/sys/firmware/efi/efivars`**

* Espone interfacce per interagire con le variabili EFI nella NVRAM.
* Una cattiva configurazione o sfruttamento può portare a laptop bloccati o macchine host non avviabili.

#### **`/sys/kernel/debug`**

* `debugfs` offre un'interfaccia di debug "senza regole" al kernel.
* Storia di problemi di sicurezza dovuti alla sua natura non limitata.

### References

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
