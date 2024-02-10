# Abuso del Socket Docker per l'Elevazione dei Privilegi

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>

Ci sono alcune occasioni in cui hai **accesso al socket Docker** e vuoi usarlo per **elevare i privilegi**. Alcune azioni potrebbero essere molto sospette e potresti voler evitarle, quindi qui puoi trovare diversi flag che possono essere utili per l'elevazione dei privilegi:

### Attraverso il mount

Puoi **montare** diverse parti del **filesystem** in un container in esecuzione come root e **accedervi**.\
Puoi anche **abusare di un mount per l'elevazione dei privilegi** all'interno del container.

* **`-v /:/host`** -> Monta il filesystem dell'host nel container in modo da poter **leggere il filesystem dell'host**.
* Se vuoi **sentirti come se fossi nell'host** ma essere nel container, puoi disabilitare altri meccanismi di difesa utilizzando flag come:
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Questo è simile al metodo precedente, ma qui stiamo **montando il disco del dispositivo**. Quindi, all'interno del container esegui `mount /dev/sda1 /mnt` e puoi **accedere** al **filesystem dell'host** in `/mnt`
* Esegui `fdisk -l` nell'host per trovare il dispositivo `</dev/sda1>` da montare
* **`-v /tmp:/host`** -> Se per qualche motivo puoi **solo montare una directory** dall'host e hai accesso all'interno dell'host. Montala e crea un **`/bin/bash`** con **suid** nella directory montata in modo da poterlo **eseguire dall'host ed elevarti a root**.

{% hint style="info" %}
Nota che potresti non essere in grado di montare la cartella `/tmp` ma puoi montare una **diversa cartella scrivibile**. Puoi trovare directory scrivibili utilizzando: `find / -writable -type d 2>/dev/null`

**Nota che non tutte le directory in una macchina Linux supporteranno il bit suid!** Per verificare quali directory supportano il bit suid, esegui `mount | grep -v "nosuid"` Ad esempio, di solito `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` non supportano il bit suid.

Nota anche che se puoi **montare `/etc`** o qualsiasi altra cartella **contenente file di configurazione**, puoi modificarli dal container Docker come root per **abusarli nell'host** ed elevare i privilegi (forse modificando `/etc/shadow`)
{% endhint %}

### Fuga dal container

* **`--privileged`** -> Con questo flag [rimuovi tutto l'isolamento dal container](docker-privileged.md#what-affects). Verifica le tecniche per [fuggire dai container privilegiati come root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Per [elevare gli accessi abusando delle capacità](../linux-capabilities.md), **concedi quella capacità al container** e disabilita altri metodi di protezione che potrebbero impedire all'exploit di funzionare.

### Curl

In questa pagina abbiamo discusso modi per elevare i privilegi utilizzando i flag di Docker, puoi trovare **modi per abusare di questi metodi utilizzando il comando curl** nella pagina:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) di GitHub.

</details>
