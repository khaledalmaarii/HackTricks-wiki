<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


## Logstash

Logstash é usado para **coletar, transformar e despachar logs** por meio de um sistema conhecido como **pipelines**. Essas pipelines são compostas por estágios de **entrada**, **filtro** e **saída**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração da Pipeline

As pipelines são configuradas no arquivo **/etc/logstash/pipelines.yml**, que lista as localizações das configurações da pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Este arquivo revela onde os arquivos **.conf**, contendo configurações de pipeline, estão localizados. Ao empregar um **módulo de saída do Elasticsearch**, é comum que os **pipelines** incluam **credenciais do Elasticsearch**, que frequentemente possuem privilégios extensos devido à necessidade do Logstash de escrever dados no Elasticsearch. Curetas em caminhos de configuração permitem que o Logstash execute todos os pipelines correspondentes no diretório designado.

### Escalação de Privilégios via Pipelines Graváveis

Para tentar a escalação de privilégios, primeiro identifique o usuário sob o qual o serviço Logstash está em execução, normalmente o usuário **logstash**. Certifique-se de atender a **um** destes critérios:

- Possuir **acesso de escrita** a um arquivo **.conf** de pipeline **ou**
- O arquivo **/etc/logstash/pipelines.yml** usa um curinga, e você pode escrever na pasta de destino

Além disso, **um** destes requisitos deve ser atendido:

- Capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** tem **config.reload.automatic: true** configurado

Dado um curinga na configuração, criar um arquivo que corresponda a este curinga permite a execução de comandos. Por exemplo:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Aqui, **intervalo** determina a frequência de execução em segundos. No exemplo fornecido, o comando **whoami** é executado a cada 120 segundos, com sua saída direcionada para **/tmp/output.log**.

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente novas ou modificadas configurações de pipeline sem a necessidade de reinicialização. Se não houver caractere curinga, modificações ainda podem ser feitas nas configurações existentes, mas é aconselhável ter cautela para evitar interrupções.


## Referências

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
