<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Informações Básicas

Logstash é usado para coletar, transformar e emitir logs. Isso é realizado usando **pipelines**, que contêm módulos de entrada, filtro e saída. O serviço se torna interessante quando se compromete uma máquina que está executando o Logstash como um serviço.

## Pipelines

O arquivo de configuração do pipeline **/etc/logstash/pipelines.yml** especifica os locais dos pipelines ativos:
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Aqui você pode encontrar os caminhos para os arquivos **.conf**, que contêm os pipelines configurados. Se o **módulo de saída Elasticsearch** for usado, é provável que os **pipelines** **contenham** credenciais válidas para uma instância do Elasticsearch. Essas credenciais geralmente têm mais privilégios, já que o Logstash precisa escrever dados no Elasticsearch. Se curingas forem usados, o Logstash tenta executar todos os pipelines localizados naquela pasta que correspondam ao curinga.

## Privesc com pipelines graváveis

Antes de tentar elevar seus próprios privilégios, você deve verificar qual usuário está executando o serviço logstash, pois será o usuário que você possuirá posteriormente. Por padrão, o serviço logstash é executado com os privilégios do usuário **logstash**.

Verifique se você tem **um** dos direitos necessários:

* Você tem **permissões de escrita** em um arquivo de pipeline **.conf** **ou**
* **/etc/logstash/pipelines.yml** contém um curinga e você tem permissão para escrever na pasta especificada

Além disso, **um** dos requisitos deve ser atendido:

* Você consegue reiniciar o serviço logstash **ou**
* **/etc/logstash/logstash.yml** contém a entrada **config.reload.automatic: true**

Se um curinga for especificado, tente criar um arquivo que corresponda a esse curinga. O seguinte conteúdo pode ser escrito no arquivo para executar comandos:
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
O **intervalo** especifica o tempo em segundos. Neste exemplo, o comando **whoami** é executado a cada 120 segundos. A saída do comando é salva em **/tmp/output.log**.

Se **/etc/logstash/logstash.yml** contiver a entrada **config.reload.automatic: true**, você só precisa esperar até que o comando seja executado, pois o Logstash reconhecerá automaticamente novos arquivos de configuração de pipeline ou quaisquer alterações nas configurações de pipeline existentes. Caso contrário, acione um reinício do serviço logstash.

Se nenhum curinga for usado, você pode aplicar essas alterações a uma configuração de pipeline existente. **Certifique-se de não quebrar nada!**

# Referências

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
