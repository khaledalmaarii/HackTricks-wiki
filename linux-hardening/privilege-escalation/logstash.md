{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Logstash

Logstash é usado para **coletar, transformar e despachar logs** através de um sistema conhecido como **pipelines**. Esses pipelines são compostos por estágios de **entrada**, **filtro** e **saída**. Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração do Pipeline

Os pipelines são configurados no arquivo **/etc/logstash/pipelines.yml**, que lista os locais das configurações do pipeline:
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
Este arquivo revela onde os arquivos **.conf**, contendo configurações de pipeline, estão localizados. Ao empregar um **módulo de saída Elasticsearch**, é comum que os **pipelines** incluam **credenciais do Elasticsearch**, que frequentemente possuem privilégios extensos devido à necessidade do Logstash de gravar dados no Elasticsearch. Caracteres curinga em caminhos de configuração permitem que o Logstash execute todos os pipelines correspondentes no diretório designado.

### Escalada de Privilégios via Pipelines Graváveis

Para tentar a escalada de privilégios, primeiro identifique o usuário sob o qual o serviço Logstash está sendo executado, tipicamente o usuário **logstash**. Certifique-se de atender a **um** desses critérios:

- Possuir **acesso de gravação** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usa um curinga, e você pode gravar na pasta de destino

Além disso, **uma** dessas condições deve ser cumprida:

- Capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** tem **config.reload.automatic: true** definido

Dado um curinga na configuração, criar um arquivo que corresponda a esse curinga permite a execução de comandos. Por exemplo:
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
Aqui, **interval** determina a frequência de execução em segundos. No exemplo dado, o comando **whoami** é executado a cada 120 segundos, com sua saída direcionada para **/tmp/output.log**.

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente novas ou modificações nas configurações do pipeline sem precisar de um reinício. Se não houver um caractere curinga, as modificações ainda podem ser feitas nas configurações existentes, mas é aconselhável ter cautela para evitar interrupções.


## Referências
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
