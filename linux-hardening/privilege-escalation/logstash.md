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

Logstash se utiliza para **reunir, transformar y despachar registros** a través de un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **entrada**, **filtro** y **salida**. Un aspecto interesante surge cuando Logstash opera en una máquina comprometida.

### Configuración del Pipeline

Los pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que lista las ubicaciones de las configuraciones del pipeline:
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
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen configuraciones de pipeline. Al emplear un **módulo de salida de Elasticsearch**, es común que los **pipelines** incluyan **credenciales de Elasticsearch**, que a menudo poseen amplios privilegios debido a la necesidad de Logstash de escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten a Logstash ejecutar todos los pipelines que coincidan en el directorio designado.

### Escalación de Privilegios a través de Pipelines Escribibles

Para intentar la escalación de privilegios, primero identifica el usuario bajo el cual se está ejecutando el servicio de Logstash, típicamente el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Poseer **acceso de escritura** a un archivo **.conf** de pipeline **o**
- El archivo **/etc/logstash/pipelines.yml** utiliza un comodín, y puedes escribir en la carpeta de destino

Además, **una** de estas condiciones debe cumplirse:

- Capacidad para reiniciar el servicio de Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene **config.reload.automatic: true** configurado

Dado un comodín en la configuración, crear un archivo que coincida con este comodín permite la ejecución de comandos. Por ejemplo:
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
Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo dado, el comando **whoami** se ejecuta cada 120 segundos, con su salida dirigida a **/tmp/output.log**.

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente nuevas o modificadas configuraciones de pipeline sin necesidad de reiniciar. Si no hay un comodín, aún se pueden hacer modificaciones a las configuraciones existentes, pero se aconseja tener precaución para evitar interrupciones.


## Referencias
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
