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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Integridad del Firmware

El **firmware personalizado y/o binarios compilados pueden ser subidos para explotar fallos de integridad o verificación de firma**. Se pueden seguir los siguientes pasos para la compilación de un shell de enlace de puerta trasera:

1. El firmware puede ser extraído usando firmware-mod-kit (FMK).
2. Se debe identificar la arquitectura del firmware objetivo y el orden de bytes.
3. Se puede construir un compilador cruzado usando Buildroot u otros métodos adecuados para el entorno.
4. La puerta trasera puede ser construida usando el compilador cruzado.
5. La puerta trasera puede ser copiada al directorio /usr/bin del firmware extraído.
6. El binario QEMU apropiado puede ser copiado al rootfs del firmware extraído.
7. La puerta trasera puede ser emulada usando chroot y QEMU.
8. La puerta trasera puede ser accedida a través de netcat.
9. El binario QEMU debe ser eliminado del rootfs del firmware extraído.
10. El firmware modificado puede ser reempaquetado usando FMK.
11. El firmware con puerta trasera puede ser probado emulándolo con un kit de herramientas de análisis de firmware (FAT) y conectándose a la IP y puerto de la puerta trasera objetivo usando netcat.

Si ya se ha obtenido un shell root a través de análisis dinámico, manipulación del cargador de arranque o pruebas de seguridad de hardware, se pueden ejecutar binarios maliciosos precompilados como implantes o shells reversos. Se pueden aprovechar herramientas automatizadas de carga útil/implante como el marco Metasploit y 'msfvenom' usando los siguientes pasos:

1. Se debe identificar la arquitectura del firmware objetivo y el orden de bytes.
2. Msfvenom puede ser utilizado para especificar la carga útil objetivo, la IP del host atacante, el número de puerto de escucha, el tipo de archivo, la arquitectura, la plataforma y el archivo de salida.
3. La carga útil puede ser transferida al dispositivo comprometido y asegurarse de que tenga permisos de ejecución.
4. Metasploit puede ser preparado para manejar solicitudes entrantes iniciando msfconsole y configurando los ajustes de acuerdo con la carga útil.
5. El shell reverso de meterpreter puede ser ejecutado en el dispositivo comprometido.
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
