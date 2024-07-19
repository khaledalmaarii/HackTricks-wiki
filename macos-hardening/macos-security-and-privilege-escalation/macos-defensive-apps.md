# Aplicaciones Defensivas de macOS

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoreará cada conexión realizada por cada proceso. Dependiendo del modo (permitir conexiones en silencio, denegar conexión en silencio y alertar) te **mostrará una alerta** cada vez que se establezca una nueva conexión. También tiene una interfaz gráfica muy agradable para ver toda esta información.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall de Objective-See. Este es un firewall básico que te alertará sobre conexiones sospechosas (tiene una interfaz gráfica, pero no es tan elegante como la de Little Snitch).

## Detección de persistencia

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicación de Objective-See que buscará en varias ubicaciones donde **el malware podría estar persistiendo** (es una herramienta de un solo uso, no un servicio de monitoreo).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Similar a KnockKnock, monitoreando procesos que generan persistencia.

## Detección de keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicación de Objective-See para encontrar **keyloggers** que instalan "event taps" de teclado.
