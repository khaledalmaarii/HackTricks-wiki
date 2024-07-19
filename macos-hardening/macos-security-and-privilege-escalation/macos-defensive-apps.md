# macOS Defensive Apps

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

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Ele monitorará cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexões silenciosamente e alertar) ele **mostrará um alerta** toda vez que uma nova conexão for estabelecida. Também possui uma interface gráfica muito boa para ver todas essas informações.
* [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. Este é um firewall básico que alertará você sobre conexões suspeitas (possui uma interface gráfica, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de persistência

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que buscará em vários locais onde **malware poderia estar persistindo** (é uma ferramenta de uso único, não um serviço de monitoramento).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Semelhante ao KnockKnock, monitorando processos que geram persistência.

## Detecção de keyloggers

* [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalem "event taps" de teclado.
