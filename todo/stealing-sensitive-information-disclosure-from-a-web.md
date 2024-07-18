# Rubare la divulgazione di informazioni sensibili da un Web

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

Se a un certo punto trovi una **pagina web che ti presenta informazioni sensibili basate sulla tua sessione**: Potrebbe riflettere cookie, stampare dettagli della carta di credito o qualsiasi altra informazione sensibile, puoi provare a rubarla.\
Qui ti presento i principali modi per cercare di ottenerla:

* [**CORS bypass**](../pentesting-web/cors-bypass.md): Se riesci a bypassare le intestazioni CORS, sarai in grado di rubare le informazioni eseguendo una richiesta Ajax per una pagina malevola.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Se trovi una vulnerabilità XSS nella pagina, potresti essere in grado di abusarne per rubare le informazioni.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Se non puoi iniettare tag XSS, potresti comunque essere in grado di rubare le informazioni utilizzando altri tag HTML regolari.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Se non c'è protezione contro questo attacco, potresti essere in grado di ingannare l'utente per inviarti i dati sensibili (un esempio [qui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
