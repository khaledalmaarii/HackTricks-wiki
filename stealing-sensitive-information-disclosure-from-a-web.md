# Rubare la divulgazione di informazioni sensibili da un sito web

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Se in qualche momento trovi una **pagina web che ti presenta informazioni sensibili basate sulla tua sessione**: forse sta riflettendo i cookie, o stampando dettagli di carte di credito o qualsiasi altra informazione sensibile, potresti provare a rubarla.\
Qui ti presento i principali modi per provare a farlo:

* [**Bypass di CORS**](pentesting-web/cors-bypass.md): Se riesci a bypassare gli header CORS, sarai in grado di rubare le informazioni eseguendo una richiesta Ajax per una pagina malevola.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Se trovi una vulnerabilità XSS sulla pagina, potresti essere in grado di sfruttarla per rubare le informazioni.
* [**Markup sospeso**](pentesting-web/dangling-markup-html-scriptless-injection/): Se non puoi iniettare tag XSS, potresti comunque essere in grado di rubare le informazioni utilizzando altri tag HTML regolari.
* [**Clickjacking**](pentesting-web/clickjacking.md): Se non c'è protezione contro questo attacco, potresti essere in grado di ingannare l'utente per inviarti i dati sensibili (un esempio [qui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
