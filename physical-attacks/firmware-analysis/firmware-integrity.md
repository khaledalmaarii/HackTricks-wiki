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

## Integrità del Firmware

Il **firmware personalizzato e/o i binari compilati possono essere caricati per sfruttare le vulnerabilità di integrità o verifica della firma**. I seguenti passaggi possono essere seguiti per la compilazione di un backdoor bind shell:

1. Il firmware può essere estratto utilizzando firmware-mod-kit (FMK).
2. L'architettura del firmware target e l'endianness devono essere identificati.
3. Un cross compiler può essere costruito utilizzando Buildroot o altri metodi adatti per l'ambiente.
4. Il backdoor può essere costruito utilizzando il cross compiler.
5. Il backdoor può essere copiato nella directory /usr/bin del firmware estratto.
6. Il binario QEMU appropriato può essere copiato nel rootfs del firmware estratto.
7. Il backdoor può essere emulato utilizzando chroot e QEMU.
8. Il backdoor può essere accessibile tramite netcat.
9. Il binario QEMU deve essere rimosso dal rootfs del firmware estratto.
10. Il firmware modificato può essere ripacchettato utilizzando FMK.
11. Il firmware con backdoor può essere testato emulandolo con il toolkit di analisi del firmware (FAT) e collegandosi all'IP e alla porta del backdoor target utilizzando netcat.

Se una shell root è già stata ottenuta tramite analisi dinamica, manipolazione del bootloader o test di sicurezza hardware, possono essere eseguiti binari malevoli precompilati come impianti o reverse shell. Strumenti automatizzati per payload/impianto come il framework Metasploit e 'msfvenom' possono essere utilizzati seguendo i seguenti passaggi:

1. L'architettura del firmware target e l'endianness devono essere identificati.
2. Msfvenom può essere utilizzato per specificare il payload target, l'IP dell'attaccante, il numero di porta in ascolto, il tipo di file, l'architettura, la piattaforma e il file di output.
3. Il payload può essere trasferito al dispositivo compromesso e assicurarsi che abbia i permessi di esecuzione.
4. Metasploit può essere preparato per gestire le richieste in arrivo avviando msfconsole e configurando le impostazioni in base al payload.
5. La reverse shell di meterpreter può essere eseguita sul dispositivo compromesso.
6. Le sessioni di meterpreter possono essere monitorate mentre si aprono.
7. Possono essere eseguite attività post-exploitation.

Se possibile, le vulnerabilità all'interno degli script di avvio possono essere sfruttate per ottenere accesso persistente a un dispositivo attraverso i riavvii. Queste vulnerabilità sorgono quando gli script di avvio fanno riferimento, [collegano simbolicamente](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), o dipendono da codice situato in posizioni montate non attendibili come schede SD e volumi flash utilizzati per memorizzare dati al di fuori dei filesystem root.

## Riferimenti
* Per ulteriori informazioni controlla [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
