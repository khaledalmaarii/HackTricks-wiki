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

I seguenti passaggi sono raccomandati per modificare le configurazioni di avvio dei dispositivi e i bootloader come U-boot:

1. **Accedi alla Shell dell'Interprete del Bootloader**:
- Durante l'avvio, premi "0", spazio, o altri "codici magici" identificati per accedere alla shell dell'interprete del bootloader.

2. **Modifica gli Argomenti di Avvio**:
- Esegui i seguenti comandi per aggiungere '`init=/bin/sh`' agli argomenti di avvio, consentendo l'esecuzione di un comando shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Configura un Server TFTP**:
- Configura un server TFTP per caricare immagini su una rete locale:
%%%
#setenv ipaddr 192.168.2.2 #IP locale del dispositivo
#setenv serverip 192.168.2.1 #IP del server TFTP
#saveenv
#reset
#ping 192.168.2.1 #controlla l'accesso alla rete
#tftp ${loadaddr} uImage-3.6.35 #loadaddr prende l'indirizzo in cui caricare il file e il nome del file dell'immagine sul server TFTP
%%%

4. **Utilizza `ubootwrite.py`**:
- Usa `ubootwrite.py` per scrivere l'immagine U-boot e caricare un firmware modificato per ottenere accesso root.

5. **Controlla le Funzionalità di Debug**:
- Verifica se le funzionalità di debug come il logging dettagliato, il caricamento di kernel arbitrari o l'avvio da fonti non affidabili sono abilitate.

6. **Interferenza Hardware Cautelativa**:
- Fai attenzione quando colleghi un pin a terra e interagisci con chip SPI o NAND flash durante la sequenza di avvio del dispositivo, in particolare prima che il kernel si decomprima. Consulta il datasheet del chip NAND flash prima di cortocircuitare i pin.

7. **Configura un Server DHCP Maligno**:
- Imposta un server DHCP maligno con parametri dannosi per un dispositivo da acquisire durante un avvio PXE. Utilizza strumenti come il server ausiliario DHCP di Metasploit (MSF). Modifica il parametro 'FILENAME' con comandi di iniezione di comandi come `'a";/bin/sh;#'` per testare la validazione dell'input per le procedure di avvio del dispositivo.

**Nota**: I passaggi che comportano interazione fisica con i pin del dispositivo (*contrassegnati con asterischi) devono essere affrontati con estrema cautela per evitare di danneggiare il dispositivo.


## References
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
