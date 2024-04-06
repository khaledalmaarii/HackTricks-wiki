<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Integrità del Firmware

Il **firmware personalizzato e/o i file binari compilati possono essere caricati per sfruttare le vulnerabilità di integrità o di verifica delle firme**. I seguenti passaggi possono essere seguiti per la compilazione di un backdoor bind shell:

1. Il firmware può essere estratto utilizzando firmware-mod-kit (FMK).
2. Dovrebbe essere identificata l'architettura del firmware di destinazione e l'endianness.
3. Può essere creato un compilatore incrociato utilizzando Buildroot o altri metodi adatti all'ambiente.
4. Il backdoor può essere creato utilizzando il compilatore incrociato.
5. Il backdoor può essere copiato nella directory /usr/bin del firmware estratto.
6. Il binario QEMU appropriato può essere copiato nella rootfs del firmware estratto.
7. Il backdoor può essere emulato utilizzando chroot e QEMU.
8. Il backdoor può essere accessibile tramite netcat.
9. Il binario QEMU dovrebbe essere rimosso dalla rootfs del firmware estratto.
10. Il firmware modificato può essere ricompattato utilizzando FMK.
11. Il firmware con backdoor può essere testato emulandolo con il firmware analysis toolkit (FAT) e connettendosi all'IP e alla porta del backdoor di destinazione utilizzando netcat.

Se è già stato ottenuto un shell di root tramite analisi dinamica, manipolazione del bootloader o test di sicurezza hardware, possono essere eseguiti file binari maligni precompilati come implant o reverse shell. Gli strumenti di payload/implant automatizzati come il framework Metasploit e 'msfvenom' possono essere sfruttati seguendo i seguenti passaggi:

1. Dovrebbe essere identificata l'architettura del firmware di destinazione e l'endianness.
2. Msfvenom può essere utilizzato per specificare il payload di destinazione, l'IP dell'host attaccante, il numero di porta di ascolto, il tipo di file, l'architettura, la piattaforma e il file di output.
3. Il payload può essere trasferito al dispositivo compromesso e assicurarsi di avere i permessi di esecuzione.
4. Metasploit può essere preparato per gestire le richieste in ingresso avviando msfconsole e configurando le impostazioni in base al payload.
5. Il reverse shell di meterpreter può essere eseguito sul dispositivo compromesso.
6. Le sessioni di meterpreter possono essere monitorate man mano che si aprono.
7. Possono essere eseguite attività di post-sfruttamento.

Se possibile, possono essere sfruttate vulnerabilità all'interno degli script di avvio per ottenere un accesso persistente a un dispositivo durante i riavvii. Queste vulnerabilità si verificano quando gli script di avvio fanno riferimento, [creano link simbolici](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) o dipendono da codice situato in posizioni montate non attendibili come schede SD e volumi flash utilizzati per archiviare dati al di fuori dei filesystem di root.

## Riferimenti
* Per ulteriori informazioni, consulta [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
