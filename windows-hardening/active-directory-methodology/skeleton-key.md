# Skeleton Key

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Attacco Skeleton Key

L'**attacco Skeleton Key** è una tecnica sofisticata che consente agli attaccanti di **eludere l'autenticazione di Active Directory** iniettando una password principale nel controller di dominio. Ciò consente all'attaccante di **autenticarsi come qualsiasi utente** senza conoscere la loro password, concedendo loro un **accesso illimitato** al dominio.

Può essere eseguito utilizzando [Mimikatz](https://github.com/gentilkiwi/mimikatz). Per effettuare questo attacco, sono necessari i **diritti di amministratore di dominio**, e l'attaccante deve prendere di mira ogni controller di dominio per garantire una violazione completa. Tuttavia, l'effetto dell'attacco è temporaneo, poiché **riavviare il controller di dominio elimina il malware**, rendendo necessaria una reimplementazione per un accesso continuativo.

**Eseguire l'attacco** richiede un singolo comando: `misc::skeleton`.

## Mitigazioni

Le strategie di mitigazione contro tali attacchi includono il monitoraggio di specifici ID evento che indicano l'installazione di servizi o l'uso di privilegi sensibili. In particolare, cercare l'ID evento di sistema 7045 o l'ID evento di sicurezza 4673 può rivelare attività sospette. Inoltre, eseguire `lsass.exe` come processo protetto può ostacolare significativamente gli sforzi degli attaccanti, poiché ciò richiede loro di utilizzare un driver in modalità kernel, aumentando la complessità dell'attacco.

Ecco i comandi PowerShell per migliorare le misure di sicurezza:

- Per rilevare l'installazione di servizi sospetti, utilizzare: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- In particolare, per rilevare il driver di Mimikatz, può essere utilizzato il seguente comando: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Per rafforzare `lsass.exe`, è consigliabile abilitarlo come processo protetto: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

La verifica dopo un riavvio del sistema è fondamentale per garantire che le misure di protezione siano state applicate con successo. Ciò è possibile tramite: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Riferimenti
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>
