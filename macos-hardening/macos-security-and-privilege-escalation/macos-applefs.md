# macOS AppleFS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repository di github.**

</details>

## File System Proprietario Apple (APFS)

**Apple File System (APFS)** è un moderno file system progettato per sostituire il Hierarchical File System Plus (HFS+). Il suo sviluppo è stato guidato dalla necessità di **migliorare le prestazioni, la sicurezza e l'efficienza**.

Alcune caratteristiche notevoli di APFS includono:

1. **Condivisione dello Spazio**: APFS consente a più volumi di **condividere lo stesso spazio di archiviazione libero** su un singolo dispositivo fisico. Ciò consente un utilizzo dello spazio più efficiente in quanto i volumi possono crescere e ridursi dinamicamente senza la necessità di ridimensionamento o ripartizionamento manuale.
1. Ciò significa, rispetto alle partizioni tradizionali nei dischi file, **che in APFS diverse partizioni (volumi) condividono tutto lo spazio del disco**, mentre una partizione regolare di solito aveva una dimensione fissa.
2. **Snapshot**: APFS supporta la **creazione di snapshot**, che sono istanze del file system **solo lettura** in un determinato momento. Gli snapshot consentono backup efficienti e facili ripristini di sistema, in quanto consumano un minimo di spazio di archiviazione aggiuntivo e possono essere creati o ripristinati rapidamente.
3. **Cloni**: APFS può **creare cloni di file o directory che condividono la stessa archiviazione** dell'originale fino a quando il clone o il file originale viene modificato. Questa funzionalità offre un modo efficiente per creare copie di file o directory senza duplicare lo spazio di archiviazione.
4. **Crittografia**: APFS **supporta nativamente la crittografia dell'intero disco** così come la crittografia per file e directory, migliorando la sicurezza dei dati in diversi casi d'uso.
5. **Protezione da Crash**: APFS utilizza uno schema di metadati di **copia su scrittura che garantisce la coerenza del file system** anche in caso di improvvisa interruzione di corrente o arresto del sistema, riducendo il rischio di corruzione dei dati.

In generale, APFS offre un file system più moderno, flessibile ed efficiente per i dispositivi Apple, con un focus sulle prestazioni migliorate, l'affidabilità e la sicurezza.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Il volume `Data` è montato in **`/System/Volumes/Data`** (puoi verificarlo con `diskutil apfs list`).

L'elenco dei firmlinks può essere trovato nel file **`/usr/share/firmlinks`**.
```bash
cat /usr/share/firmlinks
/AppleInternal	AppleInternal
/Applications	Applications
/Library	Library
[...]
```
A sinistra, c'è il percorso della directory sul volume di sistema, e a destra, il percorso della directory in cui viene mappato sul volume dei dati. Quindi, `/library` --> `/system/Volumes/data/library`
