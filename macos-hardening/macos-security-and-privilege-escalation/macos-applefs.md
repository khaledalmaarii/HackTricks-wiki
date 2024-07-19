# macOS AppleFS

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
{% endhint %}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** è un file system moderno progettato per sostituire l'Hierarchical File System Plus (HFS+). Il suo sviluppo è stato guidato dalla necessità di **migliorare le prestazioni, la sicurezza e l'efficienza**.

Al alcune caratteristiche notevoli di APFS includono:

1. **Condivisione dello spazio**: APFS consente a più volumi di **condividere lo stesso spazio di archiviazione libero sottostante** su un singolo dispositivo fisico. Questo consente un utilizzo più efficiente dello spazio, poiché i volumi possono crescere e ridursi dinamicamente senza la necessità di ridimensionamenti manuali o ripartizionamenti.
1. Ciò significa, rispetto alle partizioni tradizionali nei dischi file, **che in APFS diverse partizioni (volumi) condividono tutto lo spazio su disco**, mentre una partizione normale aveva solitamente una dimensione fissa.
2. **Snapshot**: APFS supporta **la creazione di snapshot**, che sono istanze **sola lettura** e puntuali del file system. Gli snapshot consentono backup efficienti e facili rollback di sistema, poiché consumano spazio di archiviazione aggiuntivo minimo e possono essere creati o ripristinati rapidamente.
3. **Cloni**: APFS può **creare cloni di file o directory che condividono lo stesso spazio di archiviazione** dell'originale fino a quando il clone o il file originale non vengono modificati. Questa funzione fornisce un modo efficiente per creare copie di file o directory senza duplicare lo spazio di archiviazione.
4. **Crittografia**: APFS **supporta nativamente la crittografia dell'intero disco** così come la crittografia per file e per directory, migliorando la sicurezza dei dati in diversi casi d'uso.
5. **Protezione da crash**: APFS utilizza uno **schema di metadati copy-on-write che garantisce la coerenza del file system** anche in caso di improvvisi blackout o crash di sistema, riducendo il rischio di corruzione dei dati.

In generale, APFS offre un file system più moderno, flessibile ed efficiente per i dispositivi Apple, con un focus su prestazioni, affidabilità e sicurezza migliorate.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Il volume `Data` è montato in **`/System/Volumes/Data`** (puoi verificarlo con `diskutil apfs list`).

La lista dei firmlinks può essere trovata nel file **`/usr/share/firmlinks`**.
```bash
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
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
