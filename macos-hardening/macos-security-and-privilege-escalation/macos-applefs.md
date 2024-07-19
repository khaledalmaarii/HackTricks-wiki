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

**Apple File System (APFS)** je moderan fajl sistem dizajniran da zameni Hierarchical File System Plus (HFS+). Njegov razvoj je vođen potrebom za **poboljšanom performansom, sigurnošću i efikasnošću**.

Neke od značajnih karakteristika APFS uključuju:

1. **Deljenje prostora**: APFS omogućava više volumena da **dele isti osnovni slobodni prostor** na jednom fizičkom uređaju. Ovo omogućava efikasnije korišćenje prostora jer volumeni mogu dinamički rasti i opadati bez potrebe za ručnim promenama veličine ili reparticionisanjem.
1. To znači, u poređenju sa tradicionalnim particijama na diskovima, **da u APFS različite particije (volumeni) dele sav prostor na disku**, dok je obična particija obično imala fiksnu veličinu.
2. **Snapshot-ovi**: APFS podržava **kreiranje snapshot-ova**, koji su **samo za čitanje**, tačne instance fajl sistema. Snapshot-ovi omogućavaju efikasne rezervne kopije i jednostavne povratke sistema, jer troše minimalan dodatni prostor i mogu se brzo kreirati ili vratiti.
3. **Kloni**: APFS može **kreirati klonove fajlova ili direktorijuma koji dele isti prostor** kao original dok se ili klon ili originalni fajl ne izmeni. Ova funkcija pruža efikasan način za kreiranje kopija fajlova ili direktorijuma bez dupliranja prostora za skladištenje.
4. **Enkripcija**: APFS **nativno podržava enkripciju celog diska** kao i enkripciju po fajlu i po direktorijumu, poboljšavajući sigurnost podataka u različitim slučajevima korišćenja.
5. **Zaštita od pada**: APFS koristi **shemu metapodataka kopiranja pri pisanju koja osigurava doslednost fajl sistema** čak i u slučajevima iznenadnog gubitka napajanja ili pada sistema, smanjujući rizik od oštećenja podataka.

Sve u svemu, APFS nudi moderniji, fleksibilniji i efikasniji fajl sistem za Apple uređaje, sa fokusom na poboljšanu performansu, pouzdanost i sigurnost.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` volumen je montiran u **`/System/Volumes/Data`** (možete to proveriti sa `diskutil apfs list`).

Lista firmlinks-a može se naći u **`/usr/share/firmlinks`** datoteci.
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
