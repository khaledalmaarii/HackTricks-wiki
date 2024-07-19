# macOS Serijski Broj

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

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


## Osnovne Informacije

Apple uređaji posle 2010. godine imaju serijske brojeve koji se sastoje od **12 alfanumeričkih karaktera**, pri čemu svaki segment prenosi specifične informacije:

- **Prva 3 Karaktera**: Oznaka **mesta proizvodnje**.
- **Karakteri 4 i 5**: Oznaka **godine i nedelje proizvodnje**.
- **Karakteri 6 do 8**: Služe kao **jedinstveni identifikator** za svaki uređaj.
- **Poslednja 4 Karaktera**: Oznaka **broja modela**.

Na primer, serijski broj **C02L13ECF8J2** prati ovu strukturu.

### **Mesta Proizvodnje (Prva 3 Karaktera)**
Određeni kodovi predstavljaju specifične fabrike:
- **FC, F, XA/XB/QP/G8**: Različite lokacije u SAD-u.
- **RN**: Meksiko.
- **CK**: Kork, Irska.
- **VM**: Foxconn, Češka Republika.
- **SG/E**: Singapur.
- **MB**: Malezija.
- **PT/CY**: Koreja.
- **EE/QT/UV**: Tajvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Različite lokacije u Kini.
- **C0, C3, C7**: Specifični gradovi u Kini.
- **RM**: Obnovljeni uređaji.

### **Godina Proizvodnje (4. Karakter)**
Ovaj karakter varira od 'C' (predstavlja prvu polovinu 2010. godine) do 'Z' (druga polovina 2019. godine), pri čemu različita slova označavaju različite polugodišnje periode.

### **Nedelja Proizvodnje (5. Karakter)**
Brojevi 1-9 odgovaraju nedeljama 1-9. Slova C-Y (izuzev samoglasnika i 'S') predstavljaju nedelje 10-27. Za drugu polovinu godine, 26 se dodaje ovom broju.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

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
{% endhint %}
</details>
{% endhint %}hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

{% endhint %}
</details>
{% endhint %}
