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


**Originalni post je** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Sažetak

Otkrivena su dva ključa u registru koja su mogla biti pisana od strane trenutnog korisnika:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Preporučeno je da se provere dozvole servisa **RpcEptMapper** koristeći **regedit GUI**, posebno karticu **Effective Permissions** u prozoru **Advanced Security Settings**. Ovaj pristup omogućava procenu dodeljenih dozvola određenim korisnicima ili grupama bez potrebe da se ispituje svaki Access Control Entry (ACE) pojedinačno.

Snimak ekrana je pokazao dozvole dodeljene korisniku sa niskim privilegijama, među kojima je bila istaknuta dozvola **Create Subkey**. Ova dozvola, takođe poznata kao **AppendData/AddSubdirectory**, odgovara nalazima skripte.

Primećena je nemogućnost direktne izmene određenih vrednosti, ali mogućnost kreiranja novih podključeva. Primer koji je istaknut bio je pokušaj izmene vrednosti **ImagePath**, što je rezultiralo porukom o odbijenom pristupu.

Uprkos ovim ograničenjima, identifikovana je potencijalna mogućnost eskalacije privilegija kroz mogućnost korišćenja podključa **Performance** unutar registracione strukture servisa **RpcEptMapper**, podključa koji nije prisutan po defaultu. Ovo bi omogućilo registraciju DLL-a i praćenje performansi.

Konsultovana je dokumentacija o podključe **Performance** i njegovoj upotrebi za praćenje performansi, što je dovelo do razvoja dokaza o konceptu DLL-a. Ovaj DLL, koji demonstrira implementaciju funkcija **OpenPerfData**, **CollectPerfData** i **ClosePerfData**, testiran je putem **rundll32**, potvrđujući njegovu operativnu uspešnost.

Cilj je bio primorati **RPC Endpoint Mapper service** da učita kreirani Performance DLL. Posmatranja su pokazala da izvršavanje WMI klasa upita vezanih za Performance Data putem PowerShell-a rezultira kreiranjem log fajla, omogućavajući izvršavanje proizvoljnog koda pod kontekstom **LOCAL SYSTEM**, čime se dodeljuju povišene privilegije.

Istaknuta je postojanost i potencijalne posledice ove ranjivosti, naglašavajući njenu relevantnost za strategije post-eksploatacije, lateralno kretanje i izbegavanje antivirusnih/EDR sistema.

Iako je ranjivost prvobitno otkrivena nenamerno kroz skriptu, naglašeno je da je njena eksploatacija ograničena na zastarele verzije Windows-a (npr. **Windows 7 / Server 2008 R2**) i zahteva lokalni pristup.

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
