# SmbExec/ScExec

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

## How it Works

**Smbexec** ni chombo kinachotumika kwa ajili ya utekelezaji wa amri kwa mbali kwenye mifumo ya Windows, sawa na **Psexec**, lakini kinakwepa kuweka faili zozote za uhalifu kwenye mfumo wa lengo.

### Key Points about **SMBExec**

- Inafanya kazi kwa kuunda huduma ya muda (kwa mfano, "BTOBTO") kwenye mashine ya lengo ili kutekeleza amri kupitia cmd.exe (%COMSPEC%), bila kuacha binaries zozote.
- Licha ya mbinu yake ya siri, inazalisha kumbukumbu za matukio kwa kila amri iliyotekelezwa, ikitoa aina ya "shell" isiyoingiliana.
- Amri ya kuungana kwa kutumia **Smbexec** inaonekana kama hii:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Kutekeleza Amri Bila Binaries

- **Smbexec** inaruhusu utekelezaji wa amri moja kwa moja kupitia binPaths za huduma, ikiondoa hitaji la binaries za kimwili kwenye lengo.
- Njia hii ni muhimu kwa kutekeleza amri za mara moja kwenye lengo la Windows. Kwa mfano, kuunganisha nayo moduli ya `web_delivery` ya Metasploit inaruhusu utekelezaji wa payload ya Meterpreter ya PowerShell.
- Kwa kuunda huduma ya mbali kwenye mashine ya mshambuliaji na binPath iliyowekwa kutekeleza amri iliyotolewa kupitia cmd.exe, inawezekana kutekeleza payload kwa mafanikio, kufikia callback na utekelezaji wa payload na msikilizaji wa Metasploit, hata kama makosa ya majibu ya huduma yanatokea.

### Mfano wa Amri

Kuunda na kuanzisha huduma kunaweza kufanywa kwa amri zifuatazo:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
