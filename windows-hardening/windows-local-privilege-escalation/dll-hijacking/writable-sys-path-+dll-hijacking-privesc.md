# Writable Sys Path + Dll Hijacking Privesc

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Uvod

Ako ste otkrili da možete **pisati u fascikli System Path** (imajte na umu da ovo neće raditi ako možete pisati u fascikli User Path), moguće je da biste mogli **doseći privilegije** u sistemu.

Da biste to postigli, možete zloupotrebiti **Dll Hijacking** gde ćete **preoteti biblioteku koja se učitava** od strane servisa ili procesa sa **više privilegija** od vaših, i zato što taj servis učitava Dll koji verovatno ne postoji u celom sistemu, pokušaće da ga učita iz System Path-a gde možete pisati.

Za više informacija o **šta je Dll Hijacking** proverite:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc sa Dll Hijacking

### Pronalaženje nedostajućeg Dll-a

Prva stvar koja vam je potrebna je da **identifikujete proces** koji se izvršava sa **više privilegija** od vas, a koji pokušava **učitati Dll iz System Path-a** u koji možete pisati.

Problem u ovim slučajevima je što su ti procesi verovatno već pokrenuti. Da biste pronašli koji Dll-ovi nedostaju servisima, treba da pokrenete procmon što je pre moguće (pre nego što se procesi učitaju). Dakle, da biste pronašli nedostajuće .dll-ove uradite:

* **Napravite** fasciklu `C:\privesc_hijacking` i dodajte putanju `C:\privesc_hijacking` u **System Path env promenljivu**. To možete uraditi **ručno** ili sa **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Pokrenite **`procmon`** i idite na **`Options`** --> **`Enable boot logging`** i pritisnite **`OK`** u prozoru.
* Zatim, **restartujte** računar. Kada se računar ponovo pokrene, **`procmon`** će početi **snimanje** događaja odmah.
* Kada se **Windows** pokrene, ponovo **izvršite `procmon`**, reći će vam da je već pokrenut i pitati da li želite da **sačuvate** događaje u datoteku. Recite **da** i **sačuvajte događaje u datoteku**.
* Nakon što se datoteka generiše, **zatvorite** otvoreni prozor **`procmon`** i **otvorite datoteku sa događajima**.
* Dodajte ove **filtere** i pronaći ćete sve Dll-ove koje je neki **proces pokušao da učita** iz foldera sa zapisivim sistemskim putem:

<figure><img src="../../../.gitbook/assets/image (942).png" alt=""><figcaption></figcaption></figure>

### Propušteni Dll-ovi

Pokretanjem ovoga na besplatnoj **virtuelnoj (vmware) Windows 11 mašini** dobio sam ove rezultate:

<figure><img src="../../../.gitbook/assets/image (604).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju, .exe su beskorisni, pa ih zanemarite, propušteni DLL-ovi su bili od:

| Servis                         | Dll                | CMD linija                                                           |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nakon pronalaska ovoga, pronašao sam ovaj zanimljiv blog post koji takođe objašnjava kako [**zloupotrebiti WptsExtensions.dll za eskalaciju privilegija**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Što ćemo **sada uraditi**.

### Eksploatacija

Dakle, da bismo **eskaliirali privilegije**, preuzećemo biblioteku **WptsExtensions.dll**. Imajući **putanju** i **ime**, samo treba da **generišemo zlonamerni dll**.

Možete [**pokušati koristiti bilo koji od ovih primera**](./#creating-and-compiling-dlls). Možete pokrenuti naredbe kao što su: dobiti reverznu ljusku, dodati korisnika, izvršiti beacon...

{% hint style="warning" %}
Imajte na umu da **nije svaki servis pokrenut** sa **`NT AUTHORITY\SYSTEM`**, neki se takođe pokreću sa **`NT AUTHORITY\LOCAL SERVICE`** koji ima **manje privilegija** i **nećete moći da kreirate novog korisnika** zloupotrebom njegovih dozvola.\
Međutim, taj korisnik ima privilegiju **`seImpersonate`**, pa možete koristiti [**potato suite za eskalaciju privilegija**](../roguepotato-and-printspoofer.md). Dakle, u ovom slučaju reverzna ljuska je bolja opcija nego pokušaj kreiranja korisnika.
{% endhint %}

Trenutno, servis **Task Scheduler** se pokreće sa **Nt AUTHORITY\SYSTEM**.

Nakon što ste **generisali zlonamerni Dll** (_u mom slučaju sam koristio x64 reverznu ljusku i dobio sam ljusku nazad, ali je defender ubio jer je bio od msfvenom_), sačuvajte ga u zapisivom sistemskom putanju sa imenom **WptsExtensions.dll** i **restartujte** računar (ili ponovo pokrenite servis ili uradite šta god je potrebno da ponovo pokrenete pogođeni servis/program).

Kada se servis ponovo pokrene, **dll bi trebalo da bude učitan i izvršen** (možete **ponovo koristiti** trik sa **procmon** da proverite da li je **biblioteka učitana kako se očekivalo**).
