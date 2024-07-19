# Writable Sys Path +Dll Hijacking Privesc

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

## Wprowadzenie

Jeśli odkryłeś, że możesz **zapisywać w folderze System Path** (zauważ, że to nie zadziała, jeśli możesz zapisywać w folderze User Path), istnieje możliwość, że możesz **eskalować uprawnienia** w systemie.

Aby to zrobić, możesz wykorzystać **Dll Hijacking**, gdzie zamierzasz **przejąć bibliotekę ładowaną** przez usługę lub proces z **wyższymi uprawnieniami** niż twoje, a ponieważ ta usługa ładuje Dll, która prawdopodobnie nawet nie istnieje w całym systemie, spróbuje załadować ją z System Path, w którym możesz zapisywać.

Aby uzyskać więcej informacji na temat **czym jest Dll Hijacking**, sprawdź:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Eskalacja uprawnień z Dll Hijacking

### Znalezienie brakującej Dll

Pierwszą rzeczą, którą musisz zrobić, jest **zidentyfikowanie procesu** działającego z **wyższymi uprawnieniami** niż ty, który próbuje **załadować Dll z System Path**, w którym możesz zapisywać.

Problem w tych przypadkach polega na tym, że prawdopodobnie te procesy już działają. Aby znaleźć, które Dll brakuje usługom, musisz uruchomić procmon tak szybko, jak to możliwe (zanim procesy zostaną załadowane). Aby znaleźć brakujące .dll, wykonaj:

* **Utwórz** folder `C:\privesc_hijacking` i dodaj ścieżkę `C:\privesc_hijacking` do **zmiennej środowiskowej System Path**. Możesz to zrobić **ręcznie** lub za pomocą **PS**:
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
* Uruchom **`procmon`** i przejdź do **`Options`** --> **`Enable boot logging`** i naciśnij **`OK`** w oknie dialogowym.
* Następnie **zrestartuj** komputer. Gdy komputer się uruchomi, **`procmon`** zacznie **rejestrować** zdarzenia jak najszybciej.
* Po **uruchomieniu Windows** uruchom ponownie **`procmon`**, powie ci, że działa i **zapyta, czy chcesz zapisać** zdarzenia w pliku. Powiedz **tak** i **zapisz zdarzenia w pliku**.
* **Po** **wygenerowaniu pliku**, **zamknij** otwarte okno **`procmon`** i **otwórz plik ze zdarzeniami**.
* Dodaj te **filtry**, a znajdziesz wszystkie Dll, które niektóre **procesy próbowały załadować** z folderu zapisywalnego System Path:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Przegapione Dll

Uruchamiając to na darmowej **wirtualnej maszynie (vmware) Windows 11** uzyskałem te wyniki:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

W tym przypadku .exe są bezużyteczne, więc je zignoruj, przegapione DLL pochodziły od:

| Usługa                          | Dll                | Linia CMD                                                           |
| ------------------------------- | ------------------ | ------------------------------------------------------------------- |
| Harmonogram zadań (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`         |
| Usługa polityki diagnostycznej (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`               |

Po znalezieniu tego, znalazłem ten interesujący post na blogu, który również wyjaśnia, jak [**nadużyć WptsExtensions.dll do podniesienia uprawnień**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Co właśnie **zamierzamy teraz zrobić**.

### Wykorzystanie

Aby **podnieść uprawnienia**, zamierzamy przejąć bibliotekę **WptsExtensions.dll**. Mając **ścieżkę** i **nazwę**, musimy tylko **wygenerować złośliwy dll**.

Możesz [**spróbować użyć któregokolwiek z tych przykładów**](./#creating-and-compiling-dlls). Możesz uruchomić payloady takie jak: uzyskać powłokę rev, dodać użytkownika, wykonać beacon...

{% hint style="warning" %}
Zauważ, że **nie wszystkie usługi są uruchamiane** z **`NT AUTHORITY\SYSTEM`**, niektóre są również uruchamiane z **`NT AUTHORITY\LOCAL SERVICE`**, co ma **mniejsze uprawnienia** i **nie będziesz mógł stworzyć nowego użytkownika** nadużywając jego uprawnień.\
Jednak ten użytkownik ma uprawnienie **`seImpersonate`**, więc możesz użyć [**potato suite do podniesienia uprawnień**](../roguepotato-and-printspoofer.md). W tym przypadku powłoka rev jest lepszą opcją niż próba stworzenia użytkownika.
{% endhint %}

W momencie pisania usługa **Harmonogram zadań** jest uruchamiana z **Nt AUTHORITY\SYSTEM**.

Mając **wygenerowany złośliwy Dll** (_w moim przypadku użyłem x64 rev shell i uzyskałem powłokę, ale defender ją zabił, ponieważ pochodziła z msfvenom_), zapisz go w zapisywalnym System Path pod nazwą **WptsExtensions.dll** i **zrestartuj** komputer (lub zrestartuj usługę lub zrób cokolwiek, aby ponownie uruchomić dotkniętą usługę/program).

Gdy usługa zostanie ponownie uruchomiona, **dll powinien zostać załadowany i wykonany** (możesz **ponownie użyć** sztuczki **procmon**, aby sprawdzić, czy **biblioteka została załadowana zgodnie z oczekiwaniami**).

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
