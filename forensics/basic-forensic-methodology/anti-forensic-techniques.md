# Timestamps

Um atacante pode estar interessado em **alterar os timestamps de arquivos** para evitar ser detectado.\
É possível encontrar os timestamps dentro do MFT nos atributos `$STANDARD_INFORMATION` __ e __ `$FILE_NAME`.

Ambos os atributos têm 4 timestamps: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

O **Windows explorer** e outras ferramentas mostram a informação de **`$STANDARD_INFORMATION`**.

## TimeStomp - Ferramenta Anti-forense

Esta ferramenta **modifica** a informação de timestamp dentro de **`$STANDARD_INFORMATION`** **mas** **não** a informação dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividade** **suspeita**.

## Usnjrnl

O **USN Journal** (Update Sequence Number Journal), ou Change Journal, é um recurso do sistema de arquivos Windows NT (NTFS) que **mantém um registro de alterações feitas no volume**.\
É possível usar a ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) para procurar modificações neste registro.

![](<../../.gitbook/assets/image (449).png>)

A imagem anterior é o **output** mostrado pela **ferramenta** onde se pode observar que algumas **alterações foram realizadas** no arquivo.

## $LogFile

Todas as alterações de metadados em um sistema de arquivos são registradas para garantir a recuperação consistente de estruturas críticas do sistema de arquivos após uma falha do sistema. Isso é chamado de [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging).\
Os metadados registrados são armazenados em um arquivo chamado “**$LogFile**”, que é encontrado no diretório raiz de um sistema de arquivos NTFS.\
É possível usar ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analisar este arquivo e encontrar alterações.

![](<../../.gitbook/assets/image (450).png>)

Novamente, no output da ferramenta é possível ver que **algumas alterações foram realizadas**.

Usando a mesma ferramenta é possível identificar **para qual tempo os timestamps foram modificados**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Tempo de criação do arquivo
* ATIME: Tempo de modificação do arquivo
* MTIME: Tempo de modificação do registro MFT do arquivo
* RTIME: Tempo de acesso do arquivo

## Comparação `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra forma de identificar arquivos modificados suspeitos seria comparar o tempo em ambos os atributos procurando por **incompatibilidades**.

## Nanosegundos

Os timestamps do **NTFS** têm uma **precisão** de **100 nanosegundos**. Então, encontrar arquivos com timestamps como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

## SetMace - Ferramenta Anti-forense

Esta ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário um sistema operacional ativo para modificar essa informação.

# Ocultação de Dados

NTFS usa um cluster e o tamanho mínimo de informação. Isso significa que se um arquivo ocupa um cluster e meio, o **meio restante nunca será usado** até que o arquivo seja excluído. Então, é possível **ocultar dados neste espaço livre**.

Existem ferramentas como slacker que permitem ocultar dados neste espaço "oculto". No entanto, uma análise do `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![](<../../.gitbook/assets/image (452).png>)

Então, é possível recuperar o espaço livre usando ferramentas como FTK Imager. Note que esse tipo de ferramenta pode salvar o conteúdo ofuscado ou até criptografado.

# UsbKill

Esta é uma ferramenta que **desligará o computador se qualquer alteração nas portas USB** for detectada.\
Uma maneira de descobrir isso seria inspecionar os processos em execução e **revisar cada script python em execução**.

# Distribuições Linux ao Vivo

Essas distribuições são **executadas dentro da memória RAM**. A única maneira de detectá-las é **caso o sistema de arquivos NTFS seja montado com permissões de escrita**. Se for montado apenas com permissões de leitura, não será possível detectar a intrusão.

# Exclusão Segura

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuração do Windows

É possível desativar vários métodos de registro do Windows para tornar a investigação forense muito mais difícil.

## Desativar Timestamps - UserAssist

Esta é uma chave de registro que mantém datas e horas de quando cada executável foi executado pelo usuário.

Desativar o UserAssist requer dois passos:

1. Definir duas chaves de registro, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` e `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, ambas para zero para sinalizar que queremos o UserAssist desativado.
2. Limpar suas subárvores de registro que se parecem com `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Desativar Timestamps - Prefetch

Isso salvará informações sobre os aplicativos executados com o objetivo de melhorar o desempenho do sistema Windows. No entanto, isso também pode ser útil para práticas forenses.

* Executar `regedit`
* Selecionar o caminho do arquivo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Clicar com o botão direito em `EnablePrefetcher` e `EnableSuperfetch`
* Selecionar Modificar em cada um deles para mudar o valor de 1 (ou 3) para 0
* Reiniciar

## Desativar Timestamps - Último Tempo de Acesso

Sempre que uma pasta é aberta de um volume NTFS em um servidor Windows NT, o sistema leva um tempo para **atualizar um campo de timestamp em cada pasta listada**, chamado de último tempo de acesso. Em um volume NTFS muito utilizado, isso pode afetar o desempenho.

1. Abrir o Editor de Registro (Regedit.exe).
2. Navegar até `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Procurar por `NtfsDisableLastAccessUpdate`. Se não existir, adicionar este DWORD e definir seu valor para 1, o que desativará o processo.
4. Fechar o Editor de Registro e reiniciar o servidor.

## Apagar Histórico USB

Todas as **Entradas de Dispositivos USB** são armazenadas no Registro do Windows sob a chave **USBSTOR** que contém subchaves criadas sempre que você conecta um Dispositivo USB ao seu PC ou Laptop. Você pode encontrar esta chave aqui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Apagando isso** você apagará o histórico USB.\
Você também pode usar a ferramenta [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) para ter certeza de que os apagou (e para apagá-los).

Outro arquivo que salva informações sobre os USBs é o arquivo `setupapi.dev.log` dentro de `C:\Windows\INF`. Isso também deve ser excluído.

## Desativar Cópias de Sombra

**Listar** cópias de sombra com `vssadmin list shadowstorage`\
**Apagar** elas executando `vssadmin delete shadow`

Você também pode apagá-las via GUI seguindo os passos propostos em [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Para desativar cópias de sombra:

1. Ir ao botão de início do Windows e digitar "services" na caixa de texto de pesquisa; abrir o programa Serviços.
2. Localizar "Volume Shadow Copy" na lista, destacá-lo e, em seguida, clicar com o botão direito > Propriedades.
3. No menu suspenso "Tipo de inicialização", selecionar Desativado e, em seguida, clicar em Aplicar e OK.

![](<../../.gitbook/assets/image (453).png>)

Também é possível modificar a configuração de quais arquivos serão copiados na cópia de sombra no registro `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Sobrescrever arquivos excluídos

* Você pode usar uma **ferramenta do Windows**: `cipher /w:C` Isso indicará ao cipher para remover quaisquer dados do espaço disponível não utilizado no disco dentro da unidade C.
* Você também pode usar ferramentas como [**Eraser**](https://eraser.heidi.ie)

## Apagar logs de eventos do Windows

* Windows + R --> eventvwr.msc --> Expandir "Logs do Windows" --> Clicar com o botão direito em cada categoria e selecionar "Limpar Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Desativar logs de eventos do Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Dentro da seção de serviços desativar o serviço "Log de Eventos do Windows"
* `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Desativar $UsnJrnl

* `fsutil usn deletejournal /d c:`
