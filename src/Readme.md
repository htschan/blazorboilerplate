# Blazor Boilerplate

A Blazor project as cloned and adapted from https://github.com/enkodellc/blazorboilerplate.


# Managing SQL Server

https://docs.microsoft.com/en-us/sql/linux/sql-server-linux-docker-container-configure?view=sql-server-ver15&pivots=cs1-bash


docker exec -it e69e056c702d "bash"

/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P '<YourPassword>'

To finish, typ 'exit'

## Install SQL server command line tools on Ubuntu 20

https://docs.microsoft.com/en-us/sql/linux/quickstart-install-connect-ubuntu?view=sql-server-ver15

## Create Database and User with sqlcmd

/opt/mssql-tools/bin/sqlcmd/sqlcmd -S localhost,1533 -U SA -P '<YourPassword>'

If you omit the password, you will be prompted for it.

create database <database>;
GO
use <database>;
GO
create login <username> with password = '<password>';
GO
use <database>;
CREATE USER <dbuser> FOR LOGIN <username>   
GO  
ALTER ROLE db_owner ADD MEMBER <user>;
GO

--> run application which create database schema

Drop a login
DROP LOGIN login_name ;
GO

## Connection String

https://www.connectionstrings.com/sql-server/

   "ConnectionStrings": {
      "DefaultConnection": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=BlazorBoilerplate;Trusted_Connection=True;MultipleActiveResultSets=true",
      "MssqlDocker": "Server=localhost,1533;Database=BlazorBoilerplate;User Id=yyyyy;Password=xxxxxxx;"
   },


      "MssqlDocker": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=BlazorBoilerplate;Trusted_Connection=True;MultipleActiveResultSets=true",
      "DefaultConnection": "Server=localhost,1533;Database=BlazorBoilerplate;User Id=hts;Password=Axil&311;MultipleActiveResultSets=true",
      "MssqlDockerInside": "Server=sqlserver;Database=BlazorBoilerplate;User Id=hts;Password=Axil&311;MultipleActiveResultSets=true"


## mssqli-cli

https://docs.microsoft.com/en-us/sql/tools/mssql-cli?view=sql-server-ver15



# Other

## WSL logs

C:\Users\<username>\AppData\Roaming\Docker\log\vm
