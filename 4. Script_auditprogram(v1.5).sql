/* 
This script will extract all the relevant data needed to do an security audit

Developed by Kristan Ellingsen
Chaged by Børre Lagesen

Version 1.5, 9.12.11.2016
*/


-- get an overview over installed DBs
:OUT 2.0_a)_Overview(v1.5).csv
select name,crdate from sysdatabases
GO

-- Determine login mode
:OUT 3.1_a)_Methods_of_access(v1.5).csv
xp_loginconfig 'login mode';
GO

-- Determine what DBMS roles differnet users and groups have
:OUT 3.2_a)_dbms_user_roles(v1.5).csv
select * from sys.syslogins
GO

-- Determine what type of user or group can access the DBMS
:OUT 3.2_a)_dbms_user_type(v1.5).csv
select * from sys.server_principals
GO

--this will extract all users from groups and their access to the DBMS
:OUT 3.2_a)_unnested_groups_DBMS(v1.5).csv

declare @winlogins table
(acct_name sysname,
acct_type varchar(10),
act_priv varchar(10),
login_name sysname,
perm_path sysname)

declare @group sysname

declare recscan cursor for
select name from sys.server_principals
where type = 'G' and name not like 'NT%'

open recscan
fetch next from recscan into @group

while @@FETCH_STATUS = 0
begin
insert into @winlogins
exec xp_logininfo @group,'members'
fetch next from recscan into @group
end
close recscan
deallocate recscan

select
r.name,
u.name,
u.type_desc,
wl.login_name,
wl.acct_type
from (select * from sys.server_principals where type = 'R') r
join sys.server_role_members rm on (r.principal_id = rm.role_principal_id)
join (select * from sys.server_principals where type != 'R') u on rm.member_principal_id = u.principal_id
left join @winlogins wl on u.name = wl.perm_path
order by login_name,r.principal_id,u.type_desc,u.name
GO

--Determine who can access the DBs (users and groups). And also: Why is Børre Lagesen in OAG-N such a cool guy?
:OUT 3.3_access_to_DBs(v1.5).csv
DECLARE @DB_USers TABLE
(DBName sysname, UserName sysname, LoginType sysname, AssociatedRole varchar(max),create_date datetime,modify_date datetime)

INSERT @DB_USers
EXEC sp_MSforeachdb
'
use [?]
SELECT ''?'' AS DB_Name,
case prin.name when ''dbo'' then prin.name + '' (''+ (select SUSER_SNAME(owner_sid) from master.sys.databases where name =''?'') + '')'' else prin.name end AS UserName,
prin.type_desc AS LoginType,
isnull(USER_NAME(mem.role_principal_id),'''') AS AssociatedRole ,create_date,modify_date
FROM sys.database_principals prin
LEFT OUTER JOIN sys.database_role_members mem ON prin.principal_id=mem.member_principal_id
WHERE prin.sid IS NOT NULL and prin.sid NOT IN (0x00) and
prin.is_fixed_role <> 1 AND prin.name NOT LIKE ''##%'''

SELECT
dbname,username ,logintype ,create_date ,modify_date ,
STUFF(
(
SELECT ',' + CONVERT(VARCHAR(500),associatedrole)
FROM @DB_USers user2
WHERE
user1.DBName=user2.DBName AND user1.UserName=user2.UserName
FOR XML PATH('')
)
,1,1,'') AS Permissions_user
FROM @DB_USers user1
GROUP BY
dbname,username ,logintype ,create_date ,modify_date
ORDER BY DBName,username
GO

--Confirm that Connect permissions are revoked for 'guest user'
--he is not as cool as Kristian - right Kristian...or
:OUT 3.4_a)_connect_permissions(v1.5).csv
EXEC sp_MSforeachdb
'
use [?]
SELECT ''?'' AS DBName, dpr.name, dpe.permission_name FROM sys.database_permissions dpe JOIN
sys.database_principals dpr ON dpe.grantee_principal_id=dpr.principal_id WHERE dpr.name=''guest'' AND dpe.permission_name=''CONNECT'';'
GO

--Confirm that 'Orphan users' are dropped from sql server databases, should be an empty file
:OUT 3.4_b)_orphan_users(v1.5).csv
EXEC sp_change_users_login @Action='Report';
GO

--Confirm that users runnning SQL Server services are not in the Administrators group
:OUT 3.4_cde)_accounts_running_services(v1.5).csv
select * from sys.dm_server_services
GO

-- Does the local users follow the windows password policy?
:OUT 4_a)_password_policy(v1.5).csv
Select name, is_policy_checked, is_expiration_checked, is_disabled from sys.sql_logins  
GO

-- Does the local users have blank passwords?
:OUT 4_c)_blank_passwords(v1.5).csv
Select name from sys.sql_logins where pwdcompare('', password_hash) = 1
GO

-- Does the local users changed the default passwords, ?
:OUT 4_d)_default_passwords(v1.5).csv
Select name from sys.sql_logins where pwdcompare('default', password_hash) = 1
GO

-- Have all local users not used their name as a password
:OUT 4_e)_password_equal_name(v1.5).csv
Select name  from sys.sql_logins where pwdcompare(name,password_hash)=1;
GO

-- Is surface area reduced?
:OUT 5_abcdefgh)_sys_configuration(v1.5).csv
SELECT name, CAST(value as int) as value_configured, 
CAST(value_in_use as int) as value_in_use 
FROM sys.configurations 
WHERE name IN ('ad hoc distributed queries', 'clr enabled', 'Cross db ownership chaining', 
'Database Mail XPs', 'Ole Automation Procedures', 'Remote access', 'Remote admin connections', 'Scan for startup procs');
GO

-- Is trustworthy set to off?
:OUT 5_i)_trustworthy_property(v1.5).csv
SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb' AND state = 0;
GO

-- Is the instance hidden from the network?
:OUT 5_l)_hidden_inctance(v1.5).csv
DECLARE @getValue INT; EXEC master..xp_instance_regread @rootkey = N'HKEY_LOCAL_MACHINE', 
@key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib', 
@value_name = N'HideInstance', @value = @getValue OUTPUT; SELECT @getValue;
GO

-- Is the default sa account disabled, and no sa accountname in use?
:OUT 5_)mn_SA_account(v1.5).csv
SELECT name, is_disabled,sid FROM sys.server_principals WHERE sid = 0x01 or name= 'sa';
GO

-- Is the commandshell disabled?
:OUT 5_o)_SA_account(v1.5).csv
EXECUTE sp_configure 'show advanced options',1; RECONFIGURE WITH OVERRIDE; EXECUTE sp_configure 'xp_cmdshell';
GO

-- Is 'AUTO_CLOSE OFF' set on contained databases?
:OUT 5_p)_contained_DBs(v1.5).csv
SELECT name, containment, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 and is_auto_close_on = 1;
GO

-- Is 'sa' login name in used?
:OUT 5_q)_contained_DBs(v1.5).csv
SELECT sid, name FROM sys.server_principals WHERE name = 'sa' AND sid <> 0x01;
GO

-- IS 'Maximum number of error log files' is set to greater than or equal to '12'?
:OUT 6_a)_number_of_errorlogs(v1.5).csv
DECLARE @NumErrorLogs int; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs',
 @NumErrorLogs OUTPUT; SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
GO

-- Is 'Default Trace Enabled' Server Configuration Option is set to '1'?
:OUT 6_b)_default_trace(v1.5).csv
SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Default trace enabled';
GO

-- what is the audit log level?
:OUT 6_c)_audit_loglevel(v1.5).csv
XP_loginconfig 'audit level';
GO

-- is 'SQL Server Audit' set to capture both 'failed' and 'successful logins' ?
:OUT 6_d)_audit_logins(v1.5).csv
SELECT S.name AS 'Audit Name' , CASE S.is_state_enabled WHEN 1 THEN 'Y' WHEN 0 THEN 'N' 
END AS 'Audit Enabled' , S.type_desc AS 'Write Location' , SA.name AS 'Audit Specification Name' , 
CASE SA.is_state_enabled WHEN 1 THEN 'Y' WHEN 0 THEN 'N' END AS 'Audit Specification Enabled' , 
SAD.audit_action_name , SAD.audited_result FROM sys.server_audit_specification_details AS SAD 
JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits 
AS S ON SA.audit_guid = S.audit_guid WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');
GO

-- DB version
:OUT 7_a)_DB_version(v1.5).csv
Select @@version
GO




