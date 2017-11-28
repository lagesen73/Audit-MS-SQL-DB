:out 99_user_info
select 
name, type_desc, is_disabled, create_date, modify_date, is_policy_checked, is_expiration_checked,
LOGINPROPERTY(name,'BadPasswordCount') AS [BadPasswordCount],
LOGINPROPERTY(name,'BadPasswordTime') AS [BadPasswordTime],
LOGINPROPERTY(name,'DaysUntilExpiration') AS [DaysUntilExpiration],
LOGINPROPERTY(name,'DefaultDatabase') AS [DefaultDatabase],
LOGINPROPERTY(name,'DefaultLanguage') AS [DefaultLanguage],
LOGINPROPERTY(name,'HistoryLength') AS [HistoryLength],
LOGINPROPERTY(name,'IsExpired') AS [IsExpired],
LOGINPROPERTY(name,'IsLocked') AS [IsLocked],
LOGINPROPERTY(name,'IsMustChange') AS [IsMustChange],
LOGINPROPERTY(name,'LockoutTime') AS [LockoutTime],
LOGINPROPERTY(name,'PasswordHash') AS [PasswordHash],
LOGINPROPERTY(name,'PasswordLastSetTime') AS [PasswordLastSetTime],
LOGINPROPERTY(name,'PasswordHashAlgorithm') AS [PasswordHashAlgorithm]
from sys.sql_logins
go