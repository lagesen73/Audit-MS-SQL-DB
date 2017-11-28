/**********************************************************************	
   Creation Date: 9-12.2016   			Created By: Børre Lagesen
   Purpose: Perform a simple audit of user's passwords bases on a passwordlist located in this script
   Location: master database
   Output Parameters: None
   Return Status: None
   Called By: None        
   Calls: None
   Data Modifications: None
   Updates: None 
   Version 1.5, 9.12.11.2016   
   Date        Author                      Purpose                                    
   ----------  --------------------------  ---------------------------- 
**********************************************************************/

DECLARE @WeakPwdList TABLE(WeakPwd NVARCHAR(255))
INSERT INTO @WeakPwdList(WeakPwd)
SELECT ''
UNION ALL SELECT '123'
UNION ALL SELECT '1234'
UNION ALL SELECT '12345'
UNION ALL SELECT 'abc'
UNION ALL SELECT 'default'
UNION ALL SELECT 'guest'
UNION ALL SELECT '123456'
UNION ALL SELECT '@@Name123'
UNION ALL SELECT '@@Name'
UNION ALL SELECT '@@Name@@Name'
UNION ALL SELECT 'admin'
UNION ALL SELECT 'Administrator'
UNION ALL SELECT 'admin123'
UNION ALL SELECT 'asdf'
UNION ALL SELECT 'asdfasdf'
UNION ALL SELECT 'sa'
UNION ALL SELECT 'biteme'
UNION ALL SELECT 'hds'
UNION ALL SELECT 'hdssa'
UNION ALL SELECT 'password'
UNION ALL SELECT 'pass'
UNION ALL SELECT 'tRiks2010'
UNION ALL SELECT 'Sverge'
UNION ALL SELECT 'Kristiansand'
UNION ALL SELECT 'Oslo'

SELECT t1.*, REPLACE(t2.WeakPwd,'@@Name',t1.name) As [Password]
FROM sys.sql_logins t1
        INNER JOIN @WeakPwdList t2 ON (PWDCOMPARE(t2.WeakPwd, password_hash) = 1 
                OR PWDCOMPARE(REPLACE(t2.WeakPwd,'@@Name',t1.name),password_hash) = 1) --is the password the same as the user name?
WHERE t1.is_policy_checked = 0