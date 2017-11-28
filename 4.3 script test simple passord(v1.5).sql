IF OBJECT_ID('dbo.spAuditPasswords') IS NOT NULL
DROP PROCEDURE dbo.spAuditPasswords
GO

CREATE PROCEDURE dbo.spAuditPasswords
AS
/**********************************************************************	
   Creation Date: 03/22/02    			Created By: Randy Dyess
                      				Web Site: www.TransactSQL.Com
                       		 		Email: RandyDyess@TransactSQL.Com
   Purpose: Perform a simple audit of user's passwords
   Test for: user with 
   Location: master database
   Output Parameters: None
   Return Status: None
   Called By: None        
   Calls: None
   Data Modifications: None
   Updates: None                                                                
   Date        Author                      Purpose                                    
   ----------  --------------------------  ---------------------------- 
   Version 1.5, 9.12.11.2016
**********************************************************************/
SET NOCOUNT ON

--Variables
DECLARE @lngCounter INTEGER
DECLARE @lngCounter1 INTEGER
DECLARE @lngLogCount INTEGER
DECLARE @strName VARCHAR(256)

--Create table to hold SQL logins
CREATE TABLE #tLogins
(
numID INTEGER IDENTITY(1,1)
,strLogin SYSNAME NULL
,lngPass INTEGER NULL
)

--Insert non ntuser into temp table
INSERT INTO #tLogins (strLogin)
SELECT name FROM master.dbo.syslogins WHERE isntname = 0
SET @lngLogCount = @@ROWCOUNT

--Determine if password is null and user iis SQL Login
PRINT 'The following logins have blank passwords'
SELECT name AS 'Login Name' FROM master.dbo.syslogins
WHERE password IS NULL
AND isntname = 0


--Determine if password and name are the same
SET @lngCounter = @lngLogCount

WHILE @lngCounter <> 0
BEGIN
	SET @strName = (SELECT strLogin FROM #tLogins WHERE numID = @lngCounter)

	UPDATE #tLogins
	SET lngPass = (SELECT PWDCOMPARE (@strName,(SELECT password FROM master.dbo.syslogins 
	WHERE name = @strName))) 
	WHERE numID = @lngCounter

	SET @lngCounter = @lngCounter - 1
END

PRINT 'The following logins have passwords the same as their login name'
SELECT strLogin AS 'Login Name' FROM #tLogins WHERE lngPass = 1

--Reset column for next password test
UPDATE #tLogins
SET lngPass = 0

--Determine if password is only one characcter long
SET @lngCounter = @lngLogCount

WHILE @lngCounter <> 0
BEGIN
	SET @lngCounter1 = 1
	SET @strName = (SELECT strLogin FROM #tLogins WHERE numID = @lngCounter)
	WHILE @lngCounter1 < 256
	BEGIN
		UPDATE #tLogins
		SET lngPass = (SELECT PWDCOMPARE (CHAR(@lngCounter1),(SELECT password FROM master.dbo.syslogins 
		WHERE name = @strName))) 
		WHERE numID = @lngCounter
		AND lngPass <> 1
		
		SET @lngCounter1 = @lngCounter1 + 1
	END

	SET @lngCounter = @lngCounter - 1
END

PRINT 'The following logins have one character passwords'
SELECT strLogin AS 'Login Name' FROM #tLogins WHERE lngPass = 1
GO

--Test
EXEC dbo.spAuditPasswords
GO