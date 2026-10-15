
wardenWarden1.1.0"/api/warden"/warden/share*9
DELETE /api/warden/v1/secrets/{id}/totpsecrets:write*0
GET/api/warden/v1/access/checksecrets:read*4
GET/api/warden/v1/access/effectivesecrets:read*4
GET/api/warden/v1/access/resourcessecrets:read*'
GET/api/warden/v1/audit
stats:read*-
GET/api/warden/v1/foldersfolders:manage*2
GET/api/warden/v1/folders/treefolders:manage*2
GET/api/warden/v1/folders/{id}folders:manage*0
GET/api/warden/v1/grantspermissions:manage*(
GET/api/warden/v1/health
stats:read*+
GET/api/warden/v1/secretssecrets:read*2
GET/api/warden/v1/secrets/searchsecrets:read*0
GET/api/warden/v1/secrets/{id}secrets:read*9
GET$/api/warden/v1/secrets/{id}/passwordsecrets:read*8
GET"/api/warden/v1/secrets/{id}/sharessecrets:share*5
GET /api/warden/v1/secrets/{id}/totpsecrets:read*9
GET$/api/warden/v1/secrets/{id}/versionssecrets:read*'
GET/api/warden/v1/stats
stats:read*
GET/warden/share *7
POST/api/warden/v1/backup/exportbackup:manage2x*<
POST/api/warden/v1/backup/importbackup:manage(€€€2x*.
POST/api/warden/v1/foldersfolders:manage*8
POST /api/warden/v1/folders/{id}/movefolders:manage*:
POST"/api/warden/v1/folders/{id}/removefolders:manage*-
POST/api/warden/v1/generatesecrets:read*1
POST/api/warden/v1/grantspermissions:manage*=
POST!/api/warden/v1/grants/{id}/revokepermissions:manage*-
POST/api/warden/v1/secretssecrets:write*7
POST /api/warden/v1/secrets/{id}/movesecrets:write*:
POST"/api/warden/v1/secrets/{id}/removesecrets:delete*9
POST"/api/warden/v1/secrets/{id}/sharessecrets:share*M
POST6/api/warden/v1/secrets/{id}/versions/{version}/restoresecrets:write*%
POST/api/warden/v1/share/open 8*8
POST!/api/warden/v1/shares/{id}/cancelsecrets:share*E
POST(/api/warden/v1/transfer/bitwarden/exporttransfer:export2x*J
POST(/api/warden/v1/transfer/bitwarden/importtransfer:import(€€€2x*L
POST*/api/warden/v1/transfer/bitwarden/validatetransfer:import(€€€2x*2
PUT/api/warden/v1/folders/{id}folders:manage*1
PUT/api/warden/v1/secrets/{id}secrets:write*:
PUT$/api/warden/v1/secrets/{id}/passwordsecrets:write*6
PUT /api/warden/v1/secrets/{id}/totpsecrets:write2&
/warden.v1.Secrets/Getsecrets:read2.
/warden.v1.Secrets/GetPasswordsecrets:read2(
/warden.v1.Secrets/Checksecrets:read:H
secretsread7Read secrets and reveal passwords the caller is granted:A
secretswrite/Create and change secrets the caller is granted:1
secretsdeleteDelete secrets the caller owns:H
secretsshare6Create external shares of secrets the caller may share:H
foldersmanage5Create, move and delete folders the caller is granted:P
permissionsmanage9Grant and revoke access on resources the caller may share:,
transferimportImport Bitwarden exports:H
transferexport4Export secrets to Bitwarden format (bulk disclosure):R
backupmanage@Export and import tenant backups (bulk disclosure with material):2
statsread#Read statistics and the audit trailB;
read
create
update
delete
shareSecret:secrets:readB 
manageFolder:folders:manageB#
manageGrant:permissions:manageB#
importTransfer:transfer:importB#
exportTransfer:transfer:exportB
manageBackup:backup:manageB&
readStatsWardenAudit:
stats:readJ-
/m/warden/mf-manifest.json./routes./navR3
Secrets/wardenmdi-key-variant d*secrets:readRT
Permissions/warden/permissionsmdi-shield-account-outline x*permissions:manageRJ
	Generator/warden/generatormdi-dice-multiple-outline ‚*secrets:read