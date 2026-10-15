
deployerDeployer1.1.0"/api/deployer*;
GET/api/deployer/v1/configurationsconfigurations:read*@
GET$/api/deployer/v1/configurations/{id}configurations:read*'
GET/api/deployer/v1/jobs	jobs:read*,
GET/api/deployer/v1/jobs/{id}	jobs:read*5
GET#/api/deployer/v1/jobs/{id}/children	jobs:read*4
GET"/api/deployer/v1/jobs/{id}/history	jobs:read*3
GET!/api/deployer/v1/jobs/{id}/result	jobs:read*6
GET/api/deployer/v1/providersconfigurations:read*.
GET/api/deployer/v1/statistics
stats:read*5
GET"/api/deployer/v1/statistics/tenant
stats:read*-
GET/api/deployer/v1/targetstargets:read*2
GET/api/deployer/v1/targets/{id}targets:read*A
GET,/api/deployer/v1/targets/{id}/configurationstargets:read*5
POST/api/deployer/v1/backup/exportbackup:manage*5
POST/api/deployer/v1/backup/importbackup:manage*>
POST/api/deployer/v1/configurationsconfigurations:manage*K
POST(/api/deployer/v1/configurations/validateconfigurations:manage2*J
POST+/api/deployer/v1/configurations/{id}/removeconfigurations:manage*3
POST/api/deployer/v1/deploydeploy:execute2*B
POST&/api/deployer/v1/deploy/configurationsdeploy:execute2*:
POST/api/deployer/v1/deploy/targetdeploy:execute2*E
POST)/api/deployer/v1/deploy/{job_id}/rollbackdeploy:execute2<*C
POST'/api/deployer/v1/deploy/{job_id}/verifydeploy:execute2<*6
POST!/api/deployer/v1/jobs/{id}/canceljobs:manage*5
POST /api/deployer/v1/jobs/{id}/retryjobs:manage*0
POST/api/deployer/v1/targetstargets:manage*D
POST,/api/deployer/v1/targets/{id}/configurationstargets:manage*K
POST3/api/deployer/v1/targets/{id}/configurations/removetargets:manage*<
POST$/api/deployer/v1/targets/{id}/removetargets:manage*B
PUT$/api/deployer/v1/configurations/{id}configurations:manage*4
PUT/api/deployer/v1/targets/{id}targets:manage:_
configurationsreadGList and read deployment endpoint configurations (credentials redacted):W
configurationsmanage=Create, change, delete and validate deployment configurations:C
targetsread2List and read deployment targets and their filters:O
targetsmanage<Create, change and delete deployment targets and attachments:=
jobsread/List and read deployment jobs and their history:0
jobsmanage Cancel and retry deployment jobs:I
deployexecute6Deploy, verify and roll back certificates to endpoints:)
statsreadRead deployment statistics:C
backupmanage1Export and import tenant deployment configurationBJ
read
create
update
deleteDeployerConfiguration:configurations:readB<
read
create
update
deleteDeployerTarget:targets:readB&
read
manageDeployerJob:	jobs:readB%
execute
Deployment:deploy:executeB!
readDeployerStats:
stats:readB'
manageDeployerBackup:backup:manageJ7
/m/deployer/mf-manifest.json./routes./nav./bootRA
	Dashboard	/deployermdi-view-dashboard-outline *
stats:readR9
Targets/deployer/targets
mdi-target š*targets:readRS
Configurations/deployer/configurationsmdi-cog-outline ¤*configurations:readR8
Jobs/deployer/jobsmdi-progress-clock ®*	jobs:read