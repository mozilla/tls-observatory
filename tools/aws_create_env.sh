#!/usr/bin/env bash

# requires: pip install awscli awsebcli

# uncomment to debug
#set -x

fail() {
    echo configuration failed
    exit 1
}

env="$1"
if [[ "$1" != "dev" && "$1" != "stage" && "$1" != "prod" ]];then
    echo "usage: $0 <dev|stage|prod>"
    fail
fi

export AWS_DEFAULT_REGION=us-east-1

datetag=$(date +%Y%m%d%H%M)
identifier=tls-observatory-$env-$datetag
mkdir -p tmp/$identifier

echo "Creating stack $identifier"

# Find the ID of the default VPC
aws ec2 describe-vpcs --filters Name=isDefault,Values=true > tmp/$identifier/defaultvpc.json || fail
vpcid=$(grep -Poi '"vpcid": "(.+)"' tmp/$identifier/defaultvpc.json|cut -d '"' -f 4)
echo "default vpc is $vpcid"

# Create a security group for the database
aws ec2 create-security-group \
    --group-name $identifier \
    --description "access control to TLS Observatory Postgres DB" \
    --vpc-id $vpcid > tmp/$identifier/dbsg.json || fail
dbsg=$(grep -Poi '"groupid": "(.+)"' tmp/$identifier/dbsg.json|cut -d '"' -f 4)
echo "DB security group is $dbsg"

# Create the database
multiaz="--no-multi-az"
dbinstclass="db.t2.medium"
dbstorage=5
if [ $env == "prod" ]; then
    multiaz="--multi-az"
    dbinstclass="db.r3.xlarge"
    dbstorage=500
fi
dbpass=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null| tr -dc _A-Z-a-z-0-9)
aws rds create-db-instance \
    --db-name observatory \
    --db-instance-identifier "$identifier" \
    --vpc-security-group-ids "$dbsg" \
    --allocated-storage "$dbstorage" \
    --db-instance-class "$dbinstclass" \
    --engine postgres \
    --engine-version 9.4.5 \
    --auto-minor-version-upgrade \
    --publicly-accessible \
    --master-username tlsobsadmin \
    --master-user-password "$dbpass" \
    "$multiaz" > tmp/$identifier/rds.json || fail
echo "RDS Postgres database created. username=tlsobsadmin; password='$dbpass'"

# open DB access from this local machine
myip=$(curl https://api.mig.mozilla.org/api/v1/ip)
aws ec2 authorize-security-group-ingress --group-id $dbsg --protocol tcp --port 5432 --cidr "$myip/32" || fail
while true;
do
    dbhost=$(aws rds describe-db-instances --db-instance-identifier $identifier |grep -A 2 -i endpoint|grep -Poi '"Address": "(.+)"'|cut -d '"' -f 4)
    if [ ! -z $dbhost ]; then break; fi
    echo "database is not ready yet. waiting"
    sleep 10
done
echo "$dbhost:5432:observatory:tlsobsadmin:$dbpass" >> ~/.pgpass

# create database schema
psql -U tlsobsadmin -d observatory -h $dbhost -p 5432 -c "\i ../database/schema.sql" || fail
apipass=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null| tr -dc _A-Z-a-z-0-9)
scanpass=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null| tr -dc _A-Z-a-z-0-9)
cat > tmp/$identifier/dbusercreate.sql << EOF
\c postgres
ALTER ROLE tlsobsapi LOGIN PASSWORD '$apipass';
ALTER ROLE tlsobsscanner LOGIN PASSWORD '$scanpass';
EOF
psql -U tlsobsadmin -d observatory -h $dbhost -p 5432 -c "\i tmp/$identifier/dbusercreate.sql" || fail
echo "Observatory database created with users tlsobsapi:$apipass and tlsobsscanner:$scanpass"


# Create an elasticbeantalk application that will have 2 environments: one API and one Scanner
aws elasticbeanstalk create-application \
    --application-name $identifier \
    --description "TLS Observatory $env $datetag" > tmp/$identifier/ebcreateapp.json || fail
echo "ElasticBeanTalk application created"

# Create the EB API environment
sed "s/POSTGRESPASSREPLACEME/$apipass/" ebs-api-options.json > tmp/$identifier/ebs-api-options.json || fail
sed -i "s/POSTGRESHOSTREPLACEME/$dbhost/" tmp/$identifier/ebs-api-options.json || fail
aws elasticbeanstalk create-environment \
    --application-name $identifier \
    --environment-name api$env$datetag \
    --description "TLS Observatory API dev environment" \
    --tags "Key=Owner,Value=cloudops" \
    --solution-stack-name "64bit Amazon Linux 2015.09 v2.0.4 running Docker 1.7.1" \
    --option-settings file://tmp/$identifier/ebs-api-options.json \
    --tier "Name=WebServer,Type=Standard,Version=''" > tmp/$identifier/ebcreateapienv.json || fail
apieid=$(grep -Pi '"EnvironmentId": "(.+)"' tmp/$identifier/ebcreateapienv.json |cut -d '"' -f 4)
echo "API environment $apieid created"

# Create the EB Scanner environment
sed "s/POSTGRESPASSREPLACEME/$scanpass/" ebs-worker-options.json > tmp/$identifier/ebs-worker-options.json || fail
sed -i "s/POSTGRESHOSTREPLACEME/$dbhost/" tmp/$identifier/ebs-worker-options.json || fail
aws elasticbeanstalk create-environment \
    --application-name $identifier \
    --environment-name scanner$env$datetag \
    --description "TLS Observatory Scanner dev environment" \
    --tags "Key=Owner,Value=cloudops" \
    --solution-stack-name "64bit Amazon Linux 2015.09 v2.0.4 running Docker 1.7.1" \
    --tier "Name=Worker,Type=SQS/HTTP,Version=''" \
    --option-settings file://tmp/$identifier/ebs-worker-options.json > tmp/$identifier/ebcreatescanenv.json || fail
scannereid=$(grep -Pi '"EnvironmentId": "(.+)"' tmp/$identifier/ebcreatescanenv.json |cut -d '"' -f 4)
echo "Scanner environment $scannereid created"

# grab the instance ID of the API environment, then its security group, and add that to the RDS security group
while true;
do
    aws elasticbeanstalk describe-environment-resources --environment-id $apieid > tmp/$identifier/ebapidesc.json || fail
    ec2id=$(grep -A 3 -i instances tmp/$identifier/ebapidesc.json | grep -Pi '"id": "(.+)"'|cut -d '"' -f 4)
    if [ ! -z $ec2id ]; then break; fi
    echo "stack is not ready yet. waiting"
    sleep 10
done
aws ec2 describe-instances --instance-ids $ec2id > tmp/$identifier/${ec2id}.json || fail
sgid=$(grep -A 4 -i SecurityGroups tmp/$identifier/${ec2id}.json | grep -Pi '"GroupId": "(.+)"' | cut -d '"' -f 4)
aws ec2 authorize-security-group-ingress --group-id $dbsg --source-group $sgid --protocol tcp --port 5432 || fail
echo "API security group $sgid authorized to connect to database security group $dbsg"

# grab the instance ID of the Scanner environment, then its security group, and add that to the RDS security group
while true;
do
    aws elasticbeanstalk describe-environment-resources --environment-id $scannereid > tmp/$identifier/ebscannerdesc.json || fail
    ec2id=$(grep -A 3 -i instances tmp/$identifier/ebscannerdesc.json | grep -Pi '"id": "(.+)"'|cut -d '"' -f 4)
    if [ ! -z $ec2id ]; then break; fi
    echo "stack is not ready yet. waiting"
    sleep 10
done
aws ec2 describe-instances --instance-ids $ec2id > tmp/$identifier/${ec2id}.json || fail
sgid=$(grep -A 4 -i SecurityGroups tmp/$identifier/${ec2id}.json | grep -Pi '"GroupId": "(.+)"' | cut -d '"' -f 4)
aws ec2 authorize-security-group-ingress --group-id $dbsg --source-group $sgid --protocol tcp --port 5432 || fail
echo "Scanner security group $sgid authorized to connect to database security group $dbsg"

echo "Environment ready. Create the application versions in the elasticbeanstalk web console and deploy your containers."
