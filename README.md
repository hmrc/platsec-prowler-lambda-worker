
# platsec-prowler-lambda-worker

The platsec-prowler-lambda-worker is a AWS Lambda compromising of a 
docker image.

It is responsible for executing the open source project prowler which scans an AWS environment defined at the account level against a set of rules that can be grouped into defined groups.

Prowler can execute predefined groups as well as custom groups. Platsec has created a default 
group for the MDTP platform that will always get executed.  This lambda is executed by the prowler manager 
https://github.com/hmrc/platsec-lambda-prowler-manager.

AWS accounts on the Platform need to be benchmarked for security compliance on a scheduled basis. Infrastructure that is not compliant needs to be reported to the Teams that own the accounts for remediation. Prowler is an open source tool that tests an AWS account against a set of security and compliance checks that have been written in Bash.
The checks are then grouped together in pre-defined groups. Currently, there are twenty one groups covering common standards such as:

HIPAA
SOC
CIS
as well as more specific technology area groupings around:

networking,
RDS (Relational Database Service)
SageMaker
This solution will deliver the capability of scheduled checks against MDTP’s AWS infrastructure highlighting issues, concerns and best practices against well defined benchmarks.
This project allows for teams to create their own custom checks. A check is essentially a Bash script that executes API calls against the AWS cloud platform.
PlatSec has created a group that is a cut down of CIS level 2 checks and this is to be considered as the baseline security stance that will be run against all accounts.
The baseline checks are called group20_Platsec. These will always be run against all accounts in the organization. Tests set by the teams will be run in addition to the baseline checks. If teams have not set their own checks, the baseline checks will still be run.

##Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

###Prerequisites
You will need the following installed on your machine:

GNU Make
Python version >= 3.8.x
Pipenv
Installing
All dependencies are defined in the Pipfile In the root of the project, run pipenv install

###Running the tests
Tests are run from the project root. Before running tests, you will need to setup the environment. To do this, run make setup

* To run all tests, run make test

### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
