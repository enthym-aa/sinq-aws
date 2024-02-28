# sinq-aws
Secrets Inquiry for AWS Secrets Manager 

---
**S.Inq** is a command line tool that inspects the secrets in AWS Secrets Manager and inquires the usage patterns.
It generates a report that helps you identify risks and cybersecurity issues regarding the secret values you store in AWS Secrets Manager.

Currently, S.Inq for AWS inspects a single AWS Account at a specified Region in each invocation. 
To inspect multiple accounts and/pr regions you would need run separately per each combination.

The tool prints our basic results to screen and generates a detailed JSON output.

---

payton3 s