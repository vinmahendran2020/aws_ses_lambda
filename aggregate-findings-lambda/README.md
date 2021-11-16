## Aggregate Findings Lambda
This is the lambda function to aggregate all guardduty findings based on severity and timeframe. This generates an csv report of all aggregated findings and sends an email notification to the subscriber

### Input
The request params are provided as environment variables:

```
FREQUENCY     :    <Any valid number starting from zero> This represents the number of days, findings has to be generated and reported
FROM_ADDRESS  :    <Any valid email address that is registered in AWS SES (Simple Email Service)>
TO_ADDRESS    :    <Any valid email address that is registered in AWS SES (Simple Email Service)> Email address to which notification has to be sent
```

### Output
The response is an csv file generated and emailed as follows:

```
AccountID	Severity	Finding_Type	Region	Description	Link
471159967549	2	UnauthorizedAccess:EC2/SSHBruteForce	us-east-2	114.67.74.5 is performing SSH brute force attacks against i-007e31e7a89c1d132. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.	https://console.aws.amazon.com/guardduty/home?region=us-east-2#/findings?search=id=1abd33780c5c85129c8653e5de93c9e0
350604131916	2	UnauthorizedAccess:EC2/SSHBruteForce	us-east-2	114.67.74.5 is performing SSH brute force attacks against i-0d8ba372145d39032. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.	https://console.aws.amazon.com/guardduty/home?region=us-east-2#/findings?search=id=44bd32e77a21c5901dbd52e9de1b5f4e
855168905564	2	Recon:EC2/PortProbeUnprotectedPort	us-east-2	EC2 instance has an unprotected port which is being probed by a known malicious host.	https://console.aws.amazon.com/guardduty/home?region=us-east-2#/findings?search=id=98bd30c1d9dfefff2acc319e2c3c2ff1

```

### Trigger
This lambda is triggered by CloudWatch Scheduled Event Rule <aws-guardduty-LowSeverity-FindingsEventRule> on everyday 12pm GMT

### Build:
This lambda is built and uploaded to AWS lambda as a zip file
```
npm run build
```


