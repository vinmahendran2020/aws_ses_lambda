const { GuardDutyClient, ListFindingsCommand, GetFindingsCommand } = require("@aws-sdk/client-guardduty")
const { SESClient, SendRawEmailCommand } = require("@aws-sdk/client-ses");
const moment = require('moment');
const fs = require('fs');
const mimemessage = require('mimemessage');

const filename = '/tmp/findings.csv';
const header = ["AccountID,Severity,Seen,Finding_Type,Region,Description,Link"];
const subject = 'AWS GuardDuty Low Severity Findings'
const messageBody = '   <html>  ' +
  '   <head></head>  ' +
  '   <body>  ' +
  '   <h1>AWS GuardDuty Findings!</h1>  ' +
  '   <p>Please see the attached file for a list of low severity findings.</p>  ' +
  '   </body>  ' +
  '  </html>  '
const severityMapping = {
  "0": "LOW",
  "1": "LOW",
  "2": "LOW",
  "3": "LOW",
  "4": "MEDIUM",
  "5": "MEDIUM",
  "6": "MEDIUM",
  "7": "MEDIUM",
  "8": "HIGH"
};

exports.handler = async (event) => {
  const gdClient = new GuardDutyClient();
  const sesClient = new SESClient();
  const fromAddress = process.env.FROM_ADDRESS || "tri.audit.dxacct@devx.systems";
  const toAddress = process.env.TO_ADDRESS || "tri.audit.dxacct@devx.systems";
  const frequency = parseInt(process.env.FREQUENCY) || 1;

  let limit = moment().subtract(frequency, 'day').valueOf();

  let listParams = {
    DetectorId: 'c4bd2b5a14a3c4d514592c5369ba3484',
    FindingCriteria: {
      Criterion: {
        'severity': {
          Lt: 4
        },
        'updatedAt': {
          GreaterThanOrEqual: limit
        },
      }
    }
  };

  try {
    var listResponse = await gdClient.send(new ListFindingsCommand(listParams));
    const findingIds = listResponse['FindingIds'] || [];

    if (findingIds.length > 0) {
      let getParams = {
        DetectorId: 'c4bd2b5a14a3c4d514592c5369ba3484',
        FindingIds: findingIds
      };

      const getResponse = await gdClient.send(new GetFindingsCommand(getParams));
      console.log("Generating CSV File");
      writeToCSVFile(getResponse['Findings']);

      console.log("Preparing email");
      let emailMessage = prepareEmail({ fromAddress, toAddress });

      let emailParams = {
        RawMessage: {
          Data: Buffer.from(emailMessage.toString())
        }
      };

      const sesResponse = await sesClient.send(new SendRawEmailCommand(emailParams));
      console.log("The email sent", sesResponse);
    }

  } catch (error) {
    console.log("The error", error);
  }
};

function writeToCSVFile(findings = []) {
  fs.writeFileSync(filename, extractAsCSV(findings), err => {
    if (err) {
      console.log('Error writing to csv file', err);
    } else {
      console.log(`Saved as ${filename}`);
    }
  });
}

function extractAsCSV(findings) {
  const rows = findings.map(finding => {
    let mapping = severityMapping[finding.Severity];
    return `${finding.AccountId},${mapping},${finding.UpdatedAt},${finding.Type},${finding.Region},${finding.Description},https://console.aws.amazon.com/guardduty/home?region=${finding.Region}#/findings?search=id=${finding.Id}`
  }
  );
  return header.concat(rows).join("\n");
}

function prepareEmail(address) {
  const mailContent = mimemessage.factory({ contentType: 'multipart/mixed', body: [] });

  mailContent.header('From', address.fromAddress);
  mailContent.header('To', address.toAddress);
  mailContent.header('Subject', subject);

  const alternateEntity = mimemessage.factory({
    contentType: 'multipart/alternate',
    body: []
  });

  const htmlEntity = mimemessage.factory({
    contentType: 'text/html;charset=utf-8',
    body: messageBody
  });

  const plainEntity = mimemessage.factory({
    body: 'The AWS Team.'
  });

  alternateEntity.body.push(htmlEntity);
  alternateEntity.body.push(plainEntity);
  mailContent.body.push(alternateEntity);

  const data = fs.readFileSync(filename);
  const attachmentEntity = mimemessage.factory({
    contentType: 'text/plain',
    contentTransferEncoding: 'base64',
    body: data.toString('base64').replace(/([^\0]{76})/g, "$1\n")
  });
  attachmentEntity.header('Content-Disposition', 'attachment ;filename="findings.csv"');

  mailContent.body.push(attachmentEntity);

  return mailContent;
}
