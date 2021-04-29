# -*- coding: utf-8 -*-
"""Microsoft Defender API collector bot

Fetches security alerts from Microsoft Defender ATP.

Requires credentials as described in
https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide
for an app with permissions to at least Read all alerts and Run
advanced queries.

Defender wants to include quite a lot of information that doesn't fit
in IntelMQ's default harmonisation, so it abuses the "extra" namespace
to store its information.

If the alert was of a category the bot doesn't know how to handle,
dumps a string with the JSON decode of the alert in the event field
"extra.alert_string" and sends it to the IntelMQ output path named
"unhandled".

Output structure:

   "extra.defender_id": "Defender incident ID",
   "extra.evidence": [
      List of "evidence" structures. The format is fixed, but contains
      the union of all fields ever used. Hence, most fields are null,
      and which fields contain useful data depends on the type of
      evidence, which is stored in the "entityType" field.

      Structure:
      {
         "aadUserId": "",
         "accountName": "",
         "detectionStatus": "",
         "domainName": "",
         "entityType": "",
         "evidenceCreationTime": "Timestamp",
         "fileName": "",
         "filePath": "",
         "ipAddress": "",
         "parentProcessCreationTime": "",
         "parentProcessFileName": "",
         "parentProcessFilePath": "",
         "parentProcessId": "",
         "processCommandLine": "",
         "processCreationTime": "",
         "processId": "",
         "registryHive": "",
         "registryKey": "",
         "registryValue": "",
         "registryValueType": "",
         "sha1": "",
         "sha256": "",
         "url": "",
         "userPrincipalName": "",
         "userSid": ""
      }
   ]

   "extra.fileinfo": [

      List of "fileinfo" structures, one for each evidence object of
      type "File". These are linked to the evidence structures through
      the sha1 and sha256 hash values.

      Structure:
      {
         "@odata.context": "https://api-eu.securitycenter.windows.com/api/$metadata#Files/$entity",
         "determinationType": "",
         "determinationValue": "Malware name, if known",
         "fileProductName": "",
         "filePublisher": "",
         "fileType": "",
         "globalFirstObserved": "Timestamp",
         "globalLastObserved": "Timestamp",
         "globalPrevalence": Integer,
         "isPeFile": Boolean,
         "isValidCertificate": "",
         "issuer": "",
         "md5": "Hash",
         "sha1": "Hash",
         "sha256": "Hash",
         "signer": "",
         "signerHash": "",
         "size": Integer
      }
   ]

   "extra.incident.status": "Defender's incident status",
   "extra.malware.category": "Malware category",
   "extra.malware.severity": "Malware severity",
   "extra.time.resolved": "Timestampo when Defender considered this incident resolved",
   "malware.name": "Malware name, if known",
   "source.fqdn": "Hostname of computer generating alert",
   "time.source": "Timestamp of the first event in this Defender incident"
   "source.account": "Account running the malware"

SPDX-FileCopyrightText: 2021 Linköping University <https://liu.se/>
SPDX-License-Identifier: AGPL-3.0-or-later

Parameters:

tenant_id: string, your Office 365 tenant ID.

client_id: string, the client ID you created for this application.

client_secret: string, the secret you created for this application.

lookback: integer, default rate_limit, get events for the last this
          many seconds on every run. Setting this higher than
          rate_limit will yield duplicate events in the overlapping
          time slice, and setting it lower will lose events between
          runs.

rate_limit: integer, no default, number of seconds to sleep between
            runs. Must be >= 2, since the API defaults to throttling
            clients connecting more than 100 times/minute.

"""
from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import unzip, create_request_session
from intelmq.lib.harmonization import DateTime
from intelmq.lib.exceptions import MissingDependencyError

from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from datetime import datetime, timezone, timedelta
import json
from typing import Optional


class DefenderCollectorBot(CollectorBot):
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    lookback: int = 0

    def init(self):
        if BackendApplicationClient is None:
            raise MissingDependencyError("oauthlib-requests")

        if not self.tenant_id:
            raise ConfigurationError("API", "No tenant ID specified")

        if not self.client_id:
            raise ConfigurationError("API", "No client ID specified")

        if not self.client_secret:
            raise ConfigurationError("API", "No client secret specified")

        if self.rate_limit < 2:
            raise ConfigurationError("Runtime", "rate_limit must be >= 2 seconds to avoid throttling")

        if self.lookback == 0:
            self.lookback = self.rate_limit

        self.token_uri = f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/token'
        self.base_uri = "securitycenter.windows.com"
        self.resource_uri = f"https://api.{self.base_uri}"
        self.api_uri = f"https://api-eu.{self.base_uri}/api"
        self.alert_path = "/alerts"
        self.advanced_query_path = "/advancedqueries/run"

    def add_if_present(self, report, out_field, struct, in_field):
        if struct.get(in_field, None):
            report.add(out_field, struct[in_field])

    def process(self):
        client = BackendApplicationClient(client_id=self.client_id)
        oauth = OAuth2Session(client=client)
        oauth.fetch_token(token_url=self.token_uri, client_id=self.client_id, client_secret=self.client_secret,
                          body=f"resource={self.resource_uri}")

        dt = datetime.now(tz=timezone.utc) - timedelta(seconds=self.lookback)
        date_string = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        time_filter = f"?$filter=alertCreationTime ge {date_string}"
        options = "&$expand=evidence"

        self.logger.debug("Fetching alerts: %s", self.api_uri + self.alert_path + time_filter + options)
        r = oauth.get(self.api_uri + self.alert_path + time_filter + options)

        try:
            response = json.loads(r.text)
        except json.decoder.JSONDecodeError as e:
            self.logger.error("Error: %s, Raw: %s", str(e), r.text)
            return

        if "error" in response:
            self.logger.error("API error: %s", response['error'])
            return

        if "value" in response:
            alerts = response["value"]
        else:
            self.logger.error("API response did not contain 'value'. Response: %s", r.text)
            return

        for alert in alerts:
            self.logger.debug("Considering alert: %s", alert)
            category = alert.get("category", "unknown")
            valid_categories = ["malware", "unwantedsoftware", "ransomware", "exploit", "credentialaccess"]
            if category.casefold() not in valid_categories:
                event = self.new_event()
                event.add("feed.url", self.api_uri)
                event.add("raw", str(alert))
                event.add("extra.alert_string", json.dumps(alert, indent=4))
                self.send_message(event, path="unhandled")
                continue

            fileinfo = []
            if alert.get("evidence", None):
                for evidence in alert["evidence"]:
                    if evidence["entityType"].casefold() == "file" and \
                       evidence.get("sha1", None):
                        data = self.get_fileinformation(oauth, evidence["sha1"])
                        if data:
                            fileinfo.append(data)

            username = "Unknown"
            if alert.get("relatedUser", None) and \
               alert["relatedUser"].get("username", None):
                username = alert["relatedUser"]["username"]
            else:
                query = {"Query": f'DeviceEvents | where DeviceId == "{alert["machineId"]}" and ActionType == "AntivirusDetection" | project username=InitiatingProcessAccountName | limit 1'}
                result = self.run_advancedhunting(oauth, query)
                if "error" in result:
                    self.logger.warning("Error fetching username for machine %s: %s", machineid, data["error"])
                if len(result) > 0:
                    username = result[0]["username"]

            event = self.new_event()
            event.add("source.account", username)

            self.add_if_present(event, "extra.defender_id", alert, "id")
            self.add_if_present(event, "source.fqdn", alert, "computerDnsName")
            self.add_if_present(event, "extra.malware.severity", alert, "severity")
            self.add_if_present(event, "malware.name", alert, "threatName")
            self.add_if_present(event, "extra.malware.category", alert, "category")
            self.add_if_present(event, "extra.incident.status", alert, "status")  # Check if failed?
            self.add_if_present(event, "extra.evidence", alert, "evidence")
            if len(fileinfo) > 0:
                event.add("extra.fileinfo", fileinfo)

            if alert.get("firstEventTime", None):
                event.add("time.source", self.format_timestamp(alert["firstEventTime"]))
            if alert.get("resolvedTime", None):
                event.add("extra.time.resolved", self.format_timestamp(alert["resolvedTime"]))

            event.add("feed.url", self.api_uri)
            event.add("raw", str(alert))

            self.send_message(event)

    def format_timestamp(self, timestamp):
        return DateTime.convert_from_format(timestamp.split('.')[0], "%Y-%m-%dT%H:%M:%S")

    def get_fileinformation(self, oauth, sha1):
        result = {}

        r = oauth.get(self.api_uri + "/files/" + str(sha1))
        try:
            result = json.loads(r.text)
            if "error" in result:
                self.logger.warning("Error fetching file information for sha1 %s: %s", sha1, result["error"])
                result = {}
        except json.decoder.JSONDecodeError as e:
            self.logger.error("JSON error getting file information: %s, Raw: %s", str(e), r.text)
        except KeyError as e:
            self.logger.error("Error getting file information: Key not found: %s, Raw: %s", str(e), r.text)
        finally:
            return result

    def run_advancedhunting(self, oauth, query):
        result = []

        r = oauth.post(self.api_uri + self.advanced_query_path, data=json.dumps(query))
        try:
            data = json.loads(r.text)
            if data.get("Results", None):
                result = data["Results"]
        except json.decoder.JSONDecodeError as e:
            self.logger.error("JSON error running advanced hunting query: %s, Raw: %s", str(e), r.text)
        except KeyError as e:
            self.logger.error("Error running advanced hunting query: Key not found: %s, Raw: %s", str(e), r.text)
        finally:
            return result


BOT = DefenderCollectorBot
