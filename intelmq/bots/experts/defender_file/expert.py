# -*- coding: utf-8 -*-
"""Microsoft Defender API file expert bot

Fetches file information from Microsoft Defender ATP.

Requires credentials as described in
https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide
for an app with permissions to at least Read all alerts and Run
advanced queries.

Defender wants to include quite a lot of information that doesn't fit
in IntelMQ's default harmonisation, so it abuses the "extra" namespace
to store its information.

There is a race condition in the Defender cloud service, where a file
information structure may not be ready for retrieval even though an
alert has been fired recently. To guard against this, any file not
found errors result in retries a maximum of "retries" times, with a
random delay of between "min_wait" and "max_wait" seconds between each
attempt.

Input structure:

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

Output structure:

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

SPDX-FileCopyrightText: 2021 Linköping University <https://liu.se/>
SPDX-License-Identifier: AGPL-3.0-or-later

Parameters:

api_region: string, default None, cloud region for API calls. Either
            None (for worldwide) or one of [ "us", "eu", "uk" ].

tenant_id: string, your Office 365 tenant ID.

client_id: string, the client ID you created for this application.

client_secret: string, the secret you created for this application.

retries: int, default 5, number of times to retry after receiving a
         "file not found" error.

min_wait: int, default 30, minimum number of seconds to wait between
          retry attempts.

max_wait: int, default 60, maximum number of seconds to wait between
          retry attempts.

"""
from intelmq.lib.bot import Bot
from intelmq.lib.utils import create_request_session
from intelmq.lib.harmonization import DateTime
from intelmq.lib.exceptions import ConfigurationError, MissingDependencyError

try:
    from oauthlib.oauth2 import BackendApplicationClient
    from requests_oauthlib import OAuth2Session
except:
    BackendApplicationClient = None

try:
    from tenacity import Retrying, TryAgain, stop_after_attempt, wait_random
except:
    Retrying  = None

from datetime import datetime, timezone, timedelta
import json
from typing import Optional, List


class DefenderFileExpertBot(Bot):
    api_region: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    retries: int = 5
    min_wait: int = 30
    max_wait: int = 60

    def init(self):
        if BackendApplicationClient is None:
            raise MissingDependencyError("oauthlib-requests")
        if Retrying is None:
            raise MissingDependencyError("tenacity")

        if not self.tenant_id:
            raise ConfigurationError("API", "No tenant ID specified")

        if not self.client_id:
            raise ConfigurationError("API", "No client ID specified")

        if not self.client_secret:
            raise ConfigurationError("API", "No client secret specified")

        if self.api_region is None:
            api_host = "api"
        elif self.api_region in ["eu", "uk", "us"]:
            api_host = "api-" + self.api_region
        else:
            raise ConfigurationError("API", f'Unknown API region "{self.api_region}", must be None, "eu", "uk", or "us".')

        self.token_uri = f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/token'
        self.base_uri = "securitycenter.windows.com"
        self.resource_uri = f"https://api.{self.base_uri}"
        self.api_uri = f"https://{api_host}.{self.base_uri}/api"

    def get_fileinformation(self, oauth, sha1):
        result = {}

        try:
            self.logger.debug("Fetching file information for SHA1 %s.", str(sha1))
            for attempt in Retrying(reraise=True,
                                    stop=stop_after_attempt(self.retries),
                                    wait=wait_random(self.min_wait, self.max_wait)):
                with attempt:
                    r = oauth.get(self.api_uri + "/files/" + str(sha1))
                    self.logger.debug("Status: %s, text: %s.", r.status_code, r.text)
                    response = json.loads(r.text)
                    if "error" in response:
                        self.logger.warning("Error fetching file information for SHA1 %s: %s.", sha1, response["error"])
                        if "code" in response["error"] and\
                           response["error"]["code"] == "NotFound":
                            raise TryAgain
                    else:
                        result = response
        except json.decoder.JSONDecodeError as e:
            self.logger.error("JSON error getting file information: %s, Raw: %s.", str(e), r.text)
        except KeyError as e:
            self.logger.error("Error getting file information: Key not found: %s, Raw: %s.", str(e), r.text)
        except TryAgain:
            self.logger.error("Max retries reached while fetching file information for SHA1 %s", str(sha1))
        finally:
            return result

    def process(self):
        event = self.receive_message()

        client = BackendApplicationClient(client_id=self.client_id)
        oauth = OAuth2Session(client=client)
        oauth.fetch_token(token_url=self.token_uri, client_id=self.client_id, client_secret=self.client_secret,
                          body=f"resource={self.resource_uri}")

        fileinfo = []
        if event.get("extra.evidence", None):
            for evidence in event["extra.evidence"]:
                if evidence["entityType"].casefold() == "file" and \
                   evidence.get("sha1", None):
                    data = self.get_fileinformation(oauth, evidence["sha1"])
                    if data:
                        fileinfo.append(data)

        if len(fileinfo) > 0:
            event.add("extra.fileinfo", fileinfo)

        self.send_message(event)
        self.acknowledge_message()


BOT = DefenderFileExpertBot
