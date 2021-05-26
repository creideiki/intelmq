# -*- coding: utf-8 -*-
"""Microsoft Defender API parser bot

Parses security alerts from Microsoft Defender ATP.

Defender wants to include quite a lot of information that doesn't fit
in IntelMQ's default harmonisation, so it abuses the "extra" namespace
to store its information.

Defender creates alerts of a number of different categories. The bot
will handle the ones specified in the parameter "valid_categories".
Any others will be dumped as a JSON-formatted string in the event
field "extra.alert_string" and sent to the IntelMQ output path
specified as "invalid_path".

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

   "extra.incident.status": "Defender's incident status",
   "extra.malware.category": "Malware category",
   "extra.malware.severity": "Malware severity",
   "extra.time.resolved": "Timestamp when Defender considered this incident resolved",
   "malware.name": "Malware name, if known",
   "source.fqdn": "Hostname of computer generating alert",
   "time.source": "Timestamp of the first event in this Defender incident"
   "source.account": "Account running the malware"

SPDX-FileCopyrightText: 2021 Linköping University <https://liu.se/>
SPDX-License-Identifier: AGPL-3.0-or-later

Parameters:

valid_categories: list of strings, default [ "malware",
                  "unwantedsoftware", "ransomware", "exploit",
                  "credentialaccess" ], event categories to send to
                  the default pipeline.

invalid_path: string, default "invalid", the IntelMQ destination queue
              handling alerts with invalid categories.

"""
from intelmq.lib.bot import ParserBot
from intelmq.lib.harmonization import DateTime
from intelmq.lib.utils import base64_decode

import json
from typing import List


class DefenderParserBot(ParserBot):
    valid_categories: List[str] = ["malware", "unwantedsoftware", "ransomware", "exploit", "credentialaccess"]
    invalid_path: str = "invalid"

    @classmethod
    def add_if_present(self, report, out_field, struct, in_field):
        if struct.get(in_field, None):
            report.add(out_field, struct[in_field])

    @classmethod
    def format_timestamp(self, timestamp):
        return DateTime.convert_from_format(timestamp.split('.')[0] + "+0000", "%Y-%m-%dT%H:%M:%S%z")

    def process(self):
        report = self.receive_message()
        raw_report = base64_decode(report.get("raw"))
        alert = json.loads(raw_report)

        self.logger.debug("Considering alert: %s.", alert)
        event = self.new_event(report)
        event.add("raw", raw_report)

        category = alert.get("category", "unknown")
        if category.casefold() not in self.valid_categories:
            event.add("extra.alert_string", json.dumps(alert, indent=4))
            self.send_message(event, path=self.invalid_path)
            self.acknowledge_message()
            return

        category = alert.get("category", None)
        if category.casefold() == "malware":
            classification = "infected-system"
        elif category.casefold() == "unwantedsoftware":
            classification = "infected-system"
        elif category.casefold() == "ransomware":
            classification = "infected-system"
        elif category.casefold() == "exploit":
            classification = "exploit"
        elif category.casefold() == "credentialaccess":
            classification = "compromised"
        else:
            classification = "undetermined"

        event.add("classification.type", classification)

        if alert.get("relatedUser", None) and \
           alert["relatedUser"].get("userName", None):
            event.add("source.account", alert["relatedUser"]["userName"])

        self.add_if_present(event, "extra.defender_id", alert, "id")
        self.add_if_present(event, "source.fqdn", alert, "computerDnsName")
        self.add_if_present(event, "extra.malware.severity", alert, "severity")
        self.add_if_present(event, "malware.name", alert, "threatName")
        self.add_if_present(event, "extra.malware.category", alert, "category")
        self.add_if_present(event, "extra.incident.status", alert, "status")  # Check if failed?
        self.add_if_present(event, "extra.evidence", alert, "evidence")

        if alert.get("firstEventTime", None):
            event.add("time.source", self.format_timestamp(alert["firstEventTime"]))
        if alert.get("resolvedTime", None):
            event.add("extra.time.resolved", self.format_timestamp(alert["resolvedTime"]))

        self.send_message(event)
        self.acknowledge_message()


BOT = DefenderParserBot
