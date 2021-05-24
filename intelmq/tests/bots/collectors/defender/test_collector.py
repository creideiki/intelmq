# -*- coding: utf-8 -*-
import json
import unittest
import pathlib
from copy import deepcopy
from unittest.mock import MagicMock, patch

from generatealert import GenerateAlert

import intelmq.lib.test as test
from intelmq.lib.utils import base64_encode
from intelmq.bots.collectors.defender.collector_defender import DefenderCollectorBot


class Mock_Response:
    text: str = ""
    status_code = 200

    def __init__(self, structure):
        self.text = json.dumps(structure)


class Mock_API_Endpoint:
    api_uri = ""
    alert_response = []
    files_response = []
    hunting_response = []

    def __init__(self, api_uri="", alert_response=[], files_response=[], hunting_response=[]):
        self.api_uri = api_uri
        self.alert_response = alert_response
        self.files_response = files_response
        self.hunting_response = hunting_response

    def __call__(self, url, data = None):
        if url.startswith(self.api_uri + "/alerts"):
            return Mock_Response(self.alert_response)
        elif url.startswith(self.api_uri + "/files"):
            return Mock_Response(self.files_response)
        elif url.startswith(self.api_uri + "/advancedqueries/run"):
            return Mock_Response(self.hunting_response)
        else:
            return Mock_Response("Mock API called with unknown URL: " + url)


class TestDefenderCollectorBot(test.BotTestCase, unittest.TestCase):

    @classmethod
    def set_bot(cls):
        cls.bot_reference = DefenderCollectorBot
        cls.sysconfig = {
            "tenant_id": "test_tenant_id",
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "rate_limit": 60,
            "invalid_path": "unhandled",
        }

    @patch('requests_oauthlib.OAuth2Session.fetch_token')
    @patch('requests_oauthlib.OAuth2Session.get')
    def test_api_error(self, oauth2_get_mock, oauth2_fetch_token_mock):
        oauth2_get_mock.return_value = Mock_Response({"error": "Test error"})
        self.allowed_error_count = 1
        self.run_bot()
        self.assertRegexpMatchesLog(pattern="API error: Test error.")

    @patch('requests_oauthlib.OAuth2Session.fetch_token')
    @patch('requests_oauthlib.OAuth2Session.get')
    def test_empty_api_response(self, oauth2_get_mock, oauth2_fetch_token_mock):
        oauth2_get_mock.return_value = Mock_Response({"value": []})
        self.run_bot()
        self.assertOutputQueueLen(0)

    @patch('requests_oauthlib.OAuth2Session.fetch_token')
    @patch('requests_oauthlib.OAuth2Session.get')
    def test_empty_alert(self, oauth2_get_mock, oauth2_fetch_token_mock):
        empty_alert = {}
        oauth2_get_mock.side_effect = Mock_API_Endpoint(api_uri="https://api.securitycenter.windows.com/api",
                                                        alert_response={"value": [empty_alert]})
        self.prepare_bot(destination_queues={
            "_default": "default_output_queue",
            "unhandled": ["unhandled_queue"]
        })
        self.run_bot(prepare=False)
        self.assertOutputQueueLen(0, "_default")
        self.assertOutputQueueLen(1, "unhandled")
        self.assertMessageEqual(0,
                                {
                                    "__type": "Event",
                                    "extra.alert_string": json.dumps(empty_alert),
                                    "feed.accuracy": 100.0,
                                    "feed.name": "Test Bot",
                                    "feed.url": "https://api.securitycenter.windows.com/api",
                                    "raw": base64_encode(json.dumps(empty_alert))
                                },
                                path="unhandled")

    @patch('requests_oauthlib.OAuth2Session.post')
    @patch('requests_oauthlib.OAuth2Session.fetch_token')
    @patch('requests_oauthlib.OAuth2Session.get')
    def test_valid_alert(self, oauth2_get_mock, oauth2_fetch_token_mock, oauth2_post_mock):
        PATH = pathlib.Path(__file__).parent / 'valid_input.json'
        with open(PATH) as handle:
            ALERT = json.loads(handle.read())

        EVIDENCE = deepcopy(ALERT["evidence"])


        oauth2_get_mock.side_effect = Mock_API_Endpoint(api_uri="https://api.securitycenter.windows.com/api",
                                                        alert_response={"value": [ALERT]})

        self.prepare_bot(destination_queues={
            "_default": "default_output_queue",
            "unhandled": ["unhandled_queue"]
        })
        self.run_bot()
        self.assertOutputQueueLen(1, "_default")
        self.assertOutputQueueLen(0, "unhandled")
        self.assertMessageEqual(0,
                                {
                                    "source.account": "user",
                                    "extra.defender_id": "da813763521489057597_72863788520",
                                    "source.fqdn": "computer.example.com",
                                    "extra.malware.severity": "Medium",
                                    "malware.name": "PUA:Win32/Vigua.A",
                                    "extra.malware.category": "Malware",
                                    "extra.incident.status": "Resolved",
                                    "extra.evidence": EVIDENCE,
                                    "extra.fileinfo": [
                                        {
                                            "@odata.context": "https://api-eu.securitycenter.windows.com/api/$metadata#Files/$entity",
                                            "sha1": "554a732d30b643c57b0f2137a99a71525c86bb3e",
                                            "sha256": "c47f81422b07032aee9003469a16fc2458743960eb6d4ce848d6b27ce70fd5e2",
                                            "md5": "2ba0a2c592c949a480eea9e53e8ce225",
                                            "globalPrevalence": 10,
                                            "globalFirstObserved": "2021-01-25T23:20:05.3413115Z",
                                            "globalLastObserved": "2021-05-05T21:26:44.1745187Z",
                                            "size": 251271,
                                            "fileType": None,
                                            "isPeFile": False,
                                            "filePublisher": None,
                                            "fileProductName": None,
                                            "signer": None,
                                            "issuer": None,
                                            "signerHash": None,
                                            "isValidCertificate": None,
                                            "determinationType": "Unknown",
                                            "determinationValue": ""
                                        }
                                    ],
                                    "time.source": "2021-05-24T07:51:49+00:00",
                                    "extra.time.resolved": "2021-05-24T07:51:49+00:00",
                                    "feed.url": "https://api.securitycenter.windows.com/api",
                                    "raw": base64_encode(json.dumps(ALERT))
                                },
                                path="_default")


    # @patch('requests_oauthlib.OAuth2Session.post')
    # @patch('requests_oauthlib.OAuth2Session.fetch_token')
    # @patch('requests_oauthlib.OAuth2Session.get')
    # def test_fuzz_alert(self, oauth2_get_mock, oauth2_fetch_token_mock, oauth2_post_mock):
    #     g = GenerateAlert()
    #     g.use_evidence = True
    #     g.use_only_valid_category = True
    #     g.use_relateduser = True
    #     g.use_real_threats = True
    #     g.use_comments = True

    #     alert = g.create_alert()
    #     advancedhuntingresponse = { "Results": [] }

    #     oauth2_get_mock.side_effect = Mock_API_Endpoint(api_uri="https://api.securitycenter.windows.com/api",
    #                                                     alert_response={"value": [alert]})
    #     oauth2_post_mock.side_effect = Mock_API_Endpoint(api_uri="https://api.securitycenter.windows.com/api",
    #                                                      hunting_response={"value": advancedhuntingresponse})
    #     self.prepare_bot(destination_queues={
    #         "_default": "default_output_queue",
    #         "unhandled": ["unhandled_queue"]
    #     })
    #     self.run_bot()
    #     self.assertOutputQueueLen(1, "_default")
    #     self.assertOutputQueueLen(0, "unhandled")
    #     # self.assertMessageEqual(0,
    #     #                         {
    #     #                             "__type": "Event",
    #     #                             "extra.alert_string": json.dumps(alert),
    #     #                             "feed.accuracy": 100.0,
    #     #                             "feed.name": "Test Bot",
    #     #                             "feed.url": "https://api.securitycenter.windows.com/api",
    #     #                             "raw": base64_encode(json.dumps(alert))
    #     #                         },
    #     #                         path="unhandled")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
