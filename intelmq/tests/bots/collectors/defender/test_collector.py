# -*- coding: utf-8 -*-
import json
import unittest
from unittest.mock import MagicMock, patch

from generatealert import GenerateAlert

import intelmq.lib.test as test
from intelmq.lib.utils import base64_encode
from intelmq.bots.collectors.defender.collector_defender import DefenderCollectorBot


class Mock_Response:
    text: str = ""

    def __init__(self, structure):
        self.text = json.dumps(structure)


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
        oauth2_get_mock.return_value = Mock_Response({"value": [empty_alert]})
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
