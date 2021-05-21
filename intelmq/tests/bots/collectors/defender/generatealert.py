from random import randrange, choice
from uuid import uuid4
from datetime import datetime, timezone
import json
import hashlib

class GenerateAlert:
    THREATS = [
        {"threatFamilyName": "Adware", "threatName": "Adware:macOS/Adware.MAC.Unzip.B"},
        {"threatFamilyName": "AskToolbar", "threatName": "PUA:Win32/AskToolbar"},
        {"threatFamilyName": "AutoItinject", "threatName": "Trojan:Win32/AutoItinject!ibt"},
        {"threatFamilyName": "AutoKMS", "threatName": "HackTool:Win32/AutoKMS!rfn"},
        {"threatFamilyName": "Autorun", "threatName": "Worm:VBS/Autorun!inf"},
        {"threatFamilyName": "Bandoo", "threatName": "PUA:Win32/Bandoo"},
        {"threatFamilyName": "Bitrepeyp", "threatName": "PUA:Win32/Bitrepeyp.B"},
        {"threatFamilyName": "BitTorrent", "threatName": "PUA:Win32/BitTorrent"},
        {"threatFamilyName": "Bundlore", "threatName": "PUA:MacOS/Bundlore"},
        {"threatFamilyName": "CandyOpen", "threatName": "PUA:Win32/CandyOpen"},
        {"threatFamilyName": "CoinMiner", "threatName": "PUA:Win32/CoinMiner"},
        {"threatFamilyName": "Conduit", "threatName": "PUA:Win32/Conduit"},
        {"threatFamilyName": "Conteban", "threatName": "Trojan:Script/Conteban.A!ml"},
        {"threatFamilyName": "Creprote", "threatName": "PUA:Win32/Creprote"},
        {"threatFamilyName": "Daemon_Tools_Lite_BundleInstaller", "threatName": "App:Daemon_Tools_Lite_BundleInstaller"},
        {"threatFamilyName": "DefenseEvasion", "threatName": "Behavior:Win32/DefenseEvasion.DR!ml"},
        {"threatFamilyName": "Deluge", "threatName": "PUA:Win32/Deluge"},
        {"threatFamilyName": "DownloadGuide", "threatName": "PUA:Win32/DownloadGuide"},
        {"threatFamilyName": "DoyoAds", "threatName": "PUA:Win32/DoyoAds"},
        {"threatFamilyName": "EaseUS_BundleInstaller", "threatName": "App:EaseUS_BundleInstaller"},
        {"threatFamilyName": "EICAR_Test_File", "threatName": "Virus:DOS/EICAR_Test_File"},
        {"threatFamilyName": "FileZilla_BundleInstaller", "threatName": "App:FileZilla_BundleInstaller"},
        {"threatFamilyName": "Foxit_Reader_BundleInstaller", "threatName": "App:Foxit_Reader_BundleInstaller"},
        {"threatFamilyName": "Fuerboos", "threatName": "Trojan:Win32/Fuerboos.B!cl"},
        {"threatFamilyName": "Funvalget", "threatName": "Backdoor:PHP/Funvalget.A"},
        {"threatFamilyName": "Generic", "threatName": "Virus:macOS/Generic.Peed.Eml.1.14339EFC"},
        {"threatFamilyName": "Graphez", "threatName": "EUS:Win32/Graphez!cl"},
        {"threatFamilyName": "Haknata", "threatName": "Ransom:Win32/Haknata"},
        {"threatFamilyName": "HostsFileHijack", "threatName": "SettingsModifier:Win32/HostsFileHijack"},
        {"threatFamilyName": "ICBundler", "threatName": "PUA:Win32/ICBundler"},
        {"threatFamilyName": "InstallCore", "threatName": "PUA:Win32/InstallCore"},
        {"threatFamilyName": "IObit", "threatName": "PUA:Win32/IObit"},
        {"threatFamilyName": "Java", "threatName": "Virus:macOS/Java.Trojan.GenericGB.3372"},
        {"threatFamilyName": "Keydump", "threatName": "HackTool:Win32/Keydump"},
        {"threatFamilyName": "Keygen", "threatName": "PUA:Win32/Keygen"},
        {"threatFamilyName": "Lodi", "threatName": "Misleading:Win32/Lodi"},
        {"threatFamilyName": "Mikatz", "threatName": "HackTool:Win64/Mikatz!dha"},
        {"threatFamilyName": "Mimikatz", "threatName": "HackTool:Win32/Mimikatz.D"},
        {"threatFamilyName": "Mimilove", "threatName": "HackTool:Win32/Mimilove.A!dha"},
        {"threatFamilyName": "MiniTool_Partition_Wizard_BundleInstaller", "threatName": "App:MiniTool_Partition_Wizard_BundleInstaller"},
        {"threatFamilyName": "Mintluks", "threatName": "PWS:MSIL/Mintluks"},
        {"threatFamilyName": "Mountsi", "threatName": "Trojan:PowerShell/Mountsi.A!ml"},
        {"threatFamilyName": "MyWebSearch", "threatName": "PUA:Win32/MyWebSearch"},
        {"threatFamilyName": "Nemucod", "threatName": "Trojan:JS/Nemucod.S!MSR"},
        {"threatFamilyName": "NewDotNet", "threatName": "Adware:Win32/NewDotNet"},
        {"threatFamilyName": "NiceHashMiner", "threatName": "App:NiceHashMiner"},
        {"threatFamilyName": "Obfuse", "threatName": "TrojanDownloader:O97M/Obfuse.LBC!MTB"},
        {"threatFamilyName": "Oneeva", "threatName": "Trojan:Script/Oneeva.A!ml"},
        {"threatFamilyName": "Patcher", "threatName": "HackTool:Win32/Patcher"},
        {"threatFamilyName": "PDFCreator_BundleInstaller", "threatName": "App:PDFCreator_BundleInstaller"},
        {"threatFamilyName": "Phish", "threatName": "Trojan:PDF/Phish.RR!MTB"},
        {"threatFamilyName": "Phonzy", "threatName": "Trojan:Script/Phonzy.A!ml"},
        {"threatFamilyName": "PiriformBundler", "threatName": "PUA:Win32/PiriformBundler"},
        {"threatFamilyName": "Poweriso_BundleInstaller", "threatName": "App:Poweriso_BundleInstaller"},
        {"threatFamilyName": "Presenoker", "threatName": "PUA:Win32/Presenoker"},
        {"threatFamilyName": "ProductKey", "threatName": "HackTool:Win64/ProductKey.G!MSR"},
        {"threatFamilyName": "QBitTorrent", "threatName": "PUA:Win32/QBitTorrent"},
        {"threatFamilyName": "Qjwmonkey", "threatName": "PUA:Win32/Qjwmonkey"},
        {"threatFamilyName": "RelevantKnowledge", "threatName": "PUA:Win32/RelevantKnowledge"},
        {"threatFamilyName": "RemoteAdmin", "threatName": "HackTool:Win32/RemoteAdmin"},
        {"threatFamilyName": "Rimecud", "threatName": "Worm:Win32/Rimecud!inf"},
        {"threatFamilyName": "Sfone", "threatName": "Trojan:Win32/Sfone"},
        {"threatFamilyName": "Shellcode", "threatName": "Exploit:HTML/Shellcode!MSR"},
        {"threatFamilyName": "Skeeyah", "threatName": "Trojan:Win32/Skeeyah"},
        {"threatFamilyName": "SlimWare_DriverUpdate", "threatName": "App:SlimWare_DriverUpdate"},
        {"threatFamilyName": "SoftDownloader", "threatName": "App:SoftDownloader"},
        {"threatFamilyName": "Somoto", "threatName": "PUA:Win32/Somoto"},
        {"threatFamilyName": "SpeedingUpMyPC", "threatName": "PUA:Win32/SpeedingUpMyPC"},
        {"threatFamilyName": "Spursint", "threatName": "Trojan:Win32/Spursint.F!cl"},
        {"threatFamilyName": "Tnega", "threatName": "Trojan:JS/Tnega!MSR"},
        {"threatFamilyName": "Trojan", "threatName": "Virus:macOS/Trojan.GenericKD.36249815"},
        {"threatFamilyName": "Ulthar", "threatName": "Trojan:Script/Ulthar.A!ml"},
        {"threatFamilyName": "Ulubione", "threatName": "Dialer:Win32/Ulubione"},
        {"threatFamilyName": "URL", "threatName": "Virus:macOS/URL.Spam.Heur.4"},
        {"threatFamilyName": "uTorrent", "threatName": "PUA:Win32/uTorrent"},
        {"threatFamilyName": "Utorrent_BundleInstaller", "threatName": "App:Utorrent_BundleInstaller"},
        {"threatFamilyName": "Uwamson", "threatName": "Program:Win32/Uwamson.A!ml"},
        {"threatFamilyName": "VB", "threatName": "Virus:macOS/VB:Trojan.VBA.Agent.XL"},
        {"threatFamilyName": "VBA", "threatName": "Virus:macOS/VBA.Heur2.Askatu.2.F57BF721.Gen"},
        {"threatFamilyName": "Vigram", "threatName": "Program:Win32/Vigram.A"},
        {"threatFamilyName": "Vigua", "threatName": "PUA:Win32/Vigua.A"},
        {"threatFamilyName": "Vittalia", "threatName": "PUA:Win32/Vittalia"},
        {"threatFamilyName": "Vobfus", "threatName": "Worm:Win32/Vobfus"},
        {"threatFamilyName": "Vortex", "threatName": "Exploit:iPhoneOS/Vortex.C"},
        {"threatFamilyName": "W97M", "threatName": "Virus:macOS/W97M.Downloader.HYS"},
        {"threatFamilyName": "Wacatac", "threatName": "Trojan:Win32/Wacatac.A!ml"},
        {"threatFamilyName": "Woreflint", "threatName": "Trojan:Win32/Woreflint.A!cl"},
        {"threatFamilyName": "Ymacco", "threatName": "Program:Win32/Ymacco.AAB7"},
        {"threatFamilyName": "YTDVideoDownload", "threatName": "PUA:Win32/YTDVideoDownload"},
        {"threatFamilyName": "Zpevdo", "threatName": "Trojan:Win32/Zpevdo.B"}
    ]

    def __init__(self, use_real_threats, use_evidence, use_comments):
        self.use_evidence = use_evidence
        self.use_comments = use_comments
        self.use_real_threats= use_real_threats
        self.threat = choice(self.THREATS)

    @staticmethod
    def generate_alertid():
        return f"da{randrange(0,999999999999999999):018d}_{randrange(1000000,99999999999)}"

    @staticmethod
    def generate_shortid(start, end):
        return randrange(start, end)

    @staticmethod
    def generate_assignedto():
        users = [None, "user@example.com", "Automation"]
        return choice(users)

    @staticmethod
    def generate_severity():
        return choice(["UnSpecified", "Informational", "Low", "Medium", "High"])

    @staticmethod
    def generate_status():
        return choice(["Unknown", "New", "InProgress", "Resolved"])

    @staticmethod
    def generate_classification():
        return choice([None, "Unknown", "FalsePositive", "TruePositive"])

    @staticmethod
    def generate_determination():
        return choice([None, "NotAvailable", "Apt", "Malware", "SecurityPersonnel", \
                       "SecurityTesting", "UnwantedSoftware", "Other"])

    @staticmethod
    def generate_investigationstate():
        return choice([None, "Unknown", "Terminated", "SuccessfullyRemediated", \
                       "Benign", "Failed", "PartiallyRemediated", "Running",  \
                       "PendingApproval", "PendingResource", "PartiallyInvestigated", \
                       "TerminatedByUser", "TerminatedBySystem", "Queued", \
                       "InnerFailure", "PreexistingAlert", "UnsupportedOs", \
                       "UnsupportedAlertType", "SuppressedAlert"])

    @staticmethod
    def generate_detectionsource():
        return choice(["", "AutomatedInvestigation", "CustomerTI", "MTP", \
                       "WindowsDefenderAtp", "WindowsDefenderAv"])

    def generate_detectorid(self):
        return str(self.generate_uuid())

    @staticmethod
    def generate_uuid():
        return uuid4()

    @staticmethod
    def generate_category():
        return choice(["CredentialAccess", "DefenseEvasion", "Discovery" \
                       "Execution", "Exploit", "General", "InitialAccess", \
                       "LateralMovement", "Malware", "Persistence", \
                       "Ransomware", "SuspiciousActivity", \
                       "UnwantedSoftware", ""])
    
    def generate_threatname(self):
        if self.use_real_threats:
            return self.threat["threatName"]
        else:
            return "IntelMQ:Test_Alert"

    def generate_threatfamilyname(self):
        if self.use_real_threats:
            return self.threat["threatFamilyName"]
        else:
            return "IntelMQ_Test_Alert"

    @staticmethod
    def generate_title():
        # TODO: Add variants on titles
        return "IntelMQ test alert"

    @staticmethod
    def generate_description():
        # TODO: Add variants on descriptions
        return "This is a IntelMQ test alert"

    @staticmethod
    def generate_timestamp():
        dt = datetime.now(tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f0Z")

    def generate_machineid(self):
        return self.generate_sha1()

    @staticmethod
    def generate_sha1(value = "IntelMQ test"):
        return hashlib.sha1(value.encode()).hexdigest()

    @staticmethod
    def generate_sha256(value = "IntelMQ test"):
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def generate_md5(value = "IntelMQ test"):
        return hashlib.md5(value.encode()).hexdigest()

    @staticmethod
    def generate_computerdnsname():
        # TODO: Add variants of computerdns names
        return "computer.example.com"

    @staticmethod
    def generate_rbacgroupname():
        # The documentation does not explain what this is, all
        # alerts have this value as null. Documentation has an
        # example using the string "A".
        return None

    def generate_aadtenantid(self):
        return str(self.generate_uuid())

    @staticmethod
    def generate_mitretechniques():
        # This is always a list
        
        # TODO: Add variants of mitre techniques
        return choice([[], ["T1000"]])

    @staticmethod
    def generate_relateduser():
        # This is either None or an object
        # Format of valid object is:
        # {"userName": "user", "domainName": "example"}
        
        # TODO: Add real usernames for accurate testing
        return choice([None])

    @staticmethod
    def generate_comments():
        # This is always a list
        # Format of valid comment is:
        # {"comment": "This is a comment", "createdBy": "user@example.com", "createdTime": "2021-01-28T15:39:51.32Z"}
        # {"comment": "This is a comment", "createdBy": "Automation", "createdTime": "2021-01-28T15:39:51.32Z"}

        # TODO: Add dummy comments
        return choice([[{"comment": "This is a comment", "createdBy": "user@example.com", "createdTime": "2021-01-28T15:39:51.32Z"}]])

    def create_alert(self):
        output = {
            "id": self.generate_id(),
            "incidentId": self.generate_incidentid(),
            "investigationId": self.generate_investigationid(),
            "assignedTo": self.generate_assignedto(),
            "severity": self.generate_severity(),
            "status": self.generate_status(),
            "classification": self.generate_classification(),
            "determination": self.generate_determination(),
            "investigationState": self.generate_investigationstate(),
            "detectionSource": self.generate_detectionsource(),
            "detectorId": self.generate_detectorid(),
            "category": self.generate_category(),
            "threatFamilyName": self.generate_threatfamilyname(),
            "title": self.generate_title(),
            "description": self.generate_description(),
            "alertCreationTime": self.generate_timestamp(),
            "firstEventTime": self.generate_timestamp(),
            "lastEventTime": self.generate_timestamp(),
            "lastUpdateTime": self.generate_timestamp(),
            "resolvedTime": self.generate_timestamp(),
            "machineId": self.generate_machineid(),
            "computerDnsName": self.generate_computerdnsname(),
            "rbacGroupName": self.generate_rbacgroupname(),
            "aadTenantId": self.generate_aadtenantid(),
            "threatName": self.generate_threatname(),
            "relatedUser": self.generate_relateduser(),
            "comments": []
        }

        if self.use_comments:
            output["comments"] = self.generate_comments()

        if self.use_evidence:
            output["evidence"] = []

        return json.dumps(output)