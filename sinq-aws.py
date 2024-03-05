import argparse
import json
import datetime
import logging
import re
from collections import defaultdict

import boto3


# from botocore.exceptions import ClientError


class GlobalDataClass:
    def __init__(self, _logger):
        # Globals
        self.secrets = defaultdict(dict)
        self.metacounter = {"pages": 0, "events": 0, "exceptions": 0}
        self.logger = _logger
        self.exceptions = defaultdict(lambda: defaultdict(list))

    def add_secrets_page(self, page):
        for sec in page["SecretList"]:
            self.secrets[sec["Name"]] = sec
            self.secrets[sec["Name"]]["usageStats"] = defaultdict(int)

    def proc_events_page(self, page):
        for meta_event in page["Events"]:
            event = json.loads(meta_event["CloudTrailEvent"])
            # if (len(meta_event["Resources"]) == 0) or ("errorCode" in event.keys()):
            user_name = self.__get_user_name_from_event(event)
            if "errorCode" in event.keys():
                self.exceptions[event["errorCode"]][user_name].append(event)
                self.metacounter["exceptions"] += 1
            else:
                secret_id = self.__get_secret_id_from_event(event)
                if secret_id in self.secrets.keys():
                    self.secrets[secret_id]["usageStats"][user_name] += 1
                    self.metacounter["events"] += 1
                else:
                    self.exceptions["unlisted_secretid_events"][user_name].append(event)
        self.metacounter["pages"] += 1

    def validate_count(self):
        temp_c = 0
        for k in self.secrets.keys():
            for s in self.secrets[k].get("usageStats", {}).keys():
                temp_c += self.secrets[k]["usageStats"][s]
        if temp_c != self.metacounter["events"]:  # <need to rethink> or -(-temp_c // self.metacounter["pages"]) != 50:
            self.logger.critical("{}: Events count validation failed! total usage count: {}, metadata events: {}, "
                                 "metadata pages: {}.".format(datetime.datetime.now(), temp_c,
                                                              self.metacounter["events"], self.metacounter["pages"]))
            print("Events count validation failed! total usage count: {}, metadata events: {}, metadata pages"
                  ": {}.".format(temp_c, self.metacounter["events"], self.metacounter["pages"]))
            # exit()
        else:
            self.logger.info(
                "{}: Events count validation successful! total usage count: {}, metadata events: {}, "
                "metadata pages: {}.".format(
                    datetime.datetime.now(), temp_c, self.metacounter["events"], self.metacounter["pages"]))
            print((
                "Events count validation successful! total usage count: {}, metadata events: {}, metadata "
                "pages: {}.".format(
                    temp_c, self.metacounter["events"], self.metacounter["pages"])))

    def __get_secret_id_from_event(self, event):
        secret_id = event["requestParameters"]["secretId"]
        # GetSecretValue can be called with secret's ARN instead of Secrets name,
        # but the key we use for secrets is the name.
        # Optimally this would be done by DescribeSecret API call with the ARN from the event to get the accurate
        # Secret Name value, but for now I'll just parse the ARN string:
        temp = re.match(r'arn:aws:secretsmanager:\S+:\d+:secret:(\S+)-\w+$', secret_id)
        if temp:
            secret_id = temp.group(1)
        # End parse of ARN string
        return secret_id

    def __get_user_name_from_event(self, event):
        user_name = str()
        if event["userIdentity"]["type"] == "IAMUser":
            user_name = event["userIdentity"]["userName"]
        elif event["userIdentity"]["type"] == "AssumedRole":
            user_name = event["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
        # The goal is to expend to support more identity types, then turning it into a switch with the type value
        # mapping to the keys path for value extraction from the dictionary.
        elif event["userIdentity"]["type"] == "Root":
            user_name = event["userIdentity"]["arn"]
        else:
            user_name = "Unknown User Identity Type - {}".format(str(event["userIdentity"]))
            self.logger.warning("\n\nDEBUG- Unknown userIdentity event: {}\n\n".format(event))
        return user_name


def get_secrets(data_obj, _logger):
    for page in boto3.client('secretsmanager').get_paginator('list_secrets').paginate():
        _logger.debug(
            "DEBUG- Got Secrets List Page. First Secret Name: {}, Next Token: {}.".format(page["SecretList"][0]["Name"],
                                                                                          page.get("NextToken",
                                                                                                   "Last Page!")))
        data_obj.add_secrets_page(page)
        print("Listing secrets. Got {} secrets so far.".format(len(data_obj.secrets.keys())), end="\r")
    print("\n=-*-=")
    print("Finished loading Secrets List. Loaded {} Secrets".format(len(data_obj.secrets.keys())))


def get_events(data_obj, events_days_ago, _logger):
    start_time = datetime.datetime.utcnow() - datetime.timedelta(days=events_days_ago)
    _logger.info("Start Date for Events to process is set to: {}".format(start_time))
    for page in boto3.client('cloudtrail').get_paginator('lookup_events').paginate(LookupAttributes=[
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'GetSecretValue'
            }], StartTime=start_time):
        if page["Events"]:
            _logger.debug("DEBUG- Got GetSecretValue Events Page. First Event Time: {}, Next Token: {}.".format(
                page["Events"][0]["EventTime"],
                page.get("NextToken", "Last Page!")))
            print("Collecting GetSecretValue events. Remaining events time: {} hours".format(
                str(round((page["Events"][0]["EventTime"].astimezone(datetime.timezone.utc).replace(
                    tzinfo=None) - start_time).total_seconds() / 3600))), end="\r")
            data_obj.proc_events_page(page)
        else:
            print("No GetSecretValue events were found in the past {} days in the selected region."
                  "Try using the --days-ago flag to extend the inspected time period, "
                  "or --region flag to inquire on another region".format(events_days_ago))


def serialize_datetime(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat(" ", "minutes")
    raise TypeError("Type not serializable")


def process_results(_data):
    res_dict = {"secrets": defaultdict(dict), "exceptions": defaultdict(list)}
    for k, v in _data.secrets.items():
        res_dict["secrets"][k]["lastChangedDate"] = v["LastChangedDate"]
        res_dict["secrets"][k]["daysSinceLastChanged"] = (
                datetime.datetime.utcnow() - v["LastChangedDate"].replace(tzinfo=None)).days
        res_dict["secrets"][k]["retrieversCount"] = len(v["usageStats"].keys())
        res_dict["secrets"][k]["retrievers"] = v["usageStats"]
        res_dict["secrets"][k]["sinqRisk"] = (1 + int(res_dict["secrets"][k]["daysSinceLastChanged"] / 30) +
                                              len(res_dict["secrets"][k]["retrievers"]))
        print("{} : Days since changed: {}, number of retrievers: {}, risk: {}".format(
            k, (datetime.datetime.utcnow() - v["LastChangedDate"].replace(tzinfo=None)).days,
            len(v["usageStats"].keys()), res_dict["secrets"][k]["sinqRisk"]))
        for a, c in v["usageStats"].items():
            print("     Identity {} retrieved the secret value {} times".format(a, c))
    res_dict["exceptions"] = _data.exceptions
    with open("output.json", "w") as fh:
        fh.write(json.dumps(res_dict, default=serialize_datetime, indent=3))


if __name__ == "__main__":
    # Argument Parser Setup
    parser = argparse.ArgumentParser(description="AWS Secrets Manager Analysis Script")
    parser.add_argument("--region", help="AWS region name")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--log-file-name", default="run.log", help="Log file name")
    parser.add_argument("--days-ago", type=int, default=7, help="Number of days to inspect events history")
    args = parser.parse_args()

    logging.basicConfig(filename=args.log_file_name, encoding='utf-8', level=args.log_level)
    logger = logging.getLogger('secretstats')

    boto3_default_session_config = {}
    if args.region:
        boto3_default_session_config["region_name"] = args.region
    if args.profile:
        boto3_default_session_config["profile_name"] = args.profile
    boto3.setup_default_session(**boto3_default_session_config)

    data = GlobalDataClass(logger)
    get_secrets(data, logger)
    get_events(data, args.days_ago, logger)
    data.validate_count()
    process_results(data)
