ALERTS_FILE = "/tmp/alerts.json"
LOG_FILE = "/tmp/alerts_cli.log"

IncTemplate = [
    {
        "event": "",
        "tags": "",
        "severity": "",
        "insightId": "",
        "groups": "",
        "triggerTime": "",
        "trigName": "",
        "message": "",
        "timestamp": "",
        "actions": {
            "ktalkUser": {
                "stepSate": "",
                "errorMessage": "",
                "retryNumber": ""
            },
            "ktalkBot": {
                "stepSate": "",
                "errorMessage": "",
                "retryNumber": ""
            },
            "jiraStatus": {
                "stepSate": "",
                "errorMessage": "",
                "retryNumber": ""
            },
            "recipients": {
                "stepSate": "",
                "errorMessage": "",
                "retryNumber": ""
            }
        }
    }
]
