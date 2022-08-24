import re
def rule(event):
    # Return True to match the log event and trigger an alert.
    if event.get("event").get("category") == "process" and event.get("event").get("type") in ["start", "process_started"]:
        process_name = event.get("process").get("name")
        process_args = event.get("process").get("args")

        if process_name == "perl" and re.search('.*getprotobyname.*sockaddr_in.*', process_args):
            return True
        if re.search("python.*", process_name) and re.search(".*socket.*connect.*", process_args):
            return True
        if re.search("php.*", process_name) and re.search(".*fsockopen.*", process_args):
            return True
        if re.search("ruby.*", process_name) and re.search(".*TCPSocket.*", process_args):
            return True
        if process_name == "openssl" and re.search(".*-connect.*", process_args):
            return True
        if re.search("lua.*", process_name) and re.search(".*connect.*", process_args):
            return True

    return False

def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as deduplication string.
    return 'Suspect Reverse Shell'

# def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # return ''

def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
    return dict(event)
