import re

def emailSpoofDetection(header, emailDomain):
    header = str(header);
    emailDomain = str(emailDomain);

    header = re.sub(r'\{\"name\"\:\"', '', header)
    header = re.sub(r'\"\,\"value\"\:\"', ': ', header)
    header = re.sub(r'\"\}\,', ', ', header)
    header = re.sub(r'^\[', '', header)
    header = re.sub(r'\"\}\]$', '', header)
    header = re.sub(r'\s+', ' ', header)

    header = re.sub(r'\n', ' ', header)
    header = re.sub(r'\t', ' ', header)

    match = []


    dkimRegex = r'dkim\=(\S+)\sheader\.i\=\@(\S+)\s'
    dkim = {"result": [], "domain": []}
    match = re.findall(dkimRegex, header)
    for (r, d) in match:
        if r not in dkim["result"]:
            dkim["result"].append(r)
        if d not in dkim["domain"]:
            dkim["domain"].append(d)

    spfRegex = r'spf\=(\S+).*?smtp\.mailfrom\=.*?\@(.*?)\;\s'
    spf = {"result": [], "domain": []}
    match = re.findall(spfRegex, header)
    for (r, d) in match:
        if r not in spf["result"]:
            spf["result"].append(r)
        if d not in spf["domain"]:
            spf["domain"].append(d)

    dmarcRegex = r'dmarc\=(\S+)\s\(p\=\S+\s+sp\=\S+\s+dis\=\S+\)\s+header\.from\=(\S+)'
    dmarc = {"result": [], "domain": []}
    match = re.findall(dmarcRegex, header)
    for (r, d) in match:
        if r not in dmarc["result"]:
            dmarc["result"].append(r)
        if d not in dmarc["domain"]:
            dmarc["domain"].append(d)

    if ("pass" in dkim["result"] and "pass" in spf["result"] and "pass" in dmarc["result"] and emailDomain in dkim["domain"]):
        return True
    else:
        return False


def main():
    email_file = input("Enter the path to the email file: ")
    expected_domain = input("Enter the expected domain: ")
    result = emailSpoofDetection(email_file, expected_domain)

    if result:
        print("Email sender domain matches the expected domain.")
    else:
        print("Email sender domain does not match the expected domain. Possible spoofing detected.")

if __name__ == "__main__":
    main()
