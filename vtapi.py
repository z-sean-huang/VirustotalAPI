#!/usr/bin/env python
"""
USAGE:
    (1) rating URL:
        python vtapi.py google.com

    (2) rating FILE:
        python vtapi.py /bin/ping

    (3) rating HASH:
        python vtapi.py 7b36e9a3418f2c99de9652c0d87ea36dba3da7a2

    (4) help:
        python vtapi.py --help [-h]
"""
import logging
logger = logging
import os
import sys
import requests
import hashlib

TYPE_L = {
          "doc":"MS Word Document",
          "docx":"Office Open XML Document",
          "ppt":"MS PowerPoint Presentation",
          "pptx":"Office Open XML Presentation",
          "xls":"MS Excel Spreadsheet",
          "xlsx":"Office Open XML Spreadsheet",
          "pdf":"PDF",
          "rtf":"Rich Text Format",
          "email":"Email",
          "flash":"Flash",
          "jar":"JAR",
          "hwp":"Hangul (Korean) Word Processor document",
          "emf":"Windows Enhanced Metafile",
          "java-bytecode":"Java Bytecode",
          "flv":"FLV",
          "png":"PNG",
          "html":"HTML",
          "java":"Java",
          "script":"Shell script",
          "blackhole":"Black Hole",
          "unknown":"Unknown",
          "text":"Text",
}


FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"
#FILE_SEND = "https://www.virustotal.com/vtapi/v2/file/scan"
URL_REPORT = "http://www.virustotal.com/vtapi/v2/url/report"
URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan"
INT_TIME_OUT = 20


class VtApi(object):
    """
    VtApi - vt public-api 2.0
        INPUT:
            sApiKey [str]: the virus total private api key
        RETURN:
            object: vt api object
        MORE DETAIL:
            https://www.virustotal.com/en/documentation/public-api/
    """

    def __init__(self, sApiKey):
        self.sApiKey = sApiKey


    def file_report(self, sHash):
        logger.info("start file_report() sHash=[%s]", sHash)
        dParam = {'apikey': self.sApiKey, 'resource': sHash}
        try:
            reqRet = requests.get(FILE_REPORT, params=dParam, timeout=INT_TIME_OUT)
            dReport = reqRet.json()
        except Exception as e:
            logger.exception("fail file_report() sHash=[%s]", sHash)
            raise e
        if dReport.get("response_code", 0) == 1:
            return dReport
        return {}


    def url_report(self, sUrl):
        logger.info("start url_report() sUrl=[%s]", sUrl)
        dParam = {'apikey': self.sApiKey, 'resource': sUrl}
        try:
            reqRet = requests.get(URL_REPORT, params=dParam, timeout=INT_TIME_OUT)
            dReport = reqRet.json()
        except Exception as e:
            logger.exception("fail url_report() sUrl=[%s]", sUrl)
            raise e
        if dReport.get("response_code", 0) == 1:
            return dReport
        return {}


    @staticmethod
    def is_hash(sHash):
        # check for md1, sha1, sha256
        if len(sHash) not in [32, 40, 64]:
            return False
        if not (set(sHash.lower()) - set("abcdef0123456789")):
            return True
        return False


    @staticmethod
    def is_file(sPath):
        if os.path.isfile(sPath):
            return True
        return False


    @staticmethod
    def is_url(sUrl):
        if not sUrl:
            return False
        import re
        # this method is used by Django
        regex = re.compile(
            r'(^https?://)?'  # http:// or https:// or ""
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|' # domain
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(regex.search(sUrl))


    def rating(self, sScan):
        dReport = self.report(sScan)
        if not dReport:
            return None

        try:
            iPos = dReport["positives"]
            sLink = dReport.get("permalink", "")
        except:
            logger.exception("fail rating() sScan=[%s]", sScan)
            return None

        return (iPos, sLink)


    def report(self, sScan):
        try:
            if self.is_file(sScan):
                sScan = hashlib.md5(open(sScan).read()).hexdigest()
            if self.is_hash(sScan):
                dReport = self.file_report(sScan)
            elif self.is_url(sScan):
                dReport = self.url_report(sScan)
            else:
                return None
         
            # case if sample or url doesn't have records in Virustotal
            if not dReport:
                return None

            return dReport
        except:
            logger.exception("fail report() sScan=[%s]", sScan)
            return None


def main():
    import json
    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)


    #APIKEY = "PUT_YOUR_PUBLIC_KEY_HERE"
    # you can apply a free public api key at https://www.virustotal.com/
    APIKEY = "a90537cb88de70dcd81830bf602524055b7d3174f62322c36da9266f48d13638"

    try:
        sScan = sys.argv[1]
        if sScan in ["-h", "--help"]:
            print(__doc__)
            return
    except:
        print(__doc__)
        return

    vt = VtApi(APIKEY)
    dReport = json.dumps(vt.report(sScan), indent=2)
    print(dReport)


if __name__ == '__main__':
    main()
