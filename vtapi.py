#!/usr/bin/env python
import logging
logger = logging.getLogger()
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
    def __is_hash(sHash):
        # check for md1, sha1, sha256
        if len(sHash) not in [32, 40, 64]:
            return False
        if not (set(sHash.lower()) - set("abcdef0123456789")):
            return True
        return False


    @staticmethod
    def __is_file(sPath):
        if os.path.isfile(sPath):
            return True
        return False


    @staticmethod
    def __is_url(sUrl):
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
        try:
            if self.__is_file(sScan):
                sScan = hashlib.md5(open(sScan).read()).hexdigest()

            if self.__is_hash(sScan):
                dReport = self.file_report(sScan)
            elif self.__is_url(sScan):
                dReport = self.url_report(sScan)
            else:
                return None

            # case if sample or url doesn't have records in Virustotal
            if not dReport:
                return None

            iHit = dReport["positives"]
            iTotal = dReport["total"]
            return (sScan, iHit, iTotal)

        except:
            logger.exception("fail rating() sScan=[%s]", sScan)
            return None


def main():
    # testing function
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

    # you can apply a free public api key thourgh https://www.virustotal.com/ and click "Join our community"
    APIKEY = "PUT YOUR PUBLIC APIKEY HERE"

    vt = VtApi(APIKEY)

    sHash = "481d2a43b048d139a1f08254ba68e4ec01a06a29"
    sDomain = "google.com.tw"
    sPath = "C:\MP4debug.log"

    print(vt.rating(sHash))
    print(vt.rating(sDomain))
    print(vt.rating(sPath))


if __name__ == '__main__':
    main()
