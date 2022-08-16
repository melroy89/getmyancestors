# global imports
import sys
import time
import asyncio
import aiohttp
import requests
from fake_useragent import UserAgent

# local imports
from getmyancestors.classes.translation import translations


class Session:
    """Create a FamilySearch session
    :param username and password: valid FamilySearch credentials
    :param verbose: True to active verbose mode
    :param logfile: a file object or similar
    :param timeout: time before retry a request
    """

    def __init__(self, username, password, verbose=False, logfile=False, timeout=60):
        self.username = username
        self.password = password
        self.verbose = verbose
        self.logfile = logfile
        self.timeout = timeout
        self.fid = self.lang = self.display_name = None
        self.counter = 0
        self.headers = {"User-Agent": UserAgent().firefox}
        self.loop = asyncio.get_event_loop()
        self.logged = False

    def write_log(self, text):
        """write text in the log file"""
        log = "[%s]: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
        if self.verbose:
            sys.stderr.write(log)
        if self.logfile:
            self.logfile.write(log)

    async def login(self, aiosession):
        """retrieve FamilySearch session ID
        (https://familysearch.org/developers/docs/guides/oauth2)
        """
        while True:
            try:
                url = "https://www.familysearch.org/auth/familysearch/login"
                self.write_log("Downloading: " + url)
                r = requests.get(
                    url,
                    params={"ldsauth": False},
                    allow_redirects=False,
                    headers=self.headers,
                )
                url = r.headers["Location"]
                self.write_log("Downloading: " + url)
                r = requests.get(url, allow_redirects=False, headers=self.headers)
                idx = r.text.index('name="params" value="')
                span = r.text[idx + 21 :].index('"')
                params = r.text[idx + 21 : idx + 21 + span]

                url = "https://ident.familysearch.org/cis-web/oauth2/v3/authorization"
                self.write_log("Downloading: " + url)
                async with aiosession.post(
                    url,
                    data={
                        "params": params,
                        "userName": self.username,
                        "password": self.password,
                    },
                    allow_redirects=False,
                    headers=self.headers,
                ) as r:
                    text = await r.text()
                    if "The username or password was incorrect" in text:
                        self.write_log("The username or password was incorrect")
                        return False

                    if "Invalid Oauth2 Request" in text:
                        self.write_log("Invalid Oauth2 Request")
                        await asyncio.sleep(self.timeout)
                        continue

                    url = r.headers["Location"]
                    self.write_log("Downloading: " + url)
                    r = requests.get(url, allow_redirects=False, self.headers)
                    self.fssessionid = r.cookies["fssessionid"]
            except requests.exceptions.ReadTimeout:
                self.write_log("Read timed out")
                continue
            except requests.exceptions.ConnectionError:
                self.write_log("Connection aborted")
                await asyncio.sleep(self.timeout)
                continue
            except requests.exceptions.HTTPError:
                self.write_log("HTTPError")
                await asyncio.sleep(self.timeout)
                continue
            except KeyError:
                self.write_log("KeyError")
                await asyncio.sleep(self.timeout)
                continue
            except ValueError:
                self.write_log("ValueError")
                await asyncio.sleep(self.timeout)
                continue
            self.write_log("FamilySearch session id: " + self.fssessionid)
            await self.set_current()
            self.logged = True
            return True

    async def get_url(self, url, aiosession, headers=None):
        """retrieve JSON structure from a FamilySearch URL"""
        self.counter += 1
        if headers is None:
            headers = {"Accept": "application/x-gedcomx-v1+json"}
        headers.update(self.headers)
        while True:
            try:
                self.write_log("Downloading: " + url)
                async with aiosession.get(
                    "https://familysearch.org" + url,
                    cookies={"fssessionid": self.fssessionid},
                    timeout=self.timeout,
                    headers=headers,
                ) as r:
                    self.write_log("Status code: %s" % r.status)
                    if r.status == 204:
                        return None
                    if r.status in {404, 405, 410, 500}:
                        self.write_log("WARNING: " + url)
                        return None
                    if r.status == 401:
                        self.login()
                        continue
                    if r.status == 403:
                        json = await r.json()
                        if (
                            "message" in json["errors"][0]
                            and json["errors"][0]["message"] == "Unable to get ordinances."
                        ):
                            self.write_log(
                                "Unable to get ordinances. "
                                "Try with an LDS account or without option -c."
                            )
                            return "error"
                        self.write_log(
                            "WARNING: code 403 from %s %s"
                            % (url, json["errors"][0]["message"] or "")
                        )
                        return None
                    try:
                        r.raise_for_status()
                    except requests.exceptions.HTTPError:
                        self.write_log("HTTPError")
                        await asyncio.sleep(self.timeout)
                        continue
                    try:
                        json = await r.json()
                    except Exception as e:
                        self.write_log("WARNING: corrupted file from %s, error: %s" % (url, e))
                        return None
                    return json
            except requests.exceptions.ReadTimeout:
                self.write_log("Read timed out")
                continue
            except requests.exceptions.ConnectionError:
                self.write_log("Connection aborted")
                await asyncio.sleep(self.timeout)
                continue

    async def set_current(self):
        """retrieve FamilySearch current user ID, name and language"""
        url = "/platform/users/current"
        data = await self.get_url(url)
        if data:
            self.fid = data["users"][0]["personId"]
            self.lang = data["users"][0]["preferredLanguage"]
            self.display_name = data["users"][0]["displayName"]

    def _(self, string):
        """translate a string into user's language
        TODO replace translation file for gettext format
        """
        if string in translations and self.lang in translations[string]:
            return translations[string][self.lang]
        return string
