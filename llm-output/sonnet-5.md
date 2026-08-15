I'll start by thoroughly investigating this codebase. Given this is a network-connected infant incubator control system, I'm going to actually stand up the server and client in a sandbox and empirically verify each vulnerability I find — not just read the code — so the fixes and tests I give you are proven to work rather than theoretical.That confirms it — background processes don't persist between tool calls, so I need to launch the server and run each test within a single shell invocation. Let me build proper test harnesses.The AUTH bug is empirically confirmed — the server is alive, but a **correct** password behaves identically to a **wrong** one (silent timeout). Now let's test the thread-crash denial-of-service.Confirmed — one malformed packet permanently kills a single sensor's reporting thread while the rest of the process (including the *other* sensor) keeps running normally, so nothing alarms. Now let's quantify the brute-force exposure before building fixes.Now let's check what crypto tooling is available before designing the fix for the encryption/integrity issues.Good — `cryptography` is available. Now let me design a shared authenticated-encryption helper that will close both the cleartext-transmission and the response-spoofing vulnerabilities together, since they're really two sides of the same missing-transport-security gap.Now the fixed server, integrating the crypto layer plus fixes for the exception-handling DoS, the broken auth comparison, missing lockout, weak PRNG, and missing audit logging all at once:

---

Then I ran out of my free tier usage limit... however, I did get an updated SampleNetworkServer.py file before that!

---

import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import infinc
import time
import math
import socket
import fcntl
import os
import errno
import secrets
import string
import logging
import sys

from secure_channel import SecureChannel

AUTH_PASSWORD = os.environ.get("AUTH_PASSWORD", "")
if not AUTH_PASSWORD:
    print("ERROR: AUTH_PASSWORD environment variable must be set before execution.")
    print("Usage: AUTH_PASSWORD=<your_password> python SampleNetworkServer.py")
    exit(1)

MAX_SESSIONS = 32
TOKEN_TIMEOUT = 86400          # 24 hours in seconds

# --- Requirement #2: account lockout after repeated failed auth attempts ---
FAILED_ATTEMPT_WINDOW = 600    # 10 minutes
FAILED_ATTEMPT_THRESHOLD = 5   # 5 failures
LOCKOUT_DURATION = 300         # 5 minutes

# --- Requirement #7: record all user actions with time and (best-available) user ID ---
# NOTE: this protocol has only ONE shared secret for the whole facility, not
# per-user accounts, so "user ID" below is approximated with source IP +
# truncated session id. See VULNERABILITY_REPORT.md for the recommendation
# to move to per-user credentials for full requirement #7 compliance.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("incubator_audit.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
audit = logging.getLogger("incubator.audit")


class SmartNetworkThermometer(threading.Thread):

    def __init__(self, source, updatePeriod, port):
        threading.Thread.__init__(self, daemon=True)
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()
        self.tokens = {}            # {token: created_timestamp}
        self.channel = SecureChannel(AUTH_PASSWORD)

        self.failed_attempts = {}   # ip -> [timestamps within window]
        self.locked_until = {}      # ip -> epoch time lockout ends

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"
        self.port = port

    def setSource(self, source):
        self.source = source

    def setUpdatePeriod(self, updatePeriod):
        self.updatePeriod = updatePeriod

    def setDegreeUnit(self, s):
        self.deg = s
        if self.deg not in ["F", "K", "C"]:
            self.deg = "K"

    def updateTemperature(self):
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self):
        if self.deg == "C":
            return self.curTemperature - 273
        if self.deg == "F":
            return (self.curTemperature - 273) * 9 / 5 + 32
        return self.curTemperature

    # ---------------------------------------------------------------- #
    # Requirement #2: lockout bookkeeping (tracked per source IP, since
    # this protocol has no per-user identity to key on).
    # ---------------------------------------------------------------- #
    def _is_locked_out(self, ip, now):
        until = self.locked_until.get(ip)
        return until is not None and now < until

    def _record_failure(self, ip, now):
        attempts = [t for t in self.failed_attempts.get(ip, []) if now - t < FAILED_ATTEMPT_WINDOW]
        attempts.append(now)
        self.failed_attempts[ip] = attempts
        if len(attempts) >= FAILED_ATTEMPT_THRESHOLD:
            self.locked_until[ip] = now + LOCKOUT_DURATION
            audit.warning("LOCKOUT ip=%s port=%d until=%.0f (%d failures in %ds)",
                           ip, self.port, self.locked_until[ip], len(attempts), FAILED_ATTEMPT_WINDOW)

    def _record_success(self, ip):
        self.failed_attempts.pop(ip, None)

    def _cleanup_expired_tokens(self):
        now = time.time()
        for t in [t for t, ts in self.tokens.items() if now - ts > TOKEN_TIMEOUT]:
            del self.tokens[t]

    # ---------------------------------------------------------------- #
    # Command handling. Everything here only ever runs on plaintext that
    # has ALREADY passed Fernet authentication in run(), so by the time
    # we get here the caller has proven knowledge of AUTH_PASSWORD.
    # ---------------------------------------------------------------- #
    def _handle_plaintext(self, plaintext, addr):
        try:
            msg = plaintext.decode("utf-8").strip()
        except UnicodeDecodeError:
            audit.warning("Decrypted payload was not valid UTF-8 from %s (dropped)", addr[0])
            return None

        self._cleanup_expired_tokens()

        if msg == "AUTH":
            return self._handle_auth(addr)

        if msg.startswith("LOGOUT "):
            return self._handle_logout(msg[len("LOGOUT "):], addr)

        semi = msg.find(';')
        if semi != -1:
            token = msg[:semi]
            if token in self.tokens:
                return self._process_protected(msg[semi + 1:])
            audit.info("Request with unknown/expired token from %s port=%d", addr[0], self.port)
            return b"Bad Token\n"

        return b"Bad Command\n"

    def _handle_auth(self, addr):
        # Reaching this point already proves the caller holds AUTH_PASSWORD:
        # the datagram had to decrypt correctly under the password-derived
        # key in run() before _handle_plaintext was ever called. There is
        # no separate password comparison here anymore - see
        # VULNERABILITY_REPORT.md finding #2 (broken str/bytes comparison)
        # and #8 (timing side-channel), both closed by this design.
        if len(self.tokens) >= MAX_SESSIONS:
            audit.warning("AUTH rejected (MAX_SESSIONS) from %s port=%d", addr[0], self.port)
            return b"maximum active sessions reached\n"
        token = ''.join(
            secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
            for _ in range(16)
        )
        self.tokens[token] = time.time()
        audit.info("AUTH SUCCESS ip=%s port=%d session=%s...", addr[0], self.port, token[:8])
        return token.encode("utf-8")

    def _handle_logout(self, token, addr):
        if token in self.tokens:
            del self.tokens[token]
            audit.info("LOGOUT ip=%s port=%d session=%s...", addr[0], self.port, token[:8])
        return None

    def _process_protected(self, msg):
        replies = []
        for c in msg.split(';'):
            if c == "SET_DEGF":
                self.deg = "F"
            elif c == "SET_DEGC":
                self.deg = "C"
            elif c == "SET_DEGK":
                self.deg = "K"
            elif c == "GET_TEMP":
                replies.append(("%f\n" % self.getTemperature()).encode("utf-8"))
            elif c == "UPDATE_TEMP":
                self.updateTemperature()
            elif c:
                replies.append(b"Invalid Command\n")
        return b"".join(replies) if replies else None

    def run(self):
        while True:
            try:
                raw, addr = self.serverSocket.recvfrom(2048)
                ip = addr[0]
                now = time.time()

                if self._is_locked_out(ip, now):
                    audit.info("DROPPED packet from locked-out ip=%s port=%d", ip, self.port)
                else:
                    plaintext = self.channel.decrypt(raw)
                    if plaintext is None:
                        self._record_failure(ip, now)
                        audit.warning("AUTH/DECRYPT FAILURE ip=%s port=%d", ip, self.port)
                    else:
                        self._record_success(ip)
                        reply = self._handle_plaintext(plaintext, addr)
                        if reply is not None:
                            self.serverSocket.sendto(self.channel.encrypt(reply), addr)

            except IOError as e:
                if e.errno != errno.EWOULDBLOCK:
                    audit.exception("Unexpected IOError in server loop (port=%d)", self.port)
            except Exception:
                # Defense in depth: NOTHING a remote peer sends is allowed to
                # kill this thread. See VULNERABILITY_REPORT.md finding #1
                # (uncaught-exception DoS -> frozen sensor feeding the
                # heater stale data with no alarm).
                audit.exception("Unexpected error handling datagram (port=%d) - thread survives", self.port)

            self.updateTemperature()
            time.sleep(self.updatePeriod)


class SimpleClient:
    def __init__(self, therm1, therm2):
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def updateInfTemp(self, frame) :
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature()-273)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame) :
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature()-273)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

UPDATE_PERIOD = .05 #in seconds
SIMULATION_STEP = .1 #in seconds

#create a new instance of IncubatorSimulator
bob = infinc.Human(mass = 8, length = 1.68, temperature = 36 + 273)
bobThermo = SmartNetworkThermometer(bob, UPDATE_PERIOD, 23456)
bobThermo.start() #start the thread

inc = infinc.Incubator(width = 1, depth=1, height = 1, temperature = 37 + 273, roomTemperature = 20 + 273)
incThermo = SmartNetworkThermometer(inc, UPDATE_PERIOD, 23457)
incThermo.start() #start the thread

incHeater = infinc.SmartHeater(powerOutput = 1500, setTemperature = 45 + 273, thermometer = incThermo, updatePeriod = UPDATE_PERIOD)
inc.setHeater(incHeater)
incHeater.start() #start the thread

sim = infinc.Simulator(infant = bob, incubator = inc, roomTemp = 20 + 273, timeStep = SIMULATION_STEP, sleepTime = SIMULATION_STEP / 10)

sim.start()

if __name__ == "__main__":
    sc = SimpleClient(bobThermo, incThermo)
    plt.grid()
    plt.show()