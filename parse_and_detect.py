import sqlite3                                   #database
from collections import defaultdict, deque       #defaultdict is a dictionary that creates a default value automatically if we try and access a key that does not exist
                                                 #deque is a double-ended queue we can do removal and insertion on both sides
from dataclasses import dataclass                #A dataclass is a lightweight class for storing only data. Allows us to omit some class syntax
from datetime import datetime, timedelta         #datetime represents an exact moment in time. timedelta represents a time duration
from dateutil import parser                      #parser converts timestamps from strings into datetime objects
from lxml import etree                           #lxml is a third-party Python library for working with XML and HTML
                                                 #etree allows use to read and navigate XML formatted data


DB_PATH = "ids.db"


BRUTE_FAILS = 10                                 #The number of failed login attempts from a single IP required to trigger an alert              
BRUTE_WINDOW_MIN = 5                             #The time window in which those failures must occur

SPRAY_DISTINCT_USERS = 8                         #The minimum number of different usernames an IP can attempt before a spray alert
SPRAY_TOTAL_FAILS = 12                           #Total number of fails an IP can have across the 8 usernames within the spray time window
SPRAY_WINDOW_MIN = 5                             #The time window in which the spray must happen


@dataclass                                       #A python decorator that allows us to make a class that only stores data, and it automatically generates __init__, __repr__, and __eq__
class Event:                                     #This class represents one security event parsed from a Windows log entry (every line is one event)
    ts: datetime
    event_id: int
    username: str | None                          #username can either be a str or none
    src_ip: str | None
    logon_type: int | None
    outcome: str

    #Event(ts=datetime(2025, 1, 12, 14, 32, 1), event_id=4625, username="admin", src_ip="185.234.217.21", logon_type=10, outcome="fail")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event_id INTEGER NOT NULL,
            username TEXT,
            src_ip TEXT,
            logon_type INTEGER,
            outcome TEXT NOT NULL
            )
        """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_first TEXT NOT NULL,
            ts_last TEXT NOT NULL
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL
            src_ip TEXT,
            username TEXT,
            count INTEGER NOT NULL,
            evidence TEXT
            )
        """)
    conn.commit()
    conn.close()



def parse_windows_security_xml(xml_path: str) -> list[Event]:              #parses the entire XML file, and returns one Event object per log entry inside a list

    tree = etree.parse(xml_path)               #reads the xml file and builds a tree representation of it
    root = tree.getroot()                      #gets the root element of the xml document, every xml file has exactly one root element

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}       #This makes e what we refer to the namespace http://schemas.microsoft.com/win/2004/08/events/event as and stores it in ns. The namespace identifies what schema the XML elements belong to and what the tree represents. A schema is like a class definition if the XML document is the object instance, it defines what element can exist, what they mean and how they are structered
    
    events: list[Event] = []                   #will hold all of the events (log entries)



    #root.findall(".//e:Event", namespace=ns) searches the entire XML file and returns a list of every <Event> element that belongs to the Windows Event Log namespace
    #starts at the root and walks through the entire XML tree, checking every element to see if it is an <Event> in that namespace
    #"".//e:Event" is a search instruction. . means from the current node (root). // means search recursively, at any depth, not just direct children (nested events)
    #e:Event means "elements named Event that belong to the namespace mapped to e"
    #namepacse=ns tells Python what e is
    #In summary, goes through all the events that belong to the specified namespace
    for ev in root.findall(".//e:Event", namespace=ns):


        #findtext() searches for the first matching element and returns the text inside it or None if not found
        #".//e:System/e:EventID" specifies the <EventID> tag
        #every tag is internally treated like {namespace}tagname, so every time we specify a tagname we need to include the namespace
        #so this finds the text of the <EventID> tag inside the <System> tag in the <Event> tag we are currently inside
        event_id_text = ev.findtext(".//e:System/e:EventID", namespace=ns)          
        if not event_id_text:
            continue
        event_id = int(event_id_text)                       #convert event_id_text into an int


        #ev.find() returns the XML element object itself, so then we can read its attributes
        time_node = ev.find(".//e:System/e:TimeCreated", namespace=ns)
        if time_node is None:
            continue
        ts_str = time_node.get("SystemTime")      #The TimeCreated XML element we have stored in time_node, has a SystemTime attribute. time_node.get() returns the value of this
        if not ts_str:
            continue
        ts = parser.isoparse(ts_str)        #ts_str is a string holding the datetime object, we want to convert it to an actual datetime object
                                            #dateutil.parser.isoparse() reads the ISO 9601 timestamp string and converts it into a datetime object


        data_map = {}
        for d in ev.findall(".//e:EventData/e:Data", namespace=ns):                  #goes through all the Data elements inside the EventData element
            name = d.get("Name")                #The data elements have a Name attribute


            #d.text gets the text inside the element
            val = (d.text or "").strip()        #either gets the text or an empty string if there's no text

            if name: 
                data_map[name] = val

        
        username = None
        src_ip = None
        logon_type = None
        outcome = "fail"


        if event_id in (4624, 4625):         #Event ID 4624 means successful logon. Event ID 4625 means failed logon. Event ID 4740 means account locked out

            #TargetUserName is who the action is happening to, SubjectUserName is who initiated the action. We want TargetUserName unless it's not there
            username = data_map.get("TargetUserName") or data_map.get("SubjectUserName")

            src_ip = data_map.get("IpAddress") or data_map.get("WorkstationName")
            lt = data_map.get("LogonType")
            if lt and lt.isDigit():
                logon_type = int(lt)

            outcome = "success" if event_id == 4624 else "fail"


        elif event_id == 4740:                   #For events with ID 4740, TargetUserName is the account that gets locked
            username = data_map.get("TargetUserName")
            src_ip = data_map.get("CallerComputerName")         #Event 4740 does not log the attacker's IP, CallerComputerName is the machine that reported/enforced the locked
            outcome = "lockout"


        events.append(Event(ts=ts, event_id=event_id, username=username, src_ip=src_ip, logon_type=logon_type,outcome=outcome))


    events.sort(key = lambda e: e.ts)           #key=lambda e: e.ts means for each element e in events, use e.ts as the value to compare
    return events


def store_events(events: list[Event]):                     #puts all the events into the db
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for e in events:
        cur.execute(
            "INSERT INTO events (ts, event_id, username, src_ip, logon_type, outcome) VALUES (?,?,?,?,?,?)",
            (e.ts.isoformat(), e.event_id, e.username, e.src_ip, e.logon_type, e.outcome),
            )
        conn.commit()
        conn.close()




#insert an alert into the db
def insert_alert(ts_first: datetime, ts_last: datetime, alert_type: str, severity: str, src_ip: str | None, username: str | None, count: int, evidence: str):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT INTO alerts (ts_first, ts_last, alert_type, severity, src_ip, username, count, evidence) VALUES (?,?,?,?,?,?,?,?)", 
                (ts_first.isoformat(), ts_last.isoformat(), alert_type, severity, src_ip, username, count, evidence))

    conn.commit()
    conn.close()


def detect(events: list[Event]):


    #each ip has its own timeline of failures, this is a default dictionary of each IP and its fail times
    #the key is the ip in a str format, the value is a double sided queue of datetime objects
    #defualtdict(object) is a dictionary that automatically gives you an empty specified object when you access a missing key. defaultdict(deque) makes it so if we try and access an IP not in our dictionary, it will automatically add it and assign the value to be an empty deque
    ip_fail_times: dict[str, deque[datetime]] = defaultdict(deque)

    #this is a dictionary of each IP and their respective time of failure and account it tried to access
    ip_fail_users: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)

    #timedelta is Python's built-in way to represent a duration. Not a clock or a timer. A way we compare timestamps
    brute_window = timedelta(minutes=BRUTE_WINDOW_MIN)
    spray_window = timedelta(minutes=SPRAY_WINDOW_MIN)

    for e in events:
        #continues to the next event if the user successfully logged in, or there is no source IP
        if e.outcome != "fail" or not e.src_ip:
            continue

        ip = e.src_ip
        now = e.ts


        dq = ip_fail_times[ip]          #grabs the IPs corresponding deque in ip_fail_times so we can add this time
        dq.append(now)                  #adds the failtime to the IPs deque
        
        #dq[0] is the first failure in the IPs deque, so it is the oldest
        #now - dq[0] is how long ago that failure happened compare to the most recent one
        #if dq is not empty and the timespan between the oldest and most recent failures is more than 5 minutes, remove the oldest until we only have failure times that are within 5 minutes
        while dq and (now - dq[0]) > brute_window:
            dq.popleft()



        uq = ip_fail_users[ip]                          #store the IPs corresponding deque from ip_fail_users
        if e.username:                                  #if we have a username from the event
            uq.append((now, e.username))                #add the timestamp and the username to the deque
        while uq and (now - uq[0][0]) > spray_window:   #while the deque is not empty and the oldest and newest timestamp are more than spray_window minutes apart, remove the oldest
            uq.popleft()


        if len(dq) == BRUTE_FAILS:                      #We put == BRUTE_FAILS because onece it hits 10 failures, we knnow there is a problem and do not need to keep getting alerted for every other failure
            insert_alert(dq[0], dq[-1], 
                         alert_type="BRUTE_FORCE", 
                         severity="high", 
                         src_ip=ip, 
                         username=None,
                         count=len(dq), 
                         evidence=f"{len(dq)} failed logons from {ip} within {BRUTE_WINDOW_MIN} minutes")


        if len(uq) >= SPRAY_TOTAL_FAILS:

            #u for _, u in uq takes each element in uq (timestamp, username), and unpacks it into two variables, and ignores the first one (_), and stores the second one in u which holds each username one at a time, then set collects those values
            #each time we loop through a username, it gets put in a set with set()
            #set() removes all duplicate values, so we end up with all the unique usernames
            distinct_users = len(set(u for _, u in uq))         #uq is the deque for an IP with the values being (timestamp, username). 
            if distinct_users >= SPRAY_DISTINCT_USERS:
                insert_alert(uq[0][0], uq[-1][0],
                             alert_type="PASSWORD_SPRAY",
                             severity="high",
                             src_ip=ip,
                             username=None,
                             count=len(uq),
                             evidence=f"{len(uq)} failures targeting {distinct_users} usernames from {ip} within {SPRAY_WINDOW_MIN} minutes")


def main():
    init_db()
    events = parse_windows_security_xml("security.xml")
    print(f"Parsed {len(events)} events from security.xml")
    store_events(events)
    detect(events)
    print("Stored events + detection complete. Run web_app.py to view dashboard")


if __name__ == "__main__":
    main()

































