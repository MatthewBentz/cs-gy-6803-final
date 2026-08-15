| ID | Requirement | Why it is Needed | How It Is Tested |
| 1 | The system shall require a user to log in with a username and password before changing settings | Prevents unauthorized people from changing incubator settings | Try accessing settings without login → access denied |
| 2 | The system shall lock a user account for 5 minutes after 5 failed login attempts within 10 minutes | Stops attackers from guessing passwords | Enter wrong password 5 times → account locks |
| 3 | The system shall check that temperature readings have not been altered before using them | Prevents unsafe decisions from incorrect data | Send incorrect data → system rejects it |
| 4 | The system shall protect communication so it cannot be read or changed by outsiders | Prevents data tampering and spying | Attempt unsecured connection → rejected |
| 5 | The system shall continue operating without stopping for more than 2 seconds | Ensures continuous safety for the infant | Simulate load → system remains active | 
| 6 | The system shall keep temperature between 36°C and 37.5°C if sensors fail | Maintains safe environment during failure | Disconnect sensor → temperature remains stable |
| 7 | The system shall record all user actions with time and user ID | Helps track system usage and issues | Perform action → verify it is logged |
| 8 | The system shall only install verified software updates | Prevents harmful or fake updates | Install invalid update → rejected |

