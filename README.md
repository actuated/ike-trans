# ike-trans
A variation of the IKE-SCAN user guide's transforms discovery script, adding a few features. Handshakes can be done in Main or Aggressive Modes. For Aggresive Mode, a custom group ID can be given. Targets can be specified as a single IP, or an input file of multiple IPs.

# Usage
`ike-trans.sh` is based on the transforms script found at http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide. This script was written to add support for choosing Main or Aggressive Mode, as well as using either a single target or a file with a list of target IPs.

An IKE mode and target mode are required. Additional options include **-n [string]** to provide a custom group ID for Aggressive Mode, and **-o [filename]** to specify an output file.

`./ike-trans.sh [ike mode option] [target option] [[-n [string]]] [[-o [filename]]]`

**IKE Mode Options**
* **-m** specifies Main Mode.
* **-a** specifies Aggressive Mode.

**Target Options**
* **-t [target ip]** specifies a single target IP address.
* **-f [filename]** specifies a filename containing a list of IPs, one per line, to loop through.

**Optional Parameters**

* **--audit** performs audit of all IKE transformations.
* **-n [string]** specifies a custom group ID to use for Aggressive Mode. The default is "admin".
* **-o [filename]** specifies the name of an output file to copy results to.
* **--no-id-check** disables the check for INVALID-ID-INFORMATION in the response. By default, if this response is received, the script will report it and stop checking that host. This is desired, as it would be best to find a working transform with Main Mode, and then use `ike-force` by Spider Labs to do a dictionary attack for a working group ID.

# Example
```
# ./ike-trans.sh -a -t 1.2.3.4 -n vpn

===========[ ike-trans.sh - Ted R (github: actuated) ]===========

Aggressive Mode selected (ike-scan -A -M -n vpn).
Running in single host mode against 1.2.3.4.

Press Enter to begin...

=============================[ run ]=============================

1.2.3.4

[1] SYNTAX: ike-scan -A -M -n vpn --trans=5,2,1,2 1.2.3.4 -Ppsk.txt
TRANSFORM: 5,2,1,2
Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds

[2] SYNTAX: ike-scan -A -M -n vpn --trans=5,2,65001,2 1.2.3.4 -Ppsk.txt
TRANSFORM: 5,2,65001,2
Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=XAUTH LifeType=Seconds

[2] SYNTAX: ike-scan -2 -g 2 1.2.3.4
GROUP: 2
Encr=AES_CBC,KeyLength=256 Prf=HMAC_SHA1 Integ=HMAC_SHA1_96 DH_Group=2:modp1024

=============================[ fin ]=============================
```
