#!/bin/bash
# ike-trans.sh
# 10/30/2015 by Ted R (https://github.com/actuated)
# Adapted from original ike.sh script by Josh Stone
# Which was adapted from http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide
# Enhanced by Jan Rude (https://github.com/whoot)
# This script provides customizable IKE transforms scanning.
# It can call IKE-SCAN in Main (-m) and Aggressive (-a) modes.
# It can use a target IP (-t) or loop through a file of IPs (-f).
# For Aggressive Mode, it assumes the group name "admin", or can take input with -n.
# 10/30/2015 - Changed varIkeOpts and varAMAppend setting to be part of varIkeMode check instead of input option processing
# 10/31/2015 - Changed output to grep for SA, changed order of transform and example syntax
# 12/15/2015 - Fixed problem with SA grep/awk not showing ENC type
# 1/1/2016 - Aesthetic change
# 1/24/2016 - Added elif to check response for INVALID-ID-INFORMATION, --no-id-check to ignore
# 12/12/2022 - Added audit parameter, IKEv2 support, bugfixes for aggressive mode and better progress spinning animation

varDateCreated="10/30/2015"
varLastMod="12/12/2022"
varIkeMode="null" # Variable to set Main or Aggressive Mode IKE
varRunMode="null" # Varaible to set list or file targeting
varIkeOpts="null" # Variable to give ike-scan options based on IKE mode
varIkeName="admin" # Default group name for Aggressive Mode
varTarget="null" # Variable for target host or input file
varTest="" # Variable used to check input IPs and custom group name
varAMAppend="" # Variable to add -Ppsk.txt to the end of example syntax for Aggressive Mode responses
varOutFile="" # Variable for the name of the output file
varCheckID="Y" # Variable to flag whether to check Aggressive Mode responses for INVALID-ID-INFORMATION and stop checking that host
ENCLIST="1 5 7/128 7/192 7/256" # Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
HASHLIST="1 2" # Hash algorithms: MD5, SHA1
AUTHLIST="1 3 64221 65001" # Authentication methods: Pre-Shared Key, RSA Signatures Hybrid Mode and XAUTH
GROUPLIST="1 2 5" # Diffie-Hellman groups

# Function for providing help/usage text
function usage
{
  echo
  echo "===========[ ike-trans.sh - Ted R (github: actuated) ]==========="
  echo
  echo "Customizable IKE transforms scanner."
  echo "Adapted from script at:"
  echo "  http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide."
  echo
  echo "Created $varDateCreated, last modified $varLastMod."
  echo
  echo "============================[ usage ]============================"
  echo
  echo "Usage: ./ike-trans.sh [ike mode] [target] [group name] [output]"
  echo "Ex 1: ./ike-trans.sh -a -t 192.168.1.1 -n ciscovpn"
  echo "Ex 2: ./ike-trans.sh -m -f isakmp-hosts.txt -o out.txt"
  echo
  echo "IKE Mode Parameters: Must supply only one."
  echo -e "  -m \t\t Main Mode"
  echo -e "  -a \t\t Aggressive Mode"
  echo
  echo "Target Paramters: Must supply only one."
  echo -e "  -t [host ip] \t IP address of a single target"
  echo -e "  -f [file] \t File containing a list of IPs to loop through"
  echo
  echo "Group Name: Optionally specify a group name or ID to replace the"
  echo "default 'admin' (for Aggressive Mode)."
  echo -e "  -n [name]"
  echo
  echo "Perform audit of all IKE Transformations."
  echo -e "  --audit"
  echo
  echo "Do not check for and stop on INVALID-ID-INFORMATION."
  echo -e "  --no-id-check"
  echo
  echo "Output: Optionally provide an output file."
  echo -e "  -o [name]"
  echo
  exit
}

spin() {
   local -a marks=( '┤' '┘' '┴' '└' '├' '┌' '┬' '┐' )
   printf '%s\r' "${marks[i++ % ${#marks[@]}]}"
 }

# Function to perform IKE transforms scan for the provided host
# Loop through possible transforms settings, displaying the transform, example ike-scan syntax, and response for each working transform
function ike_trans
{
  echo "$1"
  varCount=1
  # Check Ikev1
  for ENC in $ENCLIST; do
    for HASH in $HASHLIST; do
      for AUTH in $AUTHLIST; do
        for GROUP in $GROUPLIST; do
          RESPONSE=`ike-scan $varIkeOpts --multiline --trans=$ENC,$HASH,$AUTH,$GROUP $1`
          varFlagReturned=$(echo "$RESPONSE" | grep -i 'handshake returned')
          if [ "$varCheckID" = "Y" ]; then varFlagInvalidID=$(echo "$RESPONSE" | grep -i 'invalid-id-information'); fi
          if [ "$varFlagReturned" != "" ]; then
            echo -e "\033[2K"
            echo "[$varCount] SYNTAX: ike-scan $varIkeOpts --trans=$ENC,$HASH,$AUTH,$GROUP $1 $varAMAppend"
            echo "TRANSFORM: $ENC,$HASH,$AUTH,$GROUP"
            echo "$RESPONSE" | grep 'SA=' | awk '{print $1, $2, $3, $4, $5 }' | sed 's/SA=(//g'
            let varCount=varCount+1
          elif [ "$varFlagInvalidID" != "" ]; then
            echo -e "\033[2K"
            echo "[*] INVALID-ID-INFORMATION:"
            echo "Find transforms with main mode and brute-force ID with ike-force"
            echo -e "\033[2K"
            return
          else
            spin
          fi
        done
      done
    done
  done
  # Check IKEv2
  for GROUP in 1 2 5 14 15 16 17 18; do
    RESPONSE=`ike-scan -2 --multiline -g $GROUP $1`
    varFlagReturned=$(echo "$RESPONSE" | grep -i 'handshake returned')
    if [ "$varFlagReturned" != "" ]; then
          echo -e "\033[2K"
          echo "[$varCount] SYNTAX: ike-scan -2 -g $GROUP $1"
          echo "GROUP: $GROUP"
          echo "$RESPONSE" | grep 'SA=' | awk '{print $1, $2, $3, $4, $5 }' | sed 's/SA=(//g;s/)//g;s/Encr/Enc/;s/,/ /;s/DH_//'
          let varCount=varCount+1
    else
      spin
    fi
  done
  echo -e "\033[2K"
}

# List-mode function to retrieve hosts from the list and call the ike_trans function for each
function list_loop
{
  for varLine in `cat $varTarget`; do
    varTest=$(echo $varLine | fgrep -o "." | wc -l)
      if [ "$varTest" = "3" ]; then
        echo
        ike_trans $varLine
      else
        echo
        echo "Error: '$varLine' in $varTarget does not appear to be an IP, skipping."
      fi      
  done
}

# Display usage if no arguments are given
if [ "$1" = "" ]; then
  usage
fi

# Read options and paramaters
while [ "$1" != "" ]; do
  case $1 in
# Set list-mode operation, check to make sure file is given and exists, or error
    -f ) shift
         varRunMode="list"
         if [ "$1" != "" ]; then
           if [ -f "$1" ]; then
             varTarget=$1
           else
             echo
             echo "Error: $1 does not exist as file for -f."
             usage
             exit
           fi
         else
           echo
           echo "Error: No file specified for -f."
           usage
           exit
         fi
         ;;
# Set host-mode operation, check to make sure input is given and formatted as IP, or error
    -t ) shift
         varRunMode="host"
         if [ "$1" != "" ]; then
           varTest=$(echo $1 | fgrep -o "." | wc -l)
           if [ "$varTest" = "3" ]; then
             varTarget=$1
           else
             echo
             echo "Error: $1 does not appear to be a target host IP for -t."
             usage
             exit
           fi
         else
           echo
           echo "Error: No target host specified for -t."
           usage
           exit
         fi
         ;;
# Set Main Mode and IKE options
    -m ) varIkeMode="main"
         ;;
# Set Aggressive Mode and IKE options
    -a ) varIkeMode="aggr"
         ;;
# Set an alternative vpn group name for Aggressive Mode, or leave "admin" if no value is given
    -n ) shift
         if [ "$1" != "" ]; then
           varIkeName=$1
         else
           varIkeName="admin"
         fi
         ;;
# Use all known transformations
    --audit ) shift
         ENCLIST="1 2 3 4 5 6 7/128 7/192 7/256 8" # Encryption algorithms: DES, IDEA, Blowfish, RC5, Triple-DES, CAST, AES/128, AES/192 and AES/256, Camellia
         HASHLIST="1 2 3 4 5 6" # Hash algorithms: MD5, SHA1, Tiger, SHA2-256, SHA2-384, SHA2-512
         AUTHLIST="1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010" # Authentication methods: Pre-Shared Key, RSA Signatures Hybrid Mode and XAUTH
         GROUPLIST="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 31" # Diffie-Hellman groups
         ;;
# Set output file, error if input is not provided or output file already exists
    -o ) shift
         if [ "$1" != "" ]; then
           varOutFile=$1
           if [ -f $varOutFile ]; then
             echo
             echo "Error: Output file already exists."
             usage
             exit
           fi
         else
           echo
           echo "Error: No output file specified for -o."
           usage
           exit
         fi
         ;;
    --no-id-check ) varCheckID="N"
         ;;
# Display usage information if -h or an invalid option are given
    -h ) usage
         exit
         ;;
    * )  usage
         exit 1
  esac
  shift
done

# Check to make sure an IKE mode was set
# Set ike-scan parameters based on IKE mode
if [ "$varIkeMode" = "main" ]; then
  varIkeOpts="-M"
  varAMAppend=""
elif [ "$varIkeMode" = "aggr" ]; then
  varIkeOpts="-A -M -n $varIkeName"
  varAMAppend="-Ppsk.txt"
elif [ "$varIkeMode" = "null" ]; then
  echo
  echo "Error: No Ike Mode (-a or -m) was set."
  usage
  exit
fi


# Check to make sure a target mode was set
if [ "$varRunMode" = "null" ]; then
  echo
  echo "Error: No Target (-t [host] or -f [file]) was set."
  usage
  exit
fi

# Display interpreted parameters to the use before running
echo
echo "===========[ ike-trans.sh - Ted R (github: actuated) ]==========="
echo
if [ "$varIkeMode" = "main" ]; then echo "Main Mode selected (ike-scan $varIkeOpts)."; fi
if [ "$varIkeMode" = "aggr" ]; then echo "Aggressive Mode selected (ike-scan $varIkeOpts)."; fi
if [ "$varRunMode" = "host" ]; then echo "Running in single host mode against $varTarget."; fi
if [ "$varRunMode" = "list" ]; then echo "Running in list target mode against $varTarget. Non-IP lines will be skipped."; fi
if [ "$varCheckID" = "Y" ]; then echo "Checking for INVALID-ID-INFORMATION."; fi
if [ "$varCheckID" = "N" ]; then echo "Not checking for INVALID-ID-INFORMATION."; fi
if [ "$varOutFile" != "" ]; then echo "Output enabled to $varOutFile."; fi
echo
read -p "Press Enter to begin..."
echo
echo "=============================[ run ]============================="

if [ "$varRunMode" = "host" ]; then
# Call the ike_trans function directly if host-mode targeting is used
  echo
  ike_trans $varTarget | tee $varOutFile
elif [ "$varRunMode" = "list" ]; then
# Call the list_loop function if list-mode targeting is used
# This lets all of the output be tee'd to output
  list_loop | tee $varOutFile
fi

echo "=============================[ fin ]============================="
echo

