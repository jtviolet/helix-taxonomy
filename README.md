# What Is the Helix Taxonomy?
The Helix Taxonomy is FireEye's system for classifying logs. This is our way of providing normalized data to the Helix platform and there is one major advantage that this normalization provides us: Consistency.

Because of the consistent nature of the Helix Taxonomy, all information falls within a known number of categories and into a known list of objects. This allows us to fine-tune all of our algorithms across the board when the set of data is well-known. All searches, filtes, indexes, and algorithms can be hyper focused on one specific set of data, ensuring you get the most of your SIEM experience.

The Helix Taxonomy is actually very simple, and it works like this: You have a set of log data containing a number of fields (e.g. username, source ip, destination ip, last modified time, etc.) The problem is that you are one customer or partner and we have hundreds, all with variations of those logs (e.g. *sourceipv4, source_ip4, srcipv4, src_ip_v4, source ip*). The Helix Taxonomy has one key for this: ***srcipv4***.

This system ensures that we are able to categorize and store all data consistently to be analyzed on a common plane with all other systems.

# Getting Started
Getting started with the Helix Taxonomy is *very* simple. When you were a child, you probably recall having homework where you had a list of items on the left and you had to draw a line to their counterpart on the right, like so:
!["draw_line_reference"](https://files.readme.io/79a1e56-draw_line_reference.png)

The premise of making your logs taxonomically compliant with the Helix Taxonomy is no different: you are taking your log keys and matching them with a key in the Helix Taxonomy that makes the most sense. It really is that simple!

# Working with JSON
JSON is the most common, easiest-to-use log-type to send into Helix. Follow the steps below to make your JSON log taxonomically compliant. The only nuance with JSON is that nested objects are not allowed, and they must be de-nested. For example, the following log:
```
{
  "foo": {
    "bar": "",
    "baz": {
      "qux": ""
    }
  }
}
```
Unnested, would become:
```
{
  "foo_bar": "",
  "foo_baz_qux": ""
}
```
Once you have unnested your log, you are ready to make your JSON log taxonomically compliant. Move onto the Helix Taxonomy page to match your log keys to the most appropriate Helix Taxonomy key.

# Required Taxonomy Objects

## class
Allows Helix to directly classify all logs coming from a service, product, or vendor. This classification name will me the primary means in which Helix differentiates your logs from others. 

## metaclass
Permits different classes to be lumped into general catagorizes/metaclass. Multiple metaclasses may be used within a JSON array. Most popular uses are 'firewall', 'http_proxy', or 'ids'. If properly used metaclass can greatly reduce the number of Helix detection rules by broadening the alert query.

```
{
  "class" : "myfirewall",
  "metaclass" : "firewall"
 }
 
 {
  "class" : "checkpoint",
  "metaclass" : ["firewall","http_proxy"]
 }
 ```

# Helix Taxonomy Objects
Below you will find all objects in the Helix Taxonomy, their metadata, and examples of that log type. Each Helix Taxonomy object will have an associated data type, data format, short description, and examples of what related fields might look like.

## accesses
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | List of accesses for an account, typically recorded in the windows event logs as "Accesses" |  |

## accessgroup
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Access group, tupically for authorization purposes |  |

## accessmask
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A 32-bit value that specifies the rights that are allowed or denied in an access control entry (ACE). |  |

## accountdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | domain | accountdomain, used in accountname/accountdomain pairs typically found in authentication events from windows and other log types |  |

## accountid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific account identifier, see also userid for specific users |  |

## accountname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | accountname, used in accountname/accountdomain pairs typically found in authentication events from windows and other log types |  |

## ackduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | ammount of time in seconds that it took to acknowledge |  |

## acktime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was acknowledged |  |

## acktimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was acknowledged |  |

## aclname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Access Control List name, typically referring to router ACLs |  |

## aclnumber
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Access Control List number, typcially referring to router ACLs |  |

## acquire_attempt_count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | In HIP events, the count of the acquire attempts |  |

## acquired_at_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | In HIP events, date/time that something was acknowledged |  |

## acquired_by
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, a descriptive name for the ownership |  |

## action
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Action in the generic sense, typically representing action taken as a result of an event (allow,drop,quarantine,etc) |  |

## actioncode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Action code related to Action |  |

## activity
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any activity name, typically found in windows event logs as activity |  |

## activityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any activity identifier, typically found in windows event logs as activity ID |  |

## actor
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The user or service principal that performed the action |  |

## addl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, additional responses for the query |  |

## ag_count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | In HIP events, ag count |  |

## agent
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | Referencing an agent by name, typically when unique from hostname or similar, see also agentid |  |

## agentid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific agent identifier |  |

## agentversion
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Version of the agent named in the log |  |

## alert_product
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  |  |  |

## alert_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP event, alert time |  |

## alertdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the domain of a generated alert for FireEye and other devices |  |

## alerted
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, field for alerted  |  |

## alerturi
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the URI of a generated alert for FireEye and other devices |  |

## alerturl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the URL of a generated alert for FireEye and other devices |  |

## analyzer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for an analyzer |  |

## answer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Answer returned |  |

## apipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 address of the Access Point |  |

## apipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | IPv6 address of the Access Point |  |

## apmac
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| mac |  | Access Point MAC address |  |

## apname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Access Point name, typically referred as AP in WLAN configurations and logs |  |

## appcategory
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Application category for application monitoring in Checkpoint logs & other. |  |

## appdesc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Description field for application monitoring. |  |

## appid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Application ID for application monitoring within Checkpoint logs & other. |  |

## application
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing an application name |  |

## apppath
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Path where the application can be found in the system |  |

## appproperties
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Designates application properties for Checkpoint & other logs. |  |

## args
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | arguments supplied to a command or operation |  |

## asn
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Autonomous System Number (ASN) routing prefixes |  |

## attachment
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Attachment, typically observed as a filename attached to an email or IM communication |  |

## attack
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Attack name, typically observed in the firewall or proxy logs |  |

## attackinfo
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Attack description or complementary information |  |

## attemptingAcquire
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, a field to hold for attempting acquire |  |

## audititemid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | audititemid used as an identifier to audit items |  |

## auth
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, authoritatice responses for the query |  |

## auth_success
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, authentication result |  |

## authmethod
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The method of authentication used, e.g. local, domain, LDAP. Could also include network authmethods e.g. LANMAN, NTLMv1, NTLMv2, kerberos, etc |  |

## authoritativeanswer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The Authoritative Answer bit for response messages specifies that the responding name server is an authority for the domain name in the question section. |  |

## av_hits
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Antivirus hits description |  |

## ax_malicious_alerts
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the ax malicious alerts |  |

## ax_score
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, score as defined by the log source, typically referring to the current ax score |  |

## bay
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | used to capture a bay, typically referring to infrastructure equipment. |  |

## behavior
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing behavior |  |

## binary_can_sleep
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, binary can sleep |  |

## binary_languages
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events,a field for binary languages |  |

## binarystate
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The state of a value in boolean |  |

## bytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Bytes in the generic sense, often used when direction is unknown. In Bro file logs this is total number of bytes that are supposed to comprise the full file. |  |

## bytespersec
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Total number of bytes per second |  |

## cachetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a type of chache, e.g. ARP cache or other |  |

## cacheval
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a value found in some type of cache, see also cachetype |  |

## callid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific call identifier |  |

## callingdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | domain | Authentication domain of a remote calling identity, typically observed in windows event logs as calling domain |  |

## callinglogonid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Windows login id of a remote calling identity, typically observed in windows event logs as caller logon id |  |

## callingsrcip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | source IP of a remote calling identity, typically observed in windows event logs as calling address |  |

## callingsrcipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | Source IPv6 of a remote calling identity, typically observed in windows event logs as "Calling Address" |  |

## callinguid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | User ID of a remote calling identity, typically observed in windows event logs as calling id |  |

## callingusername
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Username of a remote calling identity, typically observed in windows event logs as calling username |  |

## callingusersecurityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Unique, immutable identifier of a remote calling identity, typically observed in windows event logs as caller user |  |

## capture_password
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, determines if the password will be captured for this request |  |

## category
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for Category, typcially identifies a product specific category of event, alert, or activity |  |

## cc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | email | General purpose field for representing cc, with respect to origin. Typically used in email, IM, etc. |  |

## cert_chain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, chain of certificates offered by the server to validate its complete signing chain |  |

## cert_chain_fuids
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, an ordered vector of all certicate file unique id's for the certificates offered by the server |  |

## cert_count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Certificate count |  |

## cert_errors
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A field for representing Certificate errors |  |

## cert_permanent
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, indicates if the provided certificate or cert chain is permanent or temporary |  |

## cert_type
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, if the connection is being encrypted with native rdp encryption, this is the type of cert being used |  |

## certname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | name of certificate |  |

## certsubject
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Certificate subject, in Bro ssl logs this is the 'subject' field. |  |

## charencoding
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | character encoding being used, e.g. ASCII, UNCODE, etc. |  |

## cidr
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | CIDR notation |  |

## cipher
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a specific cipher being used |  |

## class
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Class of event log collected. |  |

## client
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the client's version string |  |

## client_cert_chain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, chain of certificates offered by the client to validate its complete signing chain |  |

## client_cert_chain_fuids
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, an ordered vector of all certicate file unique id's for the certificates offered by the client |  |

## client_depth
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, client depth |  |

## client_key_exchange_seen
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, flag to indicate if we saw a client key exchange message sent by the client. |  |

## client_ticket_empty_session_seen
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, flag to indicate if we saw a non-empty session ticket being sent by the client using an empty session id |  |

## client_uuid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A universally unique client identifier is an identifier standard used in software construction |  |

## clientissuersubject
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Client Issuer certificate subject, in Bro ssl logs, this is the subject of the signer of the X.509 certificate offered by the client. |  |

## clientsubject
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Client certificate subject, in Bro ssl logs, this is the subject of the X.509 certificate offered by the client. |  |

## clientvars
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Client header variables |  |

## closeduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | ammount of time in seconds that it took to close |  |

## closetime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was closed, typically referring to workflow |  |

## closetimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was closed, typically referring to workflow |  |

## cmdarg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, command that is currently waiting for response |  |

## cnchost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used for identifying CNC (Command and Control) Host servers, typically malicious in nature.  |  |

## cncipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used for identifying CNC (Command and Control) Host server communication IP version 4 addresses. These could be either ingress or egress. |  |

## cncport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Used for identifying CNC (Command and Control) Host server communication ports. These could be either ingress or egress. |  |

## compile_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | The date/time when something was compiled |  |

## compression_alg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the compression algorithm in use |  |

## confidence
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture confidence level |  |

## connectionid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific connection identifier |  |

## connections
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Total number of connections |  |

## connstate
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Connection state, found in Bro conn logs, identifies the state of a connection via defined connstate codes, ref: bro documentation for the latest definitions. |  |

## containduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | ammount of time in seconds that it took to contain |  |

## containtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was contained, typically referring to host containment during an IR activity |  |

## containtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was contained, typically referring to host containment during an IR activity |  |

## content
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | content type, referring to HTTP content-type |  |

## context_tags
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Context tags added by decoration or other services |  |

## cookievars
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Cookie variables |  |

## count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | General purpose field used for capturing a count of any value |  |

## count_updated_at_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | In HIP events, the date/time when count was updated |  |

## createdtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was created or instantiated, implies there are follow on stamps |  |

## createdtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC  date/time that something was created or instantiated, implies there are follow on stamps |  |

## creatorprocessid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific creator process identifier |  |

## current_status
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the current status |  |

## current_status_txt
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the current status text |  |

## curve
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, elliptic curve the server chose when using ecdh?/cdhe |  |

## customer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Customer name, title, or description |  |

## customercode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Customer code, see also customer |  |

## cveid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Common Vulnerabilities and Exposures identifier, ref http://cve.mitre.org/cve/identifiers/index.html |  |

## cwd
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, current working directory that this session is in |  |

## data_channel
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, expected ftp data channel |  |

## day
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for day values |  |

## dbinstance
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a database instance |  |

## dbname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a database name |  |

## dbtable
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a database table |  |

## dcid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Delivery Connection ID used in Ironport E-mail. Each recipient to the same domain gets the same DCID, otherwise each recipient gets a different one. |  |

## defgw
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | Default gateway, typically referenced in network events |  |

## depth
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the depth of something, e.g. 32bytes,  |  |

## description
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture an event description, often free formed text messages unable to be further parsed |  |

## desktop_height
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, desktop height of client machine |  |

## desktop_width
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, desktop width of client machine |  |

## detectedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that the detection took place |  |

## detectedtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that the detection took place |  |

## deviceid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific device identifier |  |

## devicename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a devicename, e.g. removable media device name.  See also hostname |  |

## devicetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a device type, typically reserved for categories of devices, see also deviceid |  |

## dhcpscope
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Stores the dhcp scope range. |  |

## direction
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to specify logical flow or direction, inbound/outbound, etc. |  |

## disabled_aids
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, disabled analyzer id's |  |

## disk
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | the name of a disk, typically a physical disk, see also volume |  |

## disposition
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The final result condition that something ended in (success, failure, etc) Not to be confused with status  |  |

## dns_lookups
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The list of DNS lookups |  |

## domain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | domain | Domain from which an identity resides, typically an Active Directory domain, LDAP domain, Kerberos realm, etc.  |  |

## done
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, status of rdp connections done if t |  |

## driver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name of the driver installed, modified or deleted. Typically observed in windows event logs as "Driver" |  |

## dropped
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In Bro notice logs, the dropped field indicates a T/F bool. |  |

## dsthost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | hostname of the destination manchine, when direction is known and/or relevant, will typically resolve to dstip or dstipv6 |  |

## dstipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | IPv4 address of the destination |  |

## dstipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv6 | IPv6 address of the destination |  |

## dstmac
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | mac | MAC address of the destination when direction is known |  |

## dstnatrule
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | JunOS destination address NAT flow rule name |  |

## dstport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Destination port number |  |

## dstserver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 address of the destination server in a DHCP connection |  |

## dstzone
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Destination zone, when direction is known and/or relevant, typically reserved for network or firewall events specifying a logical  zone within the event |  |

## duration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Total duration in seconds |  |

## dynamic_indicators
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the dynamic indicators |  |

## enc_appdata_bytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, present if heartbleed.bro is present |  |

## enc_appdata_packages
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, present if heartbleed.bro is present |  |

## encodedmsg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | the encoded version of the message or string |  |

## encryption
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | encryption type being used |  |

## encryption_level
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, encryption level of the connection |  |

## endtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something ended, typically referring to connection events or events with a definitive start and end |  |

## endtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something ended, typically referring to connection events or events with a definitive start and end |  |

## enriched
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, whether the information is enriched |  |

## enrichment_error
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, a field for the encountered enrichment error   |  |

## enrichment_start
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | In HIP events, The date/time of enrichment start |  |

## enrichment_status_txt
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  |  |  |

## errorcode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Specific field reserved for explicit interger error codes |  |

## errormessage
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Specific field reserved for error code text strings |  |

## escalateduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | ammount of time in seconds that it took to escalate |  |

## escalatetime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was escalated, typically referring to workflow |  |

## escalatetimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was escalated, typically referring to workflow |  |

## established
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, flag to indicate if this ssl session has been established successfully or aborted |  |

## eventid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture any one specific event identifier |  |

## eventlog
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | name of the specific event log that the event came from |  |

## eventname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Description of the event included in the CEF log header |  |

## eventreceivedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| date-time |  | date/time in which the event was received |  |

## eventtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that the actual event took place, as found in the payload of the message. |  |

## eventtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that the actual event took place, as found in the payload of the message. |  |

## eventtype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Type of event, as often used in Windows events. |  |

## evil_flag
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, a flag whether the event is evil |  |

## evil_indicators
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, identify a set of evil indicators of various attributes. |  |

## exceptionlvl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | To display an excpetional level integer as from a service like MS Exchange ActiveSync |  |

## exceptionmsg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | To display an exception message for a service such as MS Exchange ActiveSync |  |

## exceptiontype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The type of exception given by an application such as MS Exchange ActiveSync. |  |

## expirationtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something will or has expired |  |

## expirationtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something will or has expired |  |

## extension
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Extension values |  |

## extnatip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | External NAT IP address, used in NAT logs |  |

## extnatipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | External NAT IPv6 address, used in NAT logs |  |

## extracted
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In Bro logs, if the file extraction successfully extracted the file from the stream. |  |

## facility
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Syslog facility. Used to specify the type of program that is logging the message, typically observed in unix logs |  |

## family
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to specify a family name or logical grouping, typically one or more malware families. |  |

## file_accessed_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | General purpose date/time field for file access time |  |

## file_created_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | General purpose date/time field for file creation |  |

## file_enrichment_status
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the file enrichment status |  |

## file_mime_type
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Specifically distinguising a specific file MIMEtype as observed in a message |  |

## file_modified_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | General purpose date/time field for file modification |  |

## file_owner
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a file owner. |  |

## file_signed
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, whether the file was signed or not |  |

## filedesc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In Bro notice logs, file_desc is a file description. |  |

## fileid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific file identifier |  |

## filename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a file name, may or may not include the entire file path preceding the file name. |  |

## filepath
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | path | General purpose field for representing a file path |  |

## filepermission
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing file permission |  |

## filetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The type of file, as referenced by the log source |  |

## filter
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a specific filter, as defined by the log source |  |

## fingerprint
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A SSL or TLS fingerprint, as used in bro_ssl logs. |  |

## firstseen
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was first seen, typically referring to malware indicators or IR related events. |  |

## firstseenutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was first seen, typically referring to malware indicators or IR related events. |  |

## flagtype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a flag name |  |

## flagval
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a flag value |  |

## force_log
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, indicates that this software being detected should definitely be sent onward to the logging framework |  |

## foreigninterface
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Foreign interface identifier, typically reserved for network or firewall events specifying interface orientation |  |

## fqdn_nucleus_summary
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the fqdn nucleus summary |  |

## from
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | email | General purpose field for representing from, with respect to origin. Typically used in email, IM, etc. |  |

## function
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Refered to a function in a program source code. |  |

## fwdipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 forwarding address typically used in firewall devices |  |

## fwdipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | IPv6 forwarding address typically used in firewall devices |  |

## gid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | any one specific group identifier |  |

## group
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a group, typically a AD or LDAP group, but could be the name of any logical grouping. |  |

## groupdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Authentication domain of a group, typically observed in windows event logs as "Group Domain" |  |

## groupsecurityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Unique, immutable identifier of a Windows user group. |  |

## gwipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 address of the gateway not set as default, typically referenced in network events |  |

## gwipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | IPv6 address of the gateway not set as default, typically referenced in network events |  |

## handleid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | any one specific handle identifier, referring to process handle IDs. |  |

## has_cert_table
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file has attribute certificate table |  |

## has_debug_data
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file has debug data |  |

## has_export_table
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file has export table |  |

## has_import_table
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file has import table |  |

## hash
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for storing any type of message digest hash value |  |

## hasMTAReport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, whether the log has a message/mail transfer agent(MTA) report |  |

## heartbleed_detected
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, present if heartbleed.bro is present |  |

## hierarchy
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A description of how and where the requested object was fetched |  |

## history
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | History, found in Bro conn logs, records the state history of connections as a string of letters. Ref: bro documentation for the latest definitions. |  |

## host_count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Host count |  |

## host_key
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the server's key fingerprint |  |

## host_key_alg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the server host key's algorithm |  |

## hostname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | hostname, used whenever source or dest is unclear or unknown. |  |

## hour
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for hour values |  |

## httpbody
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Indicator of client body based SQL injection attack. This is typically the body content of a POST request. |  |

## httpmethod
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | HTTP method, e.g. GET,POST,PUT,etc. |  |

## icid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Injection Connection ID used in Ironport E-mail. ICID assigned when a remote host connects to the appliance. |  |

## impact
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture impact level |  |

## imphash
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | import hash |  |

## import_hash_count
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | import hash count |  |

## info
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Supplemental info for a given event that is optional or adding supplimental context, typically not well delimited for fine parsing |  |

## infocode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Informational message from Bro http logs, containing the last seen 1xx informational reply code returned by the server. |  |

## infomsg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Informational message from Bro http logs, containing the last seen 1xx informational reply message returned by the server. |  |

## inreplyto
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | RFC 4021 Header information, for mail in reply to header designations |  |

## integritylevel
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Representation of the trustworthiness of running application processes and objects, such as files created by the application |  |

## interface
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Logical or physical network interface used for communications (eth0, eth1, etc) when orientation is unknown |  |

## interfaceid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Unique identifier assigned to a logical or physical network interface |  |

## intnatip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | Internal NAT IP address, used in NAT logs |  |

## ip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | DO NOT USE FOR PAYLOAD |  |

## ipmask
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | IP network mask |  |

## ipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | General purpose field for representing an IPv4 address, only used when source or dest is unclear or unknown. |  |

## ipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv6 | General purpose field for representing an IPv6 address, only used when source or dest is unclear or unknown. |  |

## is_64bit
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file is 64-bit executable |  |

## is_exe
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file is executable |  |

## is_malware
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | Whether something is a malware or not |  |

## isacquired
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In HIP events, whether the system was acquired or not |  |

## isorig
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In Bro logs, if the source of this file is a network connection, this field indicates if the file is being sent by the originator of the connection or the responder. |  |

## issuer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing an issuer, e.g. Certificate Issuer |  |

## issuersubject
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Issuer certificate subject, in Bro ssl logs, this is the subject of the signer of the X.509 certificate offered by the server. |  |

## issuetime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was issued, or becomes active, typically a certificate. |  |

## issuetimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was issued, or becomes active, typically a certificate. |  |

## job
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any job name, typically found in windows event logs as job |  |

## jobid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any job identifier, typically found in windows event logs as job ID |  |

## kex_alg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the key exchange algorithm in use |  |

## keywords
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Hexadecimal value used to group events based on the usage of the events. Typically found on windows event logs |  |

## language
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | To define a language within a logsource. |  |

## last_auth_requested
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, last auth requested |  |

## last_originator_heartbeat_request_size
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, present if heartbleed.bro is present |  |

## lastaccessedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that an object was last accessed |  |

## lastaccessedtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that an object was last accessed |  |

## lastalertid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In Bro ssl logs, the last_alert field is the last alert that was seen during the connection |  |

## lastmodifiedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that an object was last modified |  |

## lastmodifiedtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that an object was last modified |  |

## lastscannedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was last scanned, typically used for vulnerability, AV, or other malware detection technologies |  |

## lastscannedtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was last scanned, typically used for vulnerability, AV, or other malware detection technologies |  |

## lastseen
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was last seen, typically referring to malware indicators or IR related events. |  |

## lastseenutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was last seen, typically referring to malware indicators or IR related events. |  |

## length
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the length of something |  |

## level
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | General purpose field for interger levels, such as level {1,2,3,} etc. |  |

## linenumber
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | linenumber referencing the location in a page or file |  |

## local_resp
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if connection is responded to locally, false if responded to remotely |  |

## localinterface
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Local interface identifier, typcially reserved for network or firewall events specifying interface orientation |  |

## localorig
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In Bro logs, if the source of this file is a network connection, this field indicates if the data originated from the local network or not as determined by the configured Site::local_nets. |  |

## logged
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, whether this has already been logged and can be ignored |  |

## logonguid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | User ID of a login identity, typically observed in windows event logs as calling id |  |

## logonid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Windows user login id's which are unique between reboots on the same computer. Used to positively correlate between logins and security event logs |  |

## logontype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | logon type referring to char string types (win32, ADVAPI, etc) |  |

## logontypeid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Integer id that specifies type of windows logon (interactive/network/batch/etc) |  |

## mac
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | mac | General purpose field for MAC address, used whenever  |  |

## mac_alg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the signing (mac) algorithm in use |  |

## macoui
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | mac | The Organizationally Unique Identifier of a MAC address, ref: http://en.wikipedia.org/wiki/MAC_address |  |

## mailbox
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | specifying a mailbox location |  |

## mailfrom
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | RFC 4021 Header information, for mailroom designations |  |

## malwarefamily
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the family of a deteced malware |  |

## malwarename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the name of a detected malware |  |

## malwaretype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the type or FireEye assigned signature type of a detected malware |  |

## malwarevariant
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to represent the variant of a detected malware |  |

## manufacturer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Manufacturer of a product |  |

## mcube_list
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the mcube list |  |

## md5
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | computed MD5 hash of an object |  |

## member
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name of the group member added, modified or deleted. Typically observed in windows event logs as "Member Name" |  |

## memberdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name of the group member domain. Typically observed in windows event logs as member domain |  |

## membersecurityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Unique, immutable identifier of a group member. Typically observed in windows event logs as "Member ID" |  |

## method
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing method, see also httpmethod and authmethod |  |

## mid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Message ID used in Ironport E-mail. Once connection established, each successful "mail from:" command creates a MID. |  |

## mimetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Specifically distinguising a specific MIMEtype as observed in a message |  |

## minute
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for minute values |  |

## missingbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro logs, the number of bytes in the file stream that were completely missed during the process of analysis e.g. due to dropped packets. |  |

## mode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the mode of something, as defined by the log source |  |

## month
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for month values |  |

## msg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field to capture some or all of the message, used only when field parsing is not desired. |  |

## msr_ruleids
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| array |  | In Detection, the rule id's of multi-stage rule(s) |  |

## network
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Network segment, it can include the network prefix |  |

## network_connections
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | List of all network connections |  |

## next_protocol
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, next protocol the server chose using the application layer next protocol extension if present |  |

## nick
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, nickname given for the connection |  |

## node
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | Reserved for specific references to a node, typically reserved for sensor nodes or similar uses explicitly calling out nodes |  |

## notice
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, indicates if this weird was also turn into a notice |  |

## nuc_attribution_date
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | In HIP events, the nuc attribution date/time |  |

## nuc_md5_attribution
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the nuc md5 attribution |  |

## number
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | General purpose field for representing the order in which something is numbered in a sequence, e.g. partitionnumber=2, packetnumber=754 |  |

## object
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any object name, typically observed in the windows event logs as "Object" |  |

## objectserver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name of the system component handling the access request. Typically found on windows event logs |  |

## objecttype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any object type, typically observed in the windows event logs as "Object Type" |  |

## ocsp_response
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, oscp response as a string |  |

## ocsp_status
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, result of ocsp validation for this connection |  |

## offset
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the order in which something is offset, e.g. 4-bytes, 1024kb |  |

## operationid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific operation identifier |  |

## origin
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the origin |  |

## original_company_name
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, field for original company name |  |

## original_description
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, field for original description |  |

## original_file_name
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, field for original file name |  |

## originationtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that specifies the origination of something, implying when a transmission originated from A to B |  |

## originationtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that specifies the origination of something, implying when a transmission originated from A to B |  |

## originator_heartbeats
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, present if heartbleed.bro is present |  |

## os
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | operating system, typically the major OS display name |  |

## overflowbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro logs, the number of not all-in-sequence bytes in the file stream that were delivered to file analyzers due to reassembly buffer overflow. |  |

## packet_segment
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, a chunk of the payload that most likely resulted in the protocol violation |  |

## packets
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Generic packet count, typically only used when direction sent/rcvd is unknown |  |

## packettype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Type of packet ex. SYN, FIN, R |  |

## page
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | page, typtically referencing the existing page |  |

## parentfileid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific parent file identifier. In Bro logs, this is the identifier associated with a container file from which the child (fileid) was extracted as part of the file analysis. |  |

## pargs
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | parent arguments supplied to a command or operation |  |

## partition
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  |  the name of a partition, see also volume |  |

## passive
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, indicates if the session is in active or passive mode |  |

## password
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Password for a given username or account |  |

## peak
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Peak level as defined by the log source, typically referring to a peak level or percentage |  |

## pecreatedtime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | Date/time created as specified in the PE header of a PE file. |  |

## pecreatedtimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC Date/time created as specified in the PE header of a PE file. |  |

## peer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a peer, typically in an authentication relationship |  |

## pending_commands
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, queue for commands that have been sent but not yet responded to are tracked here |  |

## perchg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Percent Changed as defined by the log source |  |

## pid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | any one specific process ID, typically used for application PIDs |  |

## policy
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Typically the display name of the policy, see also policyid |  |

## policyid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific policy identifier |  |

## portid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific portid or terminal port id |  |

## ppid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | any one specific parent process ID, typcially used for application PPIDs. |  |

## pprocess
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | parent process or image, usually in Windows events. |  |

## pprocessguid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | parent process user ID, usually in Windows events. |  |

## prevscore
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | previous score as defined by the log source, typcially referring to a score prior to some follow up activity or event |  |

## printer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a printer object, physical or virtual |  |

## priority
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture a priority value |  |

## privileges
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | privileges held or granted, typically as recorded in the windows event log |  |

## privlevel
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Priviledge level |  |

## process
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a process, typically used for the full process name/description, see also pid and ppid |  |

## processguid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Process user ID, usually in Windows events. |  |

## processid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific process identifier |  |

## processpath
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Path where the process resides in the system |  |

## product
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a specific product, typically used when one log source contains multiple product types |  |

## profile
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a profile, as defined by the log source |  |

## program
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The name for a program, see also application |  |

## protocol
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | protocol used in a session. Typcially http, ftp, smtp, etc. |  |

## protocolver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | representing a specific version of a protocol, used with 'protocol' field, e.g., TLSv1, TLSv2, TLSv3, etc. |  |

## protoid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Numerical representation of a protocol (6=TCP, 17=UDP, 47=GRE, etc) |  |

## providerguid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Globally unique identifier (GUID) of the provider that published the event. Typically found on windows event logs |  |

## proxied
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Proxied, from Bro http logs, contains all of the headers that may indicate if the request was proxied. |  |

## proxydstipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | Proxy destination IP address. |  |

## proxysrcipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Designates the proxy source ip address. |  |

## proxystatuscode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Numerical representation of a status from the proxy |  |

## query
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a query of some sort (DNS, Web, DB, etc) |  |

## queryclass
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | the class of the query. (0,1,2,3, etc) |  |

## queryclassname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A descriptive name for the class of query |  |

## querytype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | A QTYPE value specifying the type of query, typically 1,2,6,12, 28 etc.  Ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types |  |

## querytypename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A descriptive name for the type of query, A, NS, SOA, PTR, AAAA, etc.ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types |  |

## rateavg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Average rate as used in CISCO_ASA Threat Detection |  |

## rateid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Configured rate being exceeded as used in CISCO_ASA Threat Detection |  |

## ratemax
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Maximum rate as used in CISCO_ASA Threat Detection. |  |

## rateval
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Current rate value as used in CISCO_ASA Threat Detection. |  |

## rcptto
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | RFC 4021 Header information, for mail receipt to header designations |  |

## rcvdbodybytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In bro http logs, the response_body_len, is the actual uncompressed content size of the data transferred form the server. |  |

## rcvdbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Total bytes received by dest from a source |  |

## rcvdfileid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Received File identifier, found in Bro http logs as the resp_fuids value, indicates the file identifier of a file pertaining to a receiver. |  |

## rcvdipbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro logs, the resp_ip_bytes field that Number of IP level bytes that the responder sent (as seen on the wire, taken from the IP total_length header field).  |  |

## rcvdmimetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Received MIME type, found in Bro http logs as the resp_mime_types value, indicates the mime type of a file pertaining to a receiver. |  |

## rcvdpackets
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | number of packets received in the transaction |  |

## ready
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | This value indicates if this request/response pair is ready to be logged.  Could be used for any BOOL ready status  (YES|NO) (True|False) |  |

## reason
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Reason in the generic sense, when a payload contains a more specific reason(s) for a given action, severity, or other field. |  |

## receptorhostid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the receptor host id |  |

## recordid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used for parsing updates on Windows event logs. Allows for easier sorting of events in table view. |  |

## recursionavailable
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The Recursion Available bit in a response message indicates that the name server supports recursive queries. |  |

## recursiondesired
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The Recursion Desired bit in a request message indicates that the client wants recursive service for this query. |  |

## referenceid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific reference ID relating 2 or more things together. |  |

## referrer
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The HTTP referrer field value |  |

## referrer_domain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The HTTP referrer field domain value |  |

## referrer_uri
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The HTTP referrer field which contains URI(path and query) values |  |

## region
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The state or providence, used for geolocation |  |

## regkey
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Registry key name, not the entire preceding regpath |  |

## regpath
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Basic registry path, could optionally include the reg key |  |

## regvalue
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Registry value contained within a key |  |

## rejected
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The DNS query was rejected by the server.  Could be used for any BOOL rejection status (YES|NO) (True|False) |  |

## reply_code
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, reply code from the server in response to the command |  |

## reply_msg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, reply message from the server in response to the command |  |

## replyto
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | email | General purpose field for representing replyto, with respect to origin. Typically used in email, IM, etc. |  |

## reportduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | ammount of time in seconds that it took to report |  |

## requestduration
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | ammount of time in seconds that it took to request |  |

## requestid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific requestID, specifying the identifier of a given request. Typically authentication or query/response type of reqests. |  |

## requesttime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something was requested |  |

## requesttimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something was requested |  |

## responder_heartbeats
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, present if heartbleed.bro is present |  |

## response
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | response given |  |

## responsecode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | The response code value, typically in DNS response messages |  |

## responsecodename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A descriptive name for the response code value |  |

## restrictedsidcount
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In Windows logs, the count of restricted security ID's |  |

## result
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The final result condition that something ended in (success, failure, etc) Not to be confused with status  |  |

## resumed
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, flag to indicate if the session was resumed reusing the key material exchanged in an earlier connection |  |

## rid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Recipient ID used in Ironport E-mail. Each recipient (To: CC: or BCC:) will get a RID. |  |

## risk
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture any risk level when displayed by name (e.g. LOW,MED,HIGH,CRITICAL,etc) see also: risklevel |  |

## risklevel
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | General purpose field used to capture any risk level when displayed by interger level (e.g. 0,1,2,3,etc) see also: risk |  |

## roleid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any one specific role identifier |  |

## rt_version
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| object |  | RT_VERSION hashes are a unique characteristic of Windows executable (PE) files. Found in fireeye_faf events. |  |

## rule
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Rule, typcally in the form of a rule name, signature name, title or brief message. |  |

## rulecat
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Rule or Singature Category, typically defined by the vendor and organized into one or more categories or logical groupings |  |

## ruleid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Rule or Signature ID containing a unique ID for a given rule or signature, typically an INT but could contain a CHAR |  |

## satori_blacklist
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the satori blacklist |  |

## saw_query
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if full dns query has been seen |  |

## saw_reply
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if full dns reply has been seen |  |

## score
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | score as defined by the log source, typically referring to the current score or most recent score |  |

## second
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for second values |  |

## seenbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro logs, number of bytes provided to the file analysis engine for the file. |  |

## sensor
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | Referencing a sensor by name |  |

## sentbodybytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In bro http logs, the request_body_len, is the actual uncompressed content size of the data transferred form the server. |  |

## sentbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Total bytes sent from a source to a dest |  |

## sentfileid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Sent File identifier, found in Bro http logs as the orig_fuids value, indicates the file identifier of a file pertaining to an orignator. |  |

## sentipbytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro logs, the orig_ip_bytes field that Number of IP level bytes that the originator sent (as seen on the wire, taken from the IP total_length header field).  |  |

## sentmimetype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Sent MIME type, found in Bro http logs as the orig_mime_types value, indicates the mime type of a file pertaining to an orignator. |  |

## sentpackets
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | number of packets sent in the transaction |  |

## serial
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Serial number field used to represent physical or virtual serial numbers |  |

## server
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | Reserved for when srchost/dsthost does not apply, e.g. a central management server, proxy, router, etc. serving a nondirectional role. |  |

## server_depth
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, current number of certificates seen from either side. used to create file handles. |  |

## serveripv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 address of the server |  |

## serveripv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | IPv6 address of the server |  |

## serverport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Port number used by the server |  |

## serverstatuscode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Numerical representation of a statusfrom ther server |  |

## servervars
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Server header variables |  |

## service
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Service in the generic sense, typically represents a windows service, network service identifier, or other service description. |  |

## serviceid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Service Identifier |  |

## sessionid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific session identifier |  |

## sessionname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name used to identify a session |  |

## sessiontype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Type of session referenced in the log |  |

## severity
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field used to capture severity level |  |

## severityvalue
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | General purpose field used to capture numerical severity level |  |

## sha1
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | computed SHA1 hash of an object |  |

## sha256
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | computed SHA256 has of an object |  |

## sha512
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | computed SHA512 has of an object |  |

## signature
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Signature, as in Windows events |  |

## signed
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | Signed, as in windows events |  |

## site
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing a site, physical or logical |  |

## size
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the size of something, e.g. disk size=2TB |  |

## sizeinram
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Specific size of something, measured in bytes, in RAM |  |

## sizeondisk
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | Specific size of something, measured in bytes, on Disk |  |

## slot
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | used to capture a slot, typically referring to infrastructure equipment. |  |

## snort_alert
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the snort alert |  |

## source
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | source referring to the source of the event log, e.g. httpd, auth, etc. |  |

## sourceclass
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Refered to a class in a program source code. |  |

## sourcemodulename
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The NXLog source module name |  |

## sourcemoduletype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The NXLog source module type |  |

## srchost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | hostname of the source machine, when direction is known and/or relevant, will typically resolve to srcip or srcipv6 |  |

## srcipv4
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | IPv4 address of the source |  |

## srcipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv6 | IPv6 address of the source |  |

## srcmac
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | mac | MAC address of the source when direction is known |  |

## srcnatrule
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | JunOS source address NAT flow rule name |  |

## srcport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Source port number |  |

## srcserver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv4 |  | IPv4 address of the source server in a DHCP connection |  |

## srczone
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Source zone, when direction is known and/or relevant, typically reserved for network or firewall events specifying a logical zone within the event |  |

## ssdeep
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | ssdeep fuzzy hash |  |

## ssid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Service identifier that uniquely names a wireless local area network (WLAN). Sometimes referred as a "network name" |  |

## ssl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, flag the connection if it was seen over ssl |  |

## starttime
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | date/time that something first started, typically referring to connection events or events with a definitive start and end |  |

## starttimeutc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | UTC date/time that something first started, typically referring to connection events or events with a definitive start and end |  |

## static_indicators
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the static indicators |  |

## stationid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific station identifier |  |

## status
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The present status of something (on/off, enabled/disabled, 'File Format Error', etc) NOT to be confused with result. |  |

## status_changed_at_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | The date/time when the status of something changed |  |

## statuscode
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Numerical representation of a status, typically used in network protocols like http status code 200,302,400's, etc. |  |

## statusmsg
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Status message, from Bro http log status_message field contains the status message returned by the server. |  |

## strings
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In Satori logs, the strings field |  |

## stringval
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Value of any arbitrary string of interest for parsing, typically reserved when the string is the "payload" of interest |  |

## subfiletype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In Satori logs, the subfile type |  |

## subject
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | uri | subject, with respect to communications. Typically used in email, IM, etc. |  |

## submit_to_satori_at_time
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | In HIP events, the date/time when it was submitted to satori |  |

## submitted_by
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the event was submitted by  |  |

## submitted_by_name
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the field for submitted by name |  |

## submittedAt
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | The date/time when something is submitted |  |

## subsystem
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a sub-system, see also system |  |

## subtype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | HX event subtypes |  |

## suppressfor
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | In Bro notice logs, the suppress_for field can be set if there is a natural suppression interval for the notice that may be different than the default value. |  |

## system
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a system, or overarching platform, eg. "e-commerce", or "payroll", not to be used as hostname |  |

## tags
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Tags, found in Bro http logs, identify a set of indicators of various attributes discovered and related to a particular request/response pair. |  |

## target
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The user or service/object that the action was performed on |  |

## targetdomain
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | domain | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targethost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targetip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targetipv6
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| ipv6 |  | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targetlogonid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targetusername
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## targetusersecurityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Typically oberved in host IDS/IPS, AV, and others when referencing a targeted system or user |  |

## task
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any task name, typically found in windows event logs as task |  |

## technique
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing technique |  |

## threadid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific thread identifier |  |

## threat
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Threat name or description |  |

## threshold
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | General purpose field for representing any type of interger based threshold |  |

## timedout
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | In Bro logs, whether the file analysis timed out at least once for the file. |  |

## timezone
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Timezone, typically expressed in either an offset, e.g. -0500 or in a three letter timezone code, e.g. EST, GMT, etc |  |

## to
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | email | General purpose field for representing to, with respect to origin. Typically used in email, IM, etc. |  |

## total_bytes
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, total number of bytes that are supposed to comprise the full file |  |

## totalanswers
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | The total number of resource records in a (DNS) reply message’s answer section. |  |

## totalpages
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Total number of pages, typically referencing print or copy jobs in windows logs |  |

## totalreplies
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | The total number of resource records in a (DNS) reply message’s answer, authority, and additional sections. |  |

## track_address
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | in bro logs, track address |  |

## transactionid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific transaction identifier |  |

## transdsthost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Translated destination host |  |

## transdstip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | Translated IPv4 address of the destination |  |

## transdstport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Translated destination port number |  |

## transsrchost
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Translated source host |  |

## transsrcip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | Translated IPv4 address of the source |  |

## transsrcport
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Translated source port number |  |

## trigger_details
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the field trigger details |  |

## truncationbit
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | The Truncation bit specifies that the message was truncated. |  |

## ttl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Time to Live measured in seconds |  |

## tty
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Physical or virtual terminal being used by a user |  |

## tunnel_type
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, the type of tunnel |  |

## tunnelparents
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Tunnel parents, found in Bro conn logs, identifes a set of one or more encapsulation tunnel UID values for parent connections used over the lifetime of this inner connection. |  |

## type
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | General purpose field for interger types, such as type {1,2,3,} etc |  |

## type_details
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| object |  | Generic field to store details about specific protocol events from NX EC. |  |

## uid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | Used when a given user (i.e. joesample) also has a unique user ID or GUID (i.e. 9473), see also username |  |

## uri
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | uri | Full URI of a resource |  |

## url
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | When necessary, the full URL including domain and URI fields.  |  |

## useragent
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | User Agent of an HTTP client |  |

## usercheck
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Used to describe the rule for user checking services in Checkpoint logs and other. |  |

## usercheckid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The unique identifier for a user check record. |  |

## userchecklvl
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Defines the level of user checking set in Checkpoint logs & other |  |

## usercheckname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name of user checking service |  |

## username
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | any one specific username.  Typcially some form of identity object from an identity store. |  |

## usersecurityid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Unique, immutable identifier of a Windows user. |  |

## uses_aslr
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file supports aslr |  |

## uses_code_integrity
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file enforces code integrity checks |  |

## uses_dep
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file supports dep |  |

## uses_seh
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| boolean |  | in bro logs, true if file uses structured exception handling  |  |

## uuid
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | A universally unique identifier (UUID) is an identifier standard used in software construction |  |

## version
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | used to futher specify the version of anything with a revision level, operating systems, applications, protocols, etc. |  |

## virus
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for representing the vendor specified streetname for a virus. |  |

## vlan
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| integer |  | numerical identifier for a VLAN |  |

## vlandesc
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Description for a VLAN |  |

## vlanname
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Name used to identify a VLAN |  |

## volume
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | a volume, typically a storage volume, see also disk |  |

## vt_first_seen
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | General purpose field for date/time when virus total was first seen |  |

## vt_ratio
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | date-time | General purpose field for virus total ratio |  |

## webclient
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | User browser application within Checkpoint logs & other |  |

## webclienttype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Secondary field tied to webclient. Populates when webclient is Other. |  |

## webserver
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Web server used when an http request is processed. |  |

## webservertype
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | The webserver version when webserver field equals Other. |  |

## weight
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| number |  | General purpose field for representing weight, literal or figurative |  |

## whitelist_info
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Whitelist info, the listing like grey etc |  |

## workstation
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | hostname | workstation name, only used in cases where hostname is already used and workstation is explicitly declared |  |

## x509
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | in bro logs, information about x509 certificates |  |

## xfwdforip
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string | ipv4 | X-Forwarded-For header value, comma+space delimited if more than one |  |

## yara_hits
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | In HIP events, the description of yara hits |  |

## year
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | General purpose field for year values |  |

## zone
| Data Type | Data Format | Description | Example Fields of Similarity |
|---|---|---|---|
| string |  | Any DNS zone when it can't be converted to a readable domain |  |
