## Automatic Update:  -> 

### New Controls:

### Updated Control IDs:
<details>
  <summary>Click to expand.</summary>
  
 -  V-92761 -> V-214277
 -  V-92763 -> V-214278
 -  V-92769 -> V-214279
 -  V-92771 -> V-214280
 -  V-92773 -> V-214281
 -  V-92775 -> V-214282
 -  V-92777 -> V-214283
 -  V-92779 -> V-214284
 -  V-92781 -> V-214285
 -  V-92785 -> V-214286
 -  V-92787 -> V-214287
 -  V-92795 -> V-214288
 -  V-92797 -> V-214289
 -  V-92799 -> V-214290
 -  V-92801 -> V-214291
 -  V-92803 -> V-214292
 -  V-92805 -> V-214293
 -  V-92807 -> V-214294
 -  V-92809 -> V-214295
 -  V-92811 -> V-214296
 -  V-92815 -> V-214297
 -  V-92817 -> V-214298
 -  V-92819 -> V-214299
 -  V-92821 -> V-214300
 -  V-92831 -> V-214301
 -  V-92835 -> V-214303
 -  V-92843 -> V-214304
</details>

### Updated Check/Fixes:
#### Checks:
<details open>
  <summary>Click to expand.</summary>
V-214278:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the directive "SSLProtocol" in the "httpd.conf" file:

    # cat /<path_to_file>/httpd.conf | grep -i "SSLProtocol"

    If the "SSLProtocol" directive is missing or does not look like the
following, this is a finding:

    SSLProtocol -ALL +TLSv1.2

    If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52
Rev 2, or if non-FIPS-approved algorithms are enabled, this is a finding.

    NOTE: In some cases, web servers are configured in an environment to
support load balancing. This configuration most likely uses a content switch to
control traffic to the various web servers. In this situation, the TLS
certificate for the websites may be installed on the content switch versus the
individual websites. This solution is acceptable as long as the web servers are
isolated from the general population LAN. Users should not have the ability to
bypass the content switch to access the websites.

```

Updated:
```
Verify the "ssl module" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared)
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLProtocol
# cat /<path_to_file>/ssl.conf | grep -i "SSLProtocol" 
Output: SSLProtocol -ALL +TLSv1.2
 
If the "SSLProtocol" directive is missing or does not look like the following, this is a finding: 
 
SSLProtocol -ALL +TLSv1.2 
 
If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52 Rev 2, or if non-FIPS-approved algorithms are enabled, this is a finding. 
 
Note: In some cases, web servers are configured in an environment to support load balancing. This configuration most likely uses a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the websites may be installed on the content switch versus the individual websites. This solution is acceptable as long as the web servers are isolated from the general population LAN. Users should not have the ability to bypass the content switch to access the websites.

```
---
V-214279:
Old: 
```
In a command line, run "httpd -M | grep -i log_config_module".

    If the "log_config_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the directive "LogFormat" in the httpd.conf file:

    # cat /<path_to_file>/httpd.conf | grep -i "LogFormat"

    If the "LogFormat" directive is missing or does not look like the
following, this is a finding:

    LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common

```

Updated:
```
In a command line, run "httpd -M | grep -i log_config_module".  
 
If the "log_config_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Search for the directive "LogFormat" in the httpd.conf file: 
 
# cat /<path_to_file>/httpd.conf | grep -i "LogFormat" 
 
If the "LogFormat" directive is missing or does not look like the following, this is a finding: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common

```
---
V-214281:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    If "Action" or "AddHandler" exist and they configure .exe, .dll, .com,
.bat, or .csh, or any other shell as a viewer for documents, this is a finding.

    If this is not documented and approved by the Information System Security
Officer (ISSO), this is a finding.

```

Updated:
```
In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding. 
 
If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.

```
---
V-214282:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Review "Script", "ScriptAlias" or "ScriptAliasMatch", or
"ScriptInterpreterSource" directives.

    Go into each directory and locate "cgi-bin" files.

    If any scripts are present that are not needed for application operation,
this is a finding.

    If this is not documented and approved by the Information System Security
Officer (ISSO), this is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used.  
Review "Script", "ScriptAlias" or "ScriptAliasMatch", or "ScriptInterpreterSource" directives. 
 
Go into each directory and locate "cgi-bin" files. 
 
If any scripts are present that are not needed for application operation, this is a finding. 
 
If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.

```
---
V-214283:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    If "Action" or "AddHandler" exist and they configure .exe, .dll, .com,
.bat, or .csh, or any other shell as a viewer for documents, this is a finding.

    If this is not documented and approved by the Information System Security
Officer (ISSO), this is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding. 
 
If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.

```
---
V-214284:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Verify there is a single "Require" directive with the value of "all
denied".

    Verify there are no "Allow" or "Deny" directives in the root
<Directory> element.

    The following may be useful in extracting root directory elements from the
Apache configuration for auditing:

    # perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i'
$APACHE_PREFIX/conf/httpd.conf

    If there are "Allow" or "Deny" directives in the root <Directory>
element, this is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify there is a single "Require" directive with the value of "all denied". 
 
Verify there are no "Allow" or "Deny" directives in the root <Directory> element. 
 
The following may be useful in extracting root directory elements from the Apache configuration for auditing: 
 
# perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' $APACHE_PREFIX/conf/httpd.conf  
 
If there are "Allow" or "Deny" directives in the root <Directory> element, this is a finding.

```
---
V-214285:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Verify that for each "VirtualHost" directive, there is an IP address and
port.

    If there is not, this is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify that for each "VirtualHost" directive, there is an IP address and port. 
 
If there is not, this is a finding.

```
---
V-214286:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf"
file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"

    Review <'HTTPD_ROOT'>/conf.d/ssl.conf

    Verify "SSLVerifyClient" is set to "require":

    SSLVerifyClient require

    Verify "SSLVerifyDepth" is set to a number greater than "0":

    SSLVerifyDepth 1

    If "SSLVerifyClient" is not set to "require" or "SSLVerifyDepth" is
not set to a number greater than "0", this is a finding.

```

Updated:
```
In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
 
Review <'HTTPD_ROOT'>/conf.d/ssl.conf 
 
Verify "SSLVerifyClient" is set to "require": 
  
SSLVerifyClient require 
  
Verify "SSLVerifyDepth" is set to a number greater than "0": 
  
SSLVerifyDepth 1 
  
If "SSLVerifyClient" is not set to "require" or "SSLVerifyDepth" is not set to a number greater than "0", this is a finding.

```
---
V-214287:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Review the private key path in the "SSLCertificateFile" directive. Verify
only authenticated system administrators and the designated PKI Sponsor for the
web server can access the web server private key.

    If the private key is accessible by unauthenticated or unauthorized users,
this is a finding.

```

Updated:
```
Verify the "ssl module" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not enabled, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLCertificateKeyFile location.
# cat <path to file>/ssl.conf | grep -i SSLCertificateKeyFile
Output: SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

Identify the correct permission set and owner/group of the certificate key file.
# ls -laH /etc/pki/tls/private/localhost.key
Output: -rw-------. 1 root root 1675 Sep 10  2020 /etc/pki/tls/private/localhost.key

The permission set must be 600 or more restrictive and the owner/group of the key file must be accessible to only authenticated system administrator and the designated PKI Sponsor.

If the correct permissions are not set or if the private key is accessible by unauthenticated or unauthorized users, this is a finding.

```
---
V-214288:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the "Header" directive:

    # cat /<path_to_file>/httpd.conf | grep -i "Header"

    If "HttpOnly" "secure" is not configured, this is a finding.

    "Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure"

    Review the code. If, when creating cookies, the following is not occurring,
this is a finding:

    function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path =
/; secure"; }

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Header" directive:

# cat /<path_to_file>/httpd.conf | grep -i "Header"
 
If "HttpOnly" "secure" is not configured, this is a finding. 
 
"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure" 
 
Review the code. If, when creating cookies, the following is not occurring, this is a finding: 
 
function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }

```
---
V-214291:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Verify that the "Timeout" directive is specified to have a value of
"10" seconds or less.

    # cat /<path_to_file>/httpd.conf | grep -i "Timeout"

    If the "Timeout" directive is not configured or is set for more than
"10" seconds, this is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Verify that the "Timeout" directive is specified to have a value of "10" seconds or less.

# cat /<path_to_file>/httpd.conf | grep -i "Timeout"

If the "Timeout" directive is not configured or is set for more than "10" seconds, this is a finding.

```
---
V-214293:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not enabled, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    If the "ErrorDocument" directive is not being used, this is a finding.

```

Updated:
```
In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If the "ErrorDocument" directive is not being used, this is a finding.

```
---
V-214294:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    For any enabled "TraceEnable" directives, verify they are part of the
server-level configuration (i.e., not nested in a "Directory" or "Location"
directive).

    Also verify that the "TraceEnable" directive is set to "Off".

    If the "TraceEnable" directive is not part of the server-level
configuration and/or is not set to "Off", this is a finding.

    If the directive does not exist in the "conf" file, this is a finding
because the default value is "On".

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
For any enabled "TraceEnable" directives, verify they are part of the server-level configuration (i.e., not nested in a "Directory" or "Location" directive). 
 
Also verify that the "TraceEnable" directive is set to "Off". 
 
If the "TraceEnable" directive is not part of the server-level configuration and/or is not set to "Off", this is a finding. 
 
If the directive does not exist in the "conf" file, this is a finding because the default value is "On".

```
---
V-214295:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Verify the "SessionMaxAge" directive exists and is set to "600".

    If the "SessionMaxAge" directive does not exist, this is a finding.

    If the "SessionMaxAge" directive exists but is not set to "600", this
is a finding.

```

Updated:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify the "SessionMaxAge" directive exists and is set to "600". 
 
If the "SessionMaxAge" directive does not exist or is commented out, this is a finding. 
 
If the "SessionMaxAge" directive exists but is not set to "600", this is a finding.

```
---
V-214297:
Old: 
```
If external controls such as host-based firewalls are used to restrict this
access, this check is Not Applicable.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the "RequireAll" directive:

    # cat /<path_to_file>/httpd.conf | grep -i "RequireAll"

    If "RequireAll" is not configured or IP ranges configured to allow are
not restrictive enough to prevent connections from nonsecure zones, this is a
finding.

```

Updated:
```
If external controls such as host-based firewalls are used to restrict this access, this check is Not Applicable.

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "RequireAll" directive:

# cat /<path_to_file>/httpd.conf | grep -i "RequireAll"

If "RequireAll" is not configured or IP ranges configured to allow are not restrictive enough to prevent connections from nonsecure zones, this is a finding.

```
---
V-214300:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If the "ssl_module" is not found, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the "SSLCACertificateFile" directive:

    # cat /<path_to_file>/httpd.conf | grep -i "SSLCACertificateFile"

    Review the path of the "SSLCACertificateFile" directive.

    Review the contents of <'path of SSLCACertificateFile'>\ca-bundle.crt.

    Examine the contents of this file to determine if the trusted CAs are DoD
approved.

    If the trusted CA that is used to authenticate users to the website does
not lead to an approved DoD CA, this is a finding.

    NOTE: There are non-DoD roots that must be on the server for it to
function. Some applications, such as antivirus programs, require root CAs to
function. DoD-approved certificate can include the External Certificate
Authorities (ECA) if approved by the AO. The PKE InstallRoot 3.06 System
Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD,
ECA, and IECA CAs.

```

Updated:
```
Verify the “ssl module” module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not found, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the 
# cat /etc/httpd/conf.d/ssl.conf | grep -i "SSLCACertificateFile"
Output should be similar to: SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of SSLCACertificateFile'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DoD-approved certificate can include the External Certificate Authorities (ECA) if approved by the AO. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.

```
---
V-214301:
Old: 
```
In a command line, run "httpd -M | grep -i ssl_module".

    If "ssl_module" is not listed, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    If the "SSLCompression" directive does not exist or is set to "on",
this is a finding.

```

Updated:
```
In a command line, run "httpd -M | grep -i ssl_module". 
 
If "ssl_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If the "SSLCompression" directive does not exist or is set to "on", this is a finding.

```
---
V-214303:
Old: 
```
In a command line, run "httpd -M | grep -i session_cookie_module".

    If "session_cookie_module" is not listed, this is a finding.

    Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Search for the "Session" and "SessionCookieName" directives:

    # cat /<path_to_file>/httpd.conf | grep -i "Session"
    # cat /<path_to_file>/httpd.conf | grep -i "SessionCookieName"

    If "Session" is not "on" and "SessionCookieName" does not contain
"httpOnly" and "secure", this is a finding.

```

Updated:
```
In a command line, run "httpd -M | grep -i session_cookie_module". 
 
If "session_cookie_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Session" and "SessionCookieName" directives:

# cat /<path_to_file>/httpd.conf | grep -i "Session"
# cat /<path_to_file>/httpd.conf | grep -i "SessionCookieName"

If "Session" is not "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.

```
---
</details>

#### Fixes:
<details open>
  <summary>Click to expand.</summary>
V-214278:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Ensure the "SSLProtocol" is added and looks like the following:

    SSLProtocol -ALL +TLSv1.2

    Restart Apache: apachectl restart

```
New:
```
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf
 
Ensure the "SSLProtocol" is added to ssl.conf and looks like the following: 
 
SSLProtocol -ALL +TLSv1.2 
 
Restart Apache: apachectl restart

```
---
V-214279:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Uncomment the "log_config_module" module line.

    Configure the "LogFormat" in the "httpd.conf" file to look like the
following:

    LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common

    Restart Apache: apachectl restart

    NOTE: Your log format may be using different variables based on your
environment, however  it should be verified to be producing the same end result
of logged elements.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Uncomment the "log_config_module" module line. 
 
Configure the "LogFormat" in the "httpd.conf" file to look like the following: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common 
 
Restart Apache: apachectl restart

Note: The log format may be using different variables based on the environment; however, it should be verified to ensure it is producing the same end result of logged elements.

```
---
V-214281:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.

    If "Action" or "AddHandler" exist and they configure any of the
following (.exe, .dll, .com, .bat, or .csh), remove those references.

    Restart Apache: apachectl restart

    Ensure this process is documented and approved by the ISSO.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Disable MIME types for .exe, .dll, .com, .bat, and .csh programs. 
 
If "Action" or "AddHandler" exist and they configure any of the following (.exe, .dll, .com, .bat, or .csh), remove those references. 
 
Restart Apache: apachectl restart 
 
Ensure this process is documented and approved by the ISSO.

```
---
V-214282:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Remove any scripts in "cgi-bin" directory if they are not needed for
application operation.

    Ensure this process is documented and approved by the ISSO.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Remove any scripts in "cgi-bin" directory if they are not needed for application operation. 
 
Ensure this process is documented and approved by the ISSO.

```
---
V-214283:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.

    If "Action" or "AddHandler" exist and they configure .exe, .dll, .com,
.bat, or .csh, remove those references.

    Restart Apache: apachectl restart

    Ensure this process is documented and approved by the ISSO.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Disable MIME types for .exe, .dll, .com, .bat, and .csh programs. 
 
If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, remove those references. 
 
Restart Apache: apachectl restart 
 
Ensure this process is documented and approved by the ISSO.

```
---
V-214284:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Set the root directory directive as follows:

    <Directory>
    ...
    Require all denied
    ...
    </Directory>

    Remove any "Deny" and "Allow" directives from the root <Directory>
element.

    Restart Apache: apachectl restart

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set the root directory directive as follows: 
 
<Directory> 
... 
Require all denied 
... 
</Directory> 
 
Remove any "Deny" and "Allow" directives from the root <Directory> element. 
 
Restart Apache: apachectl restart

```
---
V-214285:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Set each "VirtualHost" directive to listen to on a specific IP address
and port.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set each "VirtualHost" directive to listen to on a specific IP address and port.

```
---
V-214286:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf"
file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"

    Edit <'HTTPD_ROOT'>/conf.d/ssl.conf

    Set "SSLVerifyClient" to "require".

    Set "SSLVerifyDepth" to "1".

    SSLVerifyDepth 1

    For more information:
https://httpd.apache.org/docs/current/mod/ssl_module.html

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
 
Edit <'HTTPD_ROOT'>/conf.d/ssl.conf 
  
Set "SSLVerifyClient" to "require".  
  
Set "SSLVerifyDepth" to "1". 
  
SSLVerifyDepth 1 
  
For more information: https://httpd.apache.org/docs/current/mod/ssl_module.html

```
---
V-214287:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Based on the "SSLCertificateFile" directive path, configure the Apache
web server to ensure only authenticated and authorized users can access the web
server's private key.

```
New:
```
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLCertificateKeyFile location.
# cat <path to file>/ssl.conf | grep -i SSLCertificateKeyFile
Output: SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

Based on the " SSLCertificateKeyFile" directive path, configure the Apache web server to ensure only authenticated and authorized users can access the web server's private key.  

Permissions must be 600 or more restrictive.

```
---
V-214288:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Add or configure the following line:

    "Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure"

    Add the "secure" attribute to the JavaScript set cookie in any
application code:

    function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path =
/; secure"; }

    HttpOnly cannot be used since by definition this is a cookie set by
JavaScript.

    Restart www_server and Apache.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or configure the following line: 
 
"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure" 
 
Add the "secure" attribute to the JavaScript set cookie in any application code: 
 
function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }  

HttpOnly cannot be used since by definition this is a cookie set by JavaScript. 
 
Restart www_server and Apache.

```
---
V-214291:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Add or modify the "Timeout" directive in the Apache configuration to have
a value of "10" seconds or less.

    "Timeout 10"

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or modify the "Timeout" directive in the Apache configuration to have a value of "10" seconds or less. 
 
"Timeout 10"

```
---
V-214292:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Add a default document to the applicable directories.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add a default document to the applicable directories.

```
---
V-214293:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Use the "ErrorDocument" directive to enable custom error pages.

    ErrorDocument 500 "Sorry, our script crashed. Oh dear"
    ErrorDocument 500 /cgi-bin/crash-recover
    ErrorDocument 500 http://error.example.com/server_error.html
    ErrorDocument 404 /errors/not_found.html
    ErrorDocument 401 /subscription/how_to_subscribe.html

    The syntax of the ErrorDocument directive is:

    ErrorDocument <3-digit-code> <action>

    Additional Information:

    https://httpd.apache.org/docs/2.4/custom-error.html

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Use the "ErrorDocument" directive to enable custom error pages. 
 
ErrorDocument 500 "Sorry, our script crashed. Oh dear" 
ErrorDocument 500 /cgi-bin/crash-recover 
ErrorDocument 500 http://error.example.com/server_error.html 
ErrorDocument 404 /errors/not_found.html 
ErrorDocument 401 /subscription/how_to_subscribe.html 
 
The syntax of the ErrorDocument directive is: 
 
ErrorDocument <3-digit-code> <action> 
 
Additional Information: 

https://httpd.apache.org/docs/2.4/custom-error.html

```
---
V-214294:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Add or set the value of "TraceEnable" to "Off".

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or set the value of "TraceEnable" to "Off".

```
---
V-214295:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Add or set the "SessionMaxAge" directive to "600".

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or set the "SessionMaxAge" directive to "600".

```
---
V-214296:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Load the "Reqtimeout_module".

    Set the "RequestReadTimeout" directive.

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Load the "Reqtimeout_module". 
 
Set the "RequestReadTimeout" directive.

```
---
V-214301:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Ensure the "SSLCompression" is added and looks like the following:

    SSLCompression off

    Restart Apache: apachectl restart

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Ensure the "SSLCompression" is added and looks like the following: 
 
SSLCompression off 
 
Restart Apache: apachectl restart

```
---
V-214303:
Old: 
```
Determine the location of the "HTTPD_ROOT" directory and the
"httpd.conf" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT="/etc/httpd"
    -D SERVER_CONFIG_FILE="conf/httpd.conf"

    Set "Session" to "on".

    Ensure the "SessionCookieName" directive includes "httpOnly" and
"secure".

```
New:
```
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set "Session" to "on". 
 
Ensure the "SessionCookieName" directive includes "httpOnly" and "secure".

```
---
</details>

### Updated Impacts
<details open>
  <summary>Click to expand.</summary>
</details>

### Updated Titles
<details>
  <summary>Click to expand.</summary>
V-214278:
Old: The Apache web server must use encryption strength in accordance with
the categorization of data hosted by the Apache web server when remote
connections are provided.
New: The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.
---
V-214279:
Old: The Apache web server must produce log records containing sufficient
information to establish what type of events occurred.
New: The Apache web server must produce log records containing sufficient information to establish what type of events occurred.
---
V-214280:
Old: The Apache web server must not perform user management for hosted
applications.
New: The Apache web server must not perform user management for hosted applications.
---
V-214281:
Old: The Apache web server must have Multipurpose Internet Mail Extensions
(MIME) that invoke operating system shell programs disabled.
New: The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.
---
V-214282:
Old: The Apache web server must allow mappings to unused and vulnerable
scripts to be removed.
New: The Apache web server must allow mappings to unused and vulnerable scripts to be removed.
---
V-214283:
Old: The Apache web server must have resource mappings set to disable the
serving of certain file types.
New: The Apache web server must have resource mappings set to disable the serving of certain file types.
---
V-214284:
Old: Users and scripts running on behalf of users must be contained to the
document root or home directory tree of the Apache web server.
New: Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.
---
V-214285:
Old: The Apache web server must be configured to use a specified IP address
and port.
New: The Apache web server must be configured to use a specified IP address and port.
---
V-214286:
Old: The Apache web server must perform RFC 5280-compliant certification
path validation.
New: The Apache web server must perform RFC 5280-compliant certification path validation.
---
V-214287:
Old: Only authenticated system administrators or the designated PKI Sponsor
for the Apache web server must have access to the Apache web servers private
key.
New: Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.
---
V-214288:
Old: Cookies exchanged between the Apache web server and client, such as
session cookies, must have security settings that disallow cookie access
outside the originating Apache web server and hosted application.
New: Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.
---
V-214289:
Old: The Apache web server must augment re-creation to a stable and known
baseline.
New: The Apache web server must augment re-creation to a stable and known baseline.
---
V-214290:
Old: The Apache web server document directory must be in a separate
partition from the Apache web servers system files.
New: The Apache web server document directory must be in a separate partition from the Apache web servers system files.
---
V-214291:
Old: The Apache web server must be tuned to handle the operational
requirements of the hosted application.
New: The Apache web server must be tuned to handle the operational requirements of the hosted application.
---
V-214292:
Old: The Apache web server must display a default hosted application web
page, not a directory listing, when a requested web page cannot be found.
New: The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.
---
V-214293:
Old: Warning and error messages displayed to clients must be modified to
minimize the identity of the Apache web server, patches, loaded modules, and
directory paths.
New: Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.
---
V-214294:
Old: Debugging and trace information used to diagnose the Apache web server
must be disabled.
New: Debugging and trace information used to diagnose the Apache web server must be disabled.
---
V-214297:
Old: The Apache web server must restrict inbound connections from nonsecure
zones.
New: The Apache web server must restrict inbound connections from nonsecure zones.
---
V-214298:
Old: Non-privileged accounts on the hosting system must only access Apache
web server security-relevant information and functions through a distinct
administrative account.
New: Non-privileged accounts on the hosting system must only access Apache web server security-relevant information and functions through a distinct administrative account.
---
V-214299:
Old: The Apache web server application, libraries, and configuration files
must only be accessible to privileged users.
New: The Apache web server application, libraries, and configuration files must only be accessible to privileged users.
---
V-214300:
Old: The Apache web server must only accept client certificates issued by
DoD PKI or DoD-approved PKI Certification Authorities (CAs).
New: The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
---
V-214301:
Old: The Apache web server cookies, such as session cookies, sent to the
client using SSL&#x2F;TLS must not be compressed.
New: The Apache web server cookies, such as session cookies, sent to the client using SSL&#x2F;TLS must not be compressed.
---
V-214303:
Old: Cookies exchanged between the Apache web server and the client, such
as session cookies, must have cookie properties set to force the encryption of
cookies.
New: Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.
---
V-214304:
Old: The Apache web server must be configured in accordance with the
security configuration settings based on DoD security configuration or
implementation guidance, including STIGs, NSA configuration guides, CTOs, and
DTMs.
New: The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
---
</details>

### Updated Descriptions
<details>
  <summary>Click to expand.</summary>
V-214277:
Old:
```
Session management is the practice of protecting the bulk of the user
authorization and identity information. This data can be stored on the client
system or on the server.

    When the session information is stored on the client, the session ID, along
with the user authorization and identity information, is sent along with each
client request and is stored in a cookie, embedded in the uniform resource
locator (URL), or placed in a hidden field on the displayed form. Each of these
offers advantages and disadvantages. The biggest disadvantage to all three is
the possibility of the hijacking of a session along with all of the user's
credentials.

    When the user authorization and identity information is stored on the
server in a protected and encrypted database, the communication between the
client and Apache web server will only send the session identifier, and the
server can then retrieve user credentials for the session when needed. If,
during transmission, the session were to be hijacked, the user's credentials
would not be compromised.

```
New:
```
Session management is the practice of protecting the bulk of the user authorization and identity information. This data can be stored on the client system or on the server. 
 
When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the possibility of the hijacking of a session along with all of the user's credentials. 
 
When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and Apache web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised.

```
---
V-214278:
Old:
```
The Apache web server has several remote communications channels.
Examples are user requests via http/https, communication to a backend database,
and communication to authenticate users. The encryption used to communicate
must match the data that is being retrieved or presented.

    Methods of communication are "http" for publicly displayed information,
"https" to encrypt when user data is being transmitted, VPN tunneling, or
other encryption methods to a database.

```
New:
```
The Apache web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, and communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented. 
 
Methods of communication are "http" for publicly displayed information, "https" to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.



```
---
V-214279:
Old:
```
Apache web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct type of event that occurred is important during
forensic analysis. The correct determination of the event and when it occurred
is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event
occurred, investigation into the cause of event is severely hindered. Log
record content that may be necessary to satisfy the requirement of this control
includes but is not limited to time stamps, source and destination IP
addresses, user/process identifiers, event descriptions, application-specific
events, success/fail indications, file names involved, access control, and flow
control rules invoked.

```
New:
```
Apache web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 
 
Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 
 
Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes but is not limited to time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, and flow control rules invoked.

```
---
V-214280:
Old:
```
User management and authentication can be an essential part of any
application hosted by the web server. Along with authenticating users, the user
management function must perform several other tasks such as password
complexity, locking users after a configurable number of failed logons, and
management of temporary and emergency accounts. All of this must be done
enterprise-wide.

    The web server contains a minimal user management function, but the web
server user management function does not offer enterprise-wide user management,
and user management is not the primary function of the web server. User
management for the hosted applications should be done through a facility that
is built for enterprise-wide user management, like LDAP and Active Directory.

```
New:
```
User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts. All of this must be done enterprise-wide. 
 
The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.

```
---
V-214281:
Old:
```
Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type.

    A shell is a program that serves as the basic interface between the user
and the operating system, so hosted application users must not have access to
these programs. Shell programs may execute shell escapes and can then perform
unauthorized activities that could damage the security posture of the web
server.

```
New:
```
Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner. 
 
A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. 
 
A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server.

```
---
V-214282:
Old:
```
Scripts allow server-side processing on behalf of the hosted
application user or as processes needed in the implementation of hosted
applications. Removing scripts not needed for application operation or deemed
vulnerable helps to secure the web server.

    To ensure scripts are not added to the web server and run maliciously,
script mappings that are not needed or used by the web server for hosted
application operation must be removed.

```
New:
```
Scripts allow server-side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 
 
To ensure scripts are not added to the web server and run maliciously, script mappings that are not needed or used by the web server for hosted application operation must be removed.

```
---
V-214283:
Old:
```
Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and cannot be served to a user, the web
server could deliver to a user web server configuration files, log files,
password files, etc.

    The web server must only allow hosted application file types to be served
to a user, and all other types must be disabled.

```
New:
```
Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client. 
 
By not specifying which files can and cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 
 
The web server must only allow hosted application file types to be served to a user, and all other types must be disabled.

```
---
V-214284:
Old:
```
A web server is designed to deliver content and execute scripts or
applications on the request of a client or user. Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted
application directory tree through access to the user's home directory,
symbolic links or shortcuts, or through search paths for missing files.

```
New:
```
A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm. 
 
The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files.

```
---
V-214285:
Old:
```
The web server must be configured to listen on a specified IP address
and port. Without specifying an IP address and port for the web server to use,
the web server will listen on all IP addresses available to the hosting server.
If the web server has multiple IP addresses, i.e., a management IP address, the
web server will also accept connections on the management IP address.

    Accessing the hosted application through an IP address normally used for
non-application functions opens the possibility of user access to resources,
utilities, files, ports, and protocols that are protected on the desired
application IP address.

```
New:
```
The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to use, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address. 
 
Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.

```
---
V-214286:
Old:
```
A certificate's certification path is the path from the end entity
certificate to a trusted root certification authority (CA). Certification path
validation is necessary for a relying party to make an informed decision
regarding acceptance of an end entity certificate. Certification path
validation includes checks such as certificate issuer trust, time validity, and
revocation status for each certificate in the certification path. Revocation
status information for CA and subject certificates in a certification path is
commonly provided via certificate revocation lists (CRLs) or online certificate
status protocol (OCSP) responses.

```
New:
```
A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

```
---
V-214287:
Old:
```
The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the SSL traffic between a client and the web
server.

```
New:
```
The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. 
 
By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.

```
---
V-214288:
Old:
```
Cookies are used to exchange data between the web server and the
client. Cookies, such as a session cookie, may contain session information and
user credentials used to maintain a persistent connection between the user and
the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path
parameters), cookies can be shared within hosted applications residing on the
same web server or to applications hosted on different web servers residing on
the same domain.

```
New:
```
Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol. 
 
When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.

```
---
V-214289:
Old:
```
Making certain that the web server has not been updated by an
unauthorized user is always a concern. Adding patches, functions, and modules
that are untested and not part of the baseline opens the possibility for
security risks. The web server must offer, and not hinder, a method that allows
for the quick and easy reinstallation of a verified and patched baseline to
guarantee the production web server is up-to-date and has not been modified to
add functionality or expose security risks.

    When the web server does not offer a method to roll back to a clean
baseline, external methods, such as a baseline snapshot or virtualizing the web
server, can be used.

```
New:
```
Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks. 
 
When the web server does not offer a method to roll back to a clean baseline, external methods, such as a baseline snapshot or virtualizing the web server, can be used.

```
---
V-214290:
Old:
```
A web server is used to deliver content on the request of a client.
The content delivered to a client must be controlled, allowing only hosted
application files to be accessed and delivered. To allow a client access to
system files of any type is a major security risk that is entirely avoidable.
Obtaining such access is the goal of directory traversal and URL manipulation
vulnerabilities. To facilitate such access by misconfiguring the web document
(home) directory is a serious error. In addition, having the path on the same
drive as the system folder compounds potential attacks such as drive space
exhaustion.

```
New:
```
A web server is used to deliver content on the request of a client. The content delivered to a client must be controlled, allowing only hosted application files to be accessed and delivered. To allow a client access to system files of any type is a major security risk that is entirely avoidable. Obtaining such access is the goal of directory traversal and URL manipulation vulnerabilities. To facilitate such access by misconfiguring the web document (home) directory is a serious error. In addition, having the path on the same drive as the system folder compounds potential attacks such as drive space exhaustion.

```
---
V-214291:
Old:
```
A denial of service (DoS) can occur when the Apache web server is so
overwhelmed that it can no longer respond to additional requests. A web server
not properly tuned may become overwhelmed and cause a DoS condition even with
expected traffic from users. To avoid a DoS, the Apache web server must be
tuned to handle the expected traffic for the hosted applications.

```
New:
```
A denial of service (DoS) can occur when the Apache web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the Apache web server must be tuned to handle the expected traffic for the hosted applications.



```
---
V-214292:
Old:
```
The goal is to completely control the web user's experience in
navigating any portion of the web document root directories. Ensuring all web
content directories have at least the equivalent of an index.html file is a
significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being
able to obtain information about the Apache web server's directory structure by
locating directories without default pages. In the scenario, the Apache web
server will display to the user a listing of the files in the directory being
accessed. By having a default hosted application web page, the anonymous web
user will not obtain directory browsing information or an error message that
reveals the server type and version.

```
New:
```
The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. 
 
Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the Apache web server's directory structure by locating directories without default pages. In the scenario, the Apache web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.

```
---
V-214293:
Old:
```
Information needed by an attacker to begin looking for possible
vulnerabilities in an Apache web server includes any information about the
Apache web server, backend systems being accessed, and plug-ins or modules
being used.

    Apache web servers will often display error messages to client users,
displaying enough information to aid in the debugging of the error. The
information given back in error messages may display the Apache web server
type, version, patches installed, plug-ins and modules installed, type of code
being used by the hosted application, and any backends being used for data
storage.

    This information could be used by an attacker to blueprint what type of
attacks might be successful. The information given to users must be minimized
to not aid in the blueprinting of the Apache web server.

```
New:
```
Information needed by an attacker to begin looking for possible vulnerabilities in an Apache web server includes any information about the Apache web server, backend systems being accessed, and plug-ins or modules being used. 
 
Apache web servers will often display error messages to client users, displaying enough information to aid in the debugging of the error. The information given back in error messages may display the Apache web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 
 
This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the Apache web server.

```
---
V-214294:
Old:
```
Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the Apache web
server and plug-ins or modules being used. When debugging or trace information
is enabled in a production web server, information about the web server, such
as web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage, may be displayed. Since this information may be placed in
logs and general messages during normal operation of the Apache web server, an
attacker does not need to cause an error condition to gain access to this
information.

```
New:
```
Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the Apache web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage, may be displayed. Since this information may be placed in logs and general messages during normal operation of the Apache web server, an attacker does not need to cause an error condition to gain access to this information.

```
---
V-214295:
Old:
```
Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after an
absolute period of time, the user is forced to reauthenticate, guaranteeing the
session is still in use. Enabling an absolute timeout for sessions closes
sessions that are still active. Examples would be a runaway process accessing
the Apache web server or an attacker using a hijacked session to slowly probe
the Apache web server.

```
New:
```
Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to reauthenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the Apache web server or an attacker using a hijacked session to slowly probe the Apache web server.

```
---
V-214296:
Old:
```
Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the Apache web server can make certain that those
sessions that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.

```
New:
```
Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the Apache web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 
 
Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.

```
---
V-214297:
Old:
```
Remote access to the Apache web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be capable of restricting
access from what the DoD defines as nonsecure zones. Nonsecure zones are
defined as any IP, subnet, or region that is defined as a threat to the
organization. The nonsecure zones must be defined for public web servers
logically located in a DMZ, as well as private web servers with perimeter
protection devices. By restricting access from nonsecure zones, through the
internal web server access list, the Apache web server can stop or slow
denial-of-service (DoS) attacks on the web server.

```
New:
```
Remote access to the Apache web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 
 
A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through the internal web server access list, the Apache web server can stop or slow denial-of-service (DoS) attacks on the web server.

```
---
V-214298:
Old:
```
By separating Apache web server security functions from non-privileged
users, roles can be developed that can then be used to administer the Apache
web server. Forcing users to change from a non-privileged account to a
privileged account when operating on the Apache web server or on
security-relevant information forces users to only operate as a Web Server
Administrator when necessary. Operating in this manner allows for better
logging of changes and better forensic information and limits accidental
changes to the Apache web server.

```
New:
```
By separating Apache web server security functions from non-privileged users, roles can be developed that can then be used to administer the Apache web server. Forcing users to change from a non-privileged account to a privileged account when operating on the Apache web server or on security-relevant information forces users to only operate as a Web Server Administrator when necessary. Operating in this manner allows for better logging of changes and better forensic information and limits accidental changes to the Apache web server.

```
---
V-214299:
Old:
```
The Apache web server can be modified through parameter modification,
patch installation, upgrades to the Apache web server or modules, and security
parameter changes. With each of these changes, there is the potential for an
adverse effect such as a denial of service (DoS), Apache web server
instability, or hosted application instability.

    To limit changes to the Apache web server and limit exposure to any adverse
effects from the changes, files such as the Apache web server application
files, libraries, and configuration files must have permissions and ownership
set properly to only allow privileged users access.

```
New:
```
The Apache web server can be modified through parameter modification, patch installation, upgrades to the Apache web server or modules, and security parameter changes. With each of these changes, there is the potential for an adverse effect such as a denial of service (DoS), Apache web server instability, or hosted application instability. 
 
To limit changes to the Apache web server and limit exposure to any adverse effects from the changes, files such as the Apache web server application files, libraries, and configuration files must have permissions and ownership set properly to only allow privileged users access.

```
---
V-214300:
Old:
```
Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place that are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users.

```
New:
```
Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

```
---
V-214301:
Old:
```
A cookie is used when a web server needs to share data with the
client's browser. The data is often used to remember the client when the client
returns to the hosted application at a later date. A session cookie is a
special type of cookie used to remember the client during the session. The
cookie will contain the session identifier (ID) and may contain authentication
data to the hosted application. To protect this data from easily being
compromised, the cookie can be encrypted.

    When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great
deal of time and resources to decrypt the cookie. If, along with encryption,
the cookie is compressed, the attacker can now use a combination of plaintext
injection and inadvertent information leakage through data compression to
reduce the time needed to decrypt the cookie. This attack is called Compression
Ratio Info-leak Made Easy (CRIME).

    Cookies shared between the Apache web server and the client when encrypted
should not also be compressed.

```
New:
```
A cookie is used when a web server needs to share data with the client's browser. The data is often used to remember the client when the client returns to the hosted application at a later date. A session cookie is a special type of cookie used to remember the client during the session. The cookie will contain the session identifier (ID) and may contain authentication data to the hosted application. To protect this data from easily being compromised, the cookie can be encrypted. 
 
When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great deal of time and resources to decrypt the cookie. If, along with encryption, the cookie is compressed, the attacker can now use a combination of plaintext injection and inadvertent information leakage through data compression to reduce the time needed to decrypt the cookie. This attack is called Compression Ratio Info-leak Made Easy (CRIME). 
 
Cookies shared between the Apache web server and the client when encrypted should not also be compressed.

```
---
V-214303:
Old:
```
Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
but TLS/SSL is not used by every hosted application since the data being
displayed does not require the encryption of the transmission. To safeguard
against cookies, especially session cookies, being sent in plaintext, a cookie
can be encrypted before transmission. To force a cookie to be encrypted before
transmission, the cookie "Secure" property can be set.

```
New:
```
Cookies can be sent to a client using TLS/SSL to encrypt the cookies, but TLS/SSL is not used by every hosted application since the data being displayed does not require the encryption of the transmission. To safeguard against cookies, especially session cookies, being sent in plaintext, a cookie can be encrypted before transmission. To force a cookie to be encrypted before transmission, the cookie "Secure" property can be set.

```
---
V-214304:
Old:
```
Configuring the Apache web server to implement organization-wide
security implementation guides and security checklists guarantees compliance
with federal standards and establishes a common security baseline across the
DoD that reflects the most restrictive security posture consistent with
operational requirements.

    Configuration settings are the set of parameters that can be changed that
affect the security posture and/or functionality of the system.
Security-related parameters are parameters impacting the security state of the
Apache web server, including the parameters required to satisfy other security
control requirements.

```
New:
```
Configuring the Apache web server to implement organization-wide security implementation guides and security checklists guarantees compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 
 
Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the Apache web server, including the parameters required to satisfy other security control requirements.

```
---
</details>