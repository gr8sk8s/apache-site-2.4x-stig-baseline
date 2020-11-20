# encoding: UTF-8

control 'V-92807' do
  title "Debugging and trace information used to diagnose the Apache web server
must be disabled."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the Apache web
server and plug-ins or modules being used. When debugging or trace information
is enabled in a production web server, information about the web server, such
as web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage, may be displayed. Since this information may be placed in
logs and general messages during normal operation of the Apache web server, an
attacker does not need to cause an error condition to gain access to this
information."
  desc  'rationale', ''
  desc  'check', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    For any enabled \"TraceEnable\" directives, verify they are part of the
server-level configuration (i.e., not nested in a \"Directory\" or \"Location\"
directive).

    Also verify that the \"TraceEnable\" directive is set to \"Off\".

    If the \"TraceEnable\" directive is not part of the server-level
configuration and/or is not set to \"Off\", this is a finding.

    If the directive does not exist in the \"conf\" file, this is a finding
because the default value is \"On\".
  "
  desc  'fix', "
    Determine the location of the \"HTTPD_ROOT\" directory and the
\"httpd.conf\" file:

    # httpd -V | egrep -i 'httpd_root|server_config_file'
    -D HTTPD_ROOT=\"/etc/httpd\"
    -D SERVER_CONFIG_FILE=\"conf/httpd.conf\"

    Add or set the value of \"TraceEnable\" to \"Off\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-92807'
  tag rid: 'SV-102895r1_rule'
  tag stig_id: 'AS24-U2-000640'
  tag fix_id: 'F-99051r1_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

