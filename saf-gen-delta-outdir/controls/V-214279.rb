control 'V-214279' do
  title 'The Apache web server must produce log records containing sufficient
information to establish what type of events occurred.'
  desc 'Apache web server logging capability is critical for accurate forensic
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
control rules invoked.'
  desc 'check', %q(In a command line, run "httpd -M | grep -i log_config_module".  
 
If the "log_config_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Search for the directive "LogFormat" in the httpd.conf file: 
 
# cat /<path_to_file>/httpd.conf | grep -i "LogFormat" 
 
If the "LogFormat" directive is missing or does not look like the following, this is a finding: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Uncomment the "log_config_module" module line. 
 
Configure the "LogFormat" in the "httpd.conf" file to look like the following: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common 
 
Restart Apache: apachectl restart

Note: The log format may be using different variables based on the environment; however, it should be verified to ensure it is producing the same end result of logged elements.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag gid: 'V-214279'
  tag rid: 'SV-214279r881469_rule'
  tag stig_id: 'AS24-U2-000090'
  tag fix_id: 'F-15490r881468_fix'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3', 'AU-3 a']

  config_path = input('config_path')
  log_config = command('httpd -M | grep -i log_config_module').stdout

  describe log_config do
    it { should include 'log_config_module' }
  end

  describe apache_conf(config_path) do
    subject { file(config_path).content.to_s }
    it { should match /^\s*LogFormat \"%a %A %h %H %l %m %s %t %u %U \\\"%{Referer}i\\\" \" common/ }
  end
end
