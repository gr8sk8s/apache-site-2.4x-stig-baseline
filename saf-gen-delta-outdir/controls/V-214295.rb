control 'V-214295' do
  title 'The Apache web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after an
absolute period of time, the user is forced to reauthenticate, guaranteeing the
session is still in use. Enabling an absolute timeout for sessions closes
sessions that are still active. Examples would be a runaway process accessing
the Apache web server or an attacker using a hijacked session to slowly probe
the Apache web server.'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify the "SessionMaxAge" directive exists and is set to "600". 
 
If the "SessionMaxAge" directive does not exist or is commented out, this is a finding. 
 
If the "SessionMaxAge" directive exists but is not set to "600", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or set the "SessionMaxAge" directive to "600".)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag gid: 'V-214295'
  tag rid: 'SV-214295r881507_rule'
  tag stig_id: 'AS24-U2-000650'
  tag fix_id: 'F-15506r881506_fix'
  tag cci: ['CCI-002361', 'CCI-002391']
  tag nist: ['AC-12', 'SC-5 (3) (b)']

  config_path = input('config_path')

  describe apache_conf(config_path) do
    its('SessionMaxAge') { should_not be_nil }
  end

  unless apache_conf(config_path).SessionMaxAge.nil?
    apache_conf(config_path).SessionMaxAge.each do |value|
      describe 'SessionMaxAge value should be less than or equal to 600' do
        subject { value }
        it { should be <= 600 }
      end
    end
  end
end
