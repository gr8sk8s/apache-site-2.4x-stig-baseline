control 'V-214303' do
  title 'Cookies exchanged between the Apache web server and the client, such
as session cookies, must have cookie properties set to force the encryption of
cookies.'
  desc 'Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
but TLS/SSL is not used by every hosted application since the data being
displayed does not require the encryption of the transmission. To safeguard
against cookies, especially session cookies, being sent in plaintext, a cookie
can be encrypted before transmission. To force a cookie to be encrypted before
transmission, the cookie "Secure" property can be set.'
  desc 'check', %q(In a command line, run "httpd -M | grep -i session_cookie_module". 
 
If "session_cookie_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Session" and "SessionCookieName" directives:

# cat /<path_to_file>/httpd.conf | grep -i "Session"
# cat /<path_to_file>/httpd.conf | grep -i "SessionCookieName"

If "Session" is not "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set "Session" to "on". 
 
Ensure the "SessionCookieName" directive includes "httpOnly" and "secure".)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag gid: 'V-214303'
  tag rid: 'SV-214303r881521_rule'
  tag stig_id: 'AS24-U2-000890'
  tag fix_id: 'F-15514r881520_fix'
  tag cci: ['CCI-002418', 'CCI-002448']
  tag nist: ['SC-8', 'SC-12 (3)']

  config_path = input('config_path')
  session_cookie_module = command('http -M | grep -i session_cookie_module').stdout

  describe session_cookie_module do
    it { should include 'session_cookie_module' }
  end

  describe apache_conf(config_path) do
    its('SessionCookieName') { should_not be_nil }
  end

  unless apache_conf(config_path).SessionCookieName.nil?
    apache_conf(config_path).SessionCookieName.each do |value|
      describe 'SessionCookieName value should return httpOnly and Secure' do
        subject { value }
        it { should include 'httpOnly' }
        it { should include 'Secure' }
      end
    end
  end

  describe apache_conf(config_path) do
    its('Session') { should_not be_nil }
  end

  unless apache_conf(config_path).Session.nil?
    apache_conf(config_path).Session.each do |value|
      describe 'Session value should be set to on' do
        subject { value }
        it { should cmp 'on' }
      end
    end
  end
end
