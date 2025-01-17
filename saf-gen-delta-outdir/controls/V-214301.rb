control 'V-214301' do
  title 'The Apache web server cookies, such as session cookies, sent to the
client using SSL/TLS must not be compressed.'
  desc "A cookie is used when a web server needs to share data with the
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
should not also be compressed."
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module". 
 
If "ssl_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
If the "SSLCompression" directive does not exist or is set to "on", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Ensure the "SSLCompression" is added and looks like the following: 
 
SSLCompression off 
 
Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000153'
  tag gid: 'V-214301'
  tag rid: 'SV-214301r881516_rule'
  tag stig_id: 'AS24-U2-000870'
  tag fix_id: 'F-15512r881515_fix'
  tag cci: ['CCI-002418', 'CCI-002448']
  tag nist: ['SC-8', 'SC-12 (3)']

  config_path = input('config_path')
  ssl_module = command('httpd -M | grep -i ssl_module').stdout

  describe ssl_module do
    it { should include 'ssl_module' }
  end

  describe apache_conf(config_path) do
    its('SSLCompression') { should_not be_nil }
  end

  unless apache_conf(config_path).SSLCompression.nil?
    apache_conf(config_path).SSLCompression.each do |value|
      describe 'SSLCompression value should be set to off' do
        subject { value }
        it { should cmp 'off' }
      end
    end
  end
end
