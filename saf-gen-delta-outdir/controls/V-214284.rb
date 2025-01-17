control 'V-214284' do
  title 'Users and scripts running on behalf of users must be contained to the
document root or home directory tree of the Apache web server.'
  desc "A web server is designed to deliver content and execute scripts or
applications on the request of a client or user. Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted
application directory tree through access to the user's home directory,
symbolic links or shortcuts, or through search paths for missing files."
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify there is a single "Require" directive with the value of "all denied". 
 
Verify there are no "Allow" or "Deny" directives in the root <Directory> element. 
 
The following may be useful in extracting root directory elements from the Apache configuration for auditing: 
 
# perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' $APACHE_PREFIX/conf/httpd.conf  
 
If there are "Allow" or "Deny" directives in the root <Directory> element, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
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
 
Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag gid: 'V-214284'
  tag rid: 'SV-214284r881481_rule'
  tag stig_id: 'AS24-U2-000350'
  tag fix_id: 'F-15495r881480_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  config_path = input('config_path')
  httpd = apache_conf(config_path)
  root_directory = []
  root_directory.push(command("grep -n '^<Directory />' #{httpd}").stdout.strip)
  root_directory.push(command("grep -n -m1 '^</Directory>' #{httpd}").stdout.strip)

  line_numbers = root_directory ? root_directory.map { |tag| tag.split(':')[0] } : nil

  chunk = command("sed -n '#{line_numbers[0]},#{line_numbers[1]}p' #{httpd}").stdout

  describe chunk do
    it { should include 'Require all denied' }
    it { should_not cmp /Allow / }
    it { should_not cmp /Deny / }
  end
end
