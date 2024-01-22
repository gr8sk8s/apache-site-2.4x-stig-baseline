control 'V-214287' do
  title 'Only authenticated system administrators or the designated PKI Sponsor
for the Apache web server must have access to the Apache web servers private
key.'
  desc "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the SSL traffic between a client and the web
server."
  desc 'check', 'Verify the "ssl module" module is loaded
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

If the correct permissions are not set or if the private key is accessible by unauthenticated or unauthorized users, this is a finding.'
  desc 'fix', %q(Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLCertificateKeyFile location.
# cat <path to file>/ssl.conf | grep -i SSLCertificateKeyFile
Output: SSLCertificateKeyFile /etc/pki/tls/private/localhost.key

Based on the " SSLCertificateKeyFile" directive path, configure the Apache web server to ensure only authenticated and authorized users can access the web server's private key.  

Permissions must be 600 or more restrictive.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag gid: 'V-214287'
  tag rid: 'SV-214287r881490_rule'
  tag stig_id: 'AS24-U2-000390'
  tag fix_id: 'F-15498r881489_fix'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)', 'IA-5 (2) (a) (1)']

  config_path = input('config_path')
  ssl_module = command('httpd -M | grep -i ssl_module').stdout

  describe ssl_module do
    it { should include 'ssl_module' }
  end

  describe SSLCertificateFile
  describe apache_conf(config_path) do
    its('SSLCertificateFile') { should_not be_nil }
  end

  unless apache_conf(config_path).SSLCertificateFile.nil?
    apache_conf(config_path).SSLCertificateFile.each do |value|
      describe 'SSLCertificateFile path should only be accessible by authorized users' do
        subject { file(value) }
        its('owner') { should be_in input('server_admins') }
        its('group') { should be_in input('server_admin_groups') }
        its('mode') { should cmp '0400' }
      end
    end
  end
end
