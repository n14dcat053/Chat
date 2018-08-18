require 'socket'
require 'securerandom'

class CreateCertificate
	include GladeGUI

	def initialize(server)
    # init  
		@window1 = "Create Certificate"
    @csr = OpenSSL::X509::Request.new
    @server = server
    
    # random string hex
    @pass = SecureRandom.hex
     # Public key of the server CA
    @public_key_ca = nil 
    #Private key of the client
    @private_key = nil
    #Public key of the client
     @public_key = nil 
     Dir.exist?('Certificate') ? nil : Dir.mkdir('Certificate')
     Dir.exist?('PublicKeyCA') ? nil : Dir.mkdir('PublicKeyCA')
    
  end

	def before_show()
   		@builder["entry_password"].set_visibility(false)
  end  

  def Encrypt_CSR
      
      iv = OpenSSL::Cipher.new('AES-256-CBC').random_iv
      cipher = OpenSSL::Cipher.new 'AES-256-CBC'
      cipher.encrypt
      cipher.key = @pass
      cipher.iv = iv 
      cipher.update(@csr.to_s) + cipher.final
      return cipher
  end

  def button_create__clicked(*args)

  		password = @builder['entry_password'].text
      country = @builder['entry_country'].text
      state = @builder['entry_state'].text
      locality = @builder['entry_locality'].text
      organ_name = @builder['entry_organ_name'].text
      organ_unit = @builder['entry_organ_unit'].text
      common = @builder['entry_common'].text
      email = @builder['entry_email'].text
      empty = (password.empty? || country.empty? || state.empty? || locality.empty? || organ_name.empty? || organ_unit.empty? || common.empty? || email.empty?)
      if !empty
          options = { 
  
                      :country      => country,
                      :state        => state,
                      :city         => locality,
                      :organization => organ_name,
                      :department   => organ_unit, 
                      :common_name  => common,
                      :email        => email
                    }

          name = OpenSSL::X509::Name.new([
            ['C',             options[:country], OpenSSL::ASN1::PRINTABLESTRING],
            ['ST',            options[:state],        OpenSSL::ASN1::PRINTABLESTRING],
            ['L',             options[:city],         OpenSSL::ASN1::PRINTABLESTRING],
            ['O',             options[:organization], OpenSSL::ASN1::UTF8STRING],
            ['OU',            options[:department],   OpenSSL::ASN1::UTF8STRING],
            ['CN',            options[:common_name],  OpenSSL::ASN1::UTF8STRING],
            ['emailAddress',  options[:email],        OpenSSL::ASN1::UTF8STRING]
  
            ])
          begin
            private_secure_key = File.read 'PrivateKey/private_key.pem'
            @private_key = OpenSSL::PKey::RSA.new private_secure_key , password
          rescue StandardError => e
               alert "Password incorrect..!"
                @builder['entry_password'].text = ""
          else 
            begin 
               @public_key = OpenSSL::PKey::RSA.new @private_key.public_key
                @csr.version = 0
                @csr.subject = name
                @csr.public_key = @public_key
                @csr.sign @private_key, OpenSSL::Digest::SHA1.new
                @server.puts @csr.to_s
                receive = String.new 
                loop do 
                  line = @server.gets
                  receive = receive + line
                  break if line.eql?"-----END CERTIFICATE-----\n"
                end
                csr_cert = OpenSSL::X509::Certificate.new receive 

                open 'Certificate/csr_cert.pem', 'w' do |io|
                  io.write csr_cert
                end

                loop do 
                  line = @server.gets
                  receive = receive + line
                  break if line.eql?"-----END PUBLIC KEY-----\n"
                end
                @public_key_ca = OpenSSL::PKey::RSA.new receive
                 open 'PublicKeyCA/public_key_ca.pem', 'w' do |io|
                  io.write @public_key_ca
                end
                @server.close
                @builder[:window1].destroy
            rescue StandardError => e
                puts 'CSR can not be verified'
                @server.close
                @builder[:window1].destroy
            end
           
          end
      else
         alert "You have not entered enough information yet..!"
      end

  end
  	
end
