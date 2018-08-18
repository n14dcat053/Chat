class Connect
	include GladeGUI

	
	def initialize(hostname,port,password)
		@check_private_key = nil
		@hostname = hostname
		@port = port
		@password = password
		
	end
	def before_show()
		#hidden password 
    	 @builder["entry_password"].set_visibility(false)
  	end  
  	
  	

 	def button_connect__clicked(*args)
		hostname = @builder['entry_hostname'].text
		port = @builder['entry_port'].text
		password = @builder['entry_password'].text
		empty = (hostname.empty? || port.empty? || password.empty?)
		if !empty
			begin
				private_key_secure = File.read 'PrivateKey/private_key.pem'
				@check_private_key = OpenSSL::PKey::RSA.new private_key_secure, password
			rescue StandardError => e
				alert "Password incorrect..!"
				@builder['entry_password'].text = ""
			else 
				@hostname << hostname
				@port << port
				@password << password
				Dir.exist?('Info') ? nil : Dir.mkdir('Info')
				Dir.exist?('CertificateServer')? nil : Dir.mkdir('CertificateServer')
				@builder['window1'].destroy 

			end
		else 
			alert "You have not entered enough information yet..!"
		end

 	end
 	 
end