require 'openssl'

class PrivateKey
	include GladeGUI
	
	def initialize
		@window1 = " Create Private Key"
	
	end

	def before_show()
		#hidden password 
    	 @builder["entry_pass"].set_visibility(false)
    	 @builder["entry_confirm"].set_visibility(false)
  	end  
  	
  	def CreateKey(key,password)
		
		cipher = OpenSSL::Cipher.new 'AES-256-CBC'
		open 'PrivateKey/private_key.pem' , 'w', 0400 do |io|
			io.write key.export(cipher,password)
		end
	end

	def button_create__clicked(*args)
		password = @builder["entry_pass"].text
		confirm = @builder["entry_confirm"].text
		empty = (password.empty? || confirm.empty?)
		if !empty
			if password.eql?confirm
				Dir.exist?("PrivateKey") ? nil : Dir.mkdir('PrivateKey') 
				key = OpenSSL::PKey::RSA.new 4096
				CreateKey(key,password)

=begin
				# create private key and public key 
				key = OpenSSL::PKey::RSA.new 4096
				open 'PrivateKey/private_key.pem', 'w' do |io| io.write key.to_pem end
			
				# Private key encryption
				cipher = OpenSSL::Cipher.new 'AES-256-CBC'
				password = @builder["entry_pass"].text
				key_secure = key.export cipher, password
				open 'PrivateKey/private_key.pem', 'w' do |io|
					io.write key_secure
				end
=end
				@builder["window1"].destroy 
			else
				alert "Password does not match the confirm password..!"
			end
		else 
			alert "You not already type in password..!"
		end

	end
	
end	