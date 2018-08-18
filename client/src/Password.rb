class Password
	include GladeGUI

	def initialize(password)
		@password = password
		@check_private_key = nil
	end

	def before_show
		 
		 @builder[:entry].set_visibility(false)
	end

	def button__clicked(*args)
		password = @builder[:entry].text
		if !password.empty?
			begin
				private_key_secure = File.read 'PrivateKey/private_key.pem'
				@check_private_key = OpenSSL::PKey::RSA.new private_key_secure, password
			rescue
					alert "Password incorrect..!"
					@builder[:entry].text = ""
			else 
				@password << password
				@builder['window1'].destroy 
			end
		else
			alert "Password don't blank..!"
		end
	end
end