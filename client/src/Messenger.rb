
class Messenger
	include GladeGUI
	
	def initialize(file,password)
		@file = file
		@password = password
		@filename = File.basename(file)
		@hostname
		@private_key = OpenSSL::PKey::RSA.new File.read('PrivateKey/private_key.pem'), @password
		@password_aes
		@iv
		@salt
		@digest = OpenSSL::Digest::SHA256.new
		@cipher = OpenSSL::Cipher.new 'AES-128-CBC'
		@buffer = Gtk::TextBuffer.new
		@buffer.create_tag("red",{"foreground"=>"red"} )
		@buffer.create_tag("blue",{"foreground"=>"blue"} )
		@link
	end

	def DecryptionWithPrivatekey(data)
  		original_key = @private_key.private_decrypt data
  		return original_key
  	end

	def getHostname()
		temp = @filename.split(" ")
		@hostname = temp[0]
	end

	def getPassword_AES()
		temp = String.new
		File.open("KeySession/#{@filename}/password", "r") do |f|
		  f.each_line do |line|
		     temp = temp + line
		  end
		end
		@password_aes = DecryptionWithPrivatekey(temp.chop)
		temp = ""
		File.open("KeySession/#{@filename}/iv", "r") do |f|
		  f.each_line do |line|
		     temp = temp + line
		  end
		end
		@iv = DecryptionWithPrivatekey(temp.chop) 
		temp = ""
		File.open("KeySession/#{@filename}/salt", "r") do |f|
		  f.each_line do |line|
		     temp = temp + line
		  end
		end
		@salt = DecryptionWithPrivatekey(temp.chop)
	end

	def DecryptWithAES(data)
		digest = @digest
		cipher = @cipher
		cipher.decrypt
		cipher.iv = @iv # the one generated with #random_iv
		pwd = @password_aes
		salt = @salt # the one generated above
		iter = 20000
		key_len = cipher.key_len
		key = OpenSSL::PKCS5.pbkdf2_hmac(pwd, salt, iter, key_len, digest)
		cipher.key = key
		decrypted = cipher.update data
		decrypted << cipher.final
		return decrypted.to_s
	end 
	def addBuffer(mess,mode)
		data = eval(mess)
		messenger = DecryptWithAES(data[:document])
		start = @buffer.get_iter_at(:offset => @buffer.end_iter.offset)
		if mode.eql?"RECEIVE"
			@buffer.insert(start, "#{mode} : ", :tags => ["red"])
		else
			@buffer.insert(start, "#{mode} : ", :tags => ["blue"])
		end
		@buffer.apply_tag("red",start, @buffer.end_iter)
		@buffer.insert_at_cursor( messenger + "\n")
		
	end
	


	def getMessenger
		mess = String.new
		File.open("Messenger/#{@filename}", "r") do |f|
		  f.each_line do |line|
		  	mess = mess + line
		   if line.eql?"*****BEGIN RECEIVE*****\n"
		   		mess = ""

		   end
		  	if line.eql?"*****BEGIN SEND*****\n"
		   		mess = ""
		   end

		   if line.eql?"*****END RECEIVE*****\n"
		   		temp = mess.split("\n")
		   		mess1 = temp[0]
		   		addBuffer(mess1,"RECEIVE")
		   		mess = ""
		   end
		   if line.eql?"*****END SEND*****\n"
		   		temp = mess.split("\n")
		   		mess1 = temp[0]
		   		addBuffer(mess1,"SEND")
		   		mess = ""
		   end

		  end
		end
	end

	def getInfo()
		File.open('Info/index.txt').each do |line|
	  			array = line.split('   ')
	  			if array[0].eql?"#{@hostname}"
	  				@link = array[2].chop
	  				
	  				break
	  			end
	  		end
	end

	def ShowInfo()
		
		certificate = OpenSSL::X509::Certificate.new File.read("#{@link}")
		info = certificate.subject.to_s
		temp = info.split("/")
		info_temp = String.new
		temp.each do |string|
			info_temp = info_temp + string +"\n"
		end
		@builder[:label1].text = info_temp

	end

	def before_show()
		begin
			getHostname()
			getPassword_AES()
			getMessenger()
			getInfo()
			ShowInfo()
			@builder[:textview].set_buffer(@buffer)
		rescue StandardError => e
			alert "The file format is incorrect"
			
		end
		
  	end  

  
	
end	