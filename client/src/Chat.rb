require 'json'

class Chat
	include GladeGUI

	def initialize(hostname,port,password,server)
		
		@window1 = "client"
		@hostname = hostname
		@port = port
		@password = password
		@server = server
		@buffer = Gtk::TextBuffer.new
		@buffer.create_tag("red",{"foreground"=>"red"} )
		@buffer.create_tag("blue",{"foreground"=>"blue"} )
		@private_key = OpenSSL::PKey::RSA.new File.read('PrivateKey/private_key.pem'), @password
		@public_key = OpenSSL::PKey::RSA.new @private_key.public_key
		@public_key_ca = OpenSSL::PKey::RSA.new File.read('PublicKeyCA/public_key_ca.pem')
		@certificate = OpenSSL::X509::Certificate.new File.read('Certificate/csr_cert.pem')
		@certificate_server
		@ID = String.new 
		@public_key_server 
		@digest = OpenSSL::Digest::SHA256.new
		@password_aes = SecureRandom.hex
		@cipher = OpenSSL::Cipher.new 'AES-128-CBC'
		@iv = @cipher.random_iv
		@salt = OpenSSL::Random.random_bytes 16
		@session_time
		
	end


	def before_show()

		CheckInfo()
		nhan = Thread.new { Nhan() }

	end

	def Destroy(mess)
		alert "#{mess}"
		@server.close
		@builder[:window1].destroy
	end

	def Check 
		File.open('Info/index.txt').each do |line|
				array = line.split('   ')
				if array[0].eql?"#{@hostname}"
					@ID = array[1]
					link = array[2].chomp
					@certificate_server = OpenSSL::X509::Certificate.new File.read("#{link}")
					@public_key_server =  OpenSSL::PKey::RSA.new @certificate_server.public_key
					break
				end 
		end
		@ID.empty? ? FirstConnect() : Connect() 
	end

	def CheckInfo
		if 	File.zero?('Info/index.txt') || !File.exist?('Info/index.txt')
			FirstConnect()
		else 
			Check()
		end 
		
	end

	def FirstConnect
		
		receive = String.new
		@server.puts "---FIRST CONNECT---"
		@server.puts @certificate.to_s
		receive = @server.gets.chomp
		if receive.eql?"---ERROR---"
			alert "Client - Certificate can not be verified..! Disconnect"
			@builder[:window1].destroy
		else 
			receive = ""
			loop do 
	            line = @server.gets
	            receive = receive + line
	            break if line.eql?"-----END CERTIFICATE-----\n"
        	end

        	certificate_server = OpenSSL::X509::Certificate.new receive
        	

        	begin 
        	certificate_server.verify @public_key_ca 
	    	rescue StandardError => e
	    		@server.puts "---ERROR---"
	       		Destroy("Certificate Server can not be verified..! Disconnect")
	       	else 
	       		@server.puts "---OK---"
	       		receive = @server.gets.chomp
	       		puts "#{receive}"
	       		info = @hostname + "   " + receive + "   " + "CertificateServer/#{@hostname}_csr_cert.pem"
	       		open "CertificateServer/#{@hostname}_csr_cert.pem", 'w' do |io| io.write certificate_server end
	       		open 'Info/index.txt' ,'a' do |io| io.puts info end
	       		Check()
	  		end
		end


	end

	def CheckSignatures(signature,document)
  		
  		if @public_key_server.verify @digest, signature, document
			  return true
		else
			  return false 
		end
  	end

	def SignaturesAndPack(document)
		signature = @private_key.sign @digest, document
		data = {}
		data[:document] = document
		data[:signature] = signature
	
		return data
	end



	def EncryptionWithPublickey(data,public_key)
		wrapped_key = public_key.public_encrypt data
		return wrapped_key
	end

	
	def ShowInfo()
		info = String.new
		info_server = @certificate_server.subject.to_s
		temp = info_server.split('/')
		temp.each do |string|
			info = info + string +"\n"
		end

		@builder[:label1].text = info
		@builder[:label].text = "#{@hostname}"
		
	end

	

	def Connect()
		begin 
			@server.puts "---CONNECT---"
			#send ID to server

			@server.puts SignaturesAndPack(@ID)
			#receive confirm from server
			
			receive = @server.gets
			
			data = eval(receive)

			#check Signature 
			CheckSignatures(data[:signature],data[:document]) ? nil : Destroy("Signature of server invalid")
			
			if data[:document].eql?"---OK---"
				
				key = EncryptionWithPublickey(@password_aes,@public_key_server)
			
				iv = EncryptionWithPublickey(@iv,@public_key_server)
				
				salt = EncryptionWithPublickey(@salt,@public_key_server)
				
				@server.puts SignaturesAndPack(key)
				@server.puts SignaturesAndPack(iv)
				@server.puts SignaturesAndPack(salt)

			else 
				@server.close
				builder[:window1].destroy
			end
			ShowInfo()
		rescue StandardError => e
			Destroy("Disconnect..!")
		end 

	end

	def EncryptWithAES(data)
		digest = @digest
		cipher = @cipher
		cipher.encrypt
		cipher.iv = @iv
		pwd = @password_aes
		salt = @salt
		iter = 20000
		key_len = cipher.key_len
		digest = OpenSSL::Digest::SHA256.new
		key = OpenSSL::PKCS5.pbkdf2_hmac(pwd, salt, iter, key_len, digest)
		cipher.key = key
		encrypted = cipher.update data
		encrypted << cipher.final
		return encrypted.to_s
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


	def CreateSaveMessenger()
		@session_time = DateTime.now.strftime("%d/%m/%Y %H:%M:%S")
		Dir.exist?('Messenger') ? nil : Dir.mkdir('Messenger')
  		Dir.exist?('KeySession') ? nil : Dir.mkdir('KeySession')
  		password = EncryptionWithPublickey(@password_aes,@public_key)
  		iv = EncryptionWithPublickey(@iv,@public_key)
  		salt = EncryptionWithPublickey(@salt,@public_key)
  		temp = @session_time.split(' ')
  		temp1 = temp[0].tr("/","-")
  		filename = @hostname + " " + temp1 + " " + temp[1]
  		Dir.mkdir("KeySession/#{filename}")
  		open "KeySession/#{filename}/password" ,'w', 0400 do |io| io.puts "#{password}" end
  		open "KeySession/#{filename}/iv" ,'w', 0400 do |io| io.puts "#{iv}" end
  		open "KeySession/#{filename}/salt" ,'w', 0400 do |io| io.puts "#{salt}" end
  		#begin_messenger = "**********BEGIN MESSENGER**********"
  		#open "Messenger/#{filename}" ,'a' do |io| io.puts "#{begin_messenger}\n" end
	end

	def SaveMessenger(messenger,mode)
		temp = @session_time.split(' ')
  		temp1 = temp[0].tr("/","-")
  		filename = @hostname + " " + temp1 + " " + temp[1]
  		begin_mess = "*****BEGIN #{mode}*****"
  		open "Messenger/#{filename}" ,'a' do |io| io.puts "#{begin_mess}\n" end
		open "Messenger/#{filename}" ,'a' do |io| io.puts "#{messenger}\n" end
		end_mess = "*****END #{mode}*****"
		open "Messenger/#{filename}" ,'a' do |io| io.puts "#{end_mess}\n" end	
	end

	def Nhan()
		CreateSaveMessenger()
		begin
			while true
					receive =  @server.gets
					data = eval(receive)
					time = Time.now.strftime("%d/%m/%Y %H:%M:%S")
					if CheckSignatures(data[:signature],data[:document])
						print "Receive <="
						p data[:document] 
						puts "\n #{data[:document]}"
						mess = DecryptWithAES(data[:document])
						start = @buffer.get_iter_at(:offset => @buffer.end_iter.offset)
						@buffer.insert(start, "#{time} : ", :tags => ["red"])
						@buffer.apply_tag("red",start, @buffer.end_iter)
						@buffer.insert_at_cursor(mess + "\n")
						#@buffer.set_text(@buffer.text + "\n" + "Nhan <= " +mess)
						@builder[:textview].set_buffer(@buffer)
						SaveMessenger(data,"RECEIVE")
					end
				
			end
		rescue StandardError => e
			#temp = @session_time.split(' ')
	  		#temp1 = temp[0].tr("/","-")
	  		#filename = @ID + " " + temp1 + " " + temp[1]
			#end_messenger = "**********END MESSENGER**********"
	  		#open "Messenger/#{filename}" ,'a' do |io| io.puts "#{end_messenger}" end
			puts "Disconnect..!"
			@builder[:window1].destroy
		end

	end


	def entry__activate(*args)
		button__clicked()
	end
	
	def exit__clicked(*args)

		@server.close
	end

	def button__clicked(*args)
		mess = @builder[:entry].text
		if !mess.empty?
			document = EncryptWithAES(mess)
			print "Send => "
			p document
			puts "\n #{document}"
			document_send = SignaturesAndPack(document)
			@server.puts document_send
			time = Time.now.strftime("%d/%m/%Y %H:%M:%S")
			start = @buffer.get_iter_at(:offset => @buffer.end_iter.offset)
			@buffer.insert(start, "#{time} : ", :tags => ["blue"])
			@buffer.apply_tag("blue",start, @buffer.end_iter)
			@buffer.insert_at_cursor(mess + "\n")
			#@buffer.set_text(@buffer.text + "\n" + "Gui => " +mess)
			@builder[:textview].set_buffer(@buffer)
			@builder[:entry].set_text("")
			SaveMessenger(document_send,"SEND")
		end
	end


end
