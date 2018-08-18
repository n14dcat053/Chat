require 'json'

class Chat
	include GladeGUI
	
	def initialize(client,password)
		
		@window1 = "server"
		@client = client
		@buffer = Gtk::TextBuffer.new
		@buffer.create_tag("red",{"foreground"=>"red"} )
		@buffer.create_tag("blue",{"foreground"=>"blue"} )
		@password = password
		@private_key = OpenSSL::PKey::RSA.new File.read('PrivateKey/private_key.pem'), @password
		@public_key = OpenSSL::PKey::RSA.new @private_key.public_key
		@certificate = OpenSSL::X509::Certificate.new File.read('Certificate/csr_cert.pem') 
		@public_key_ca = OpenSSL::PKey::RSA.new File.read('PublicKeyCA/public_key_ca.pem')
		@ID_client = String.new
		@public_key_client 
		@Info_client = String.new
		@digest = OpenSSL::Digest::SHA256.new
		@password_aes = String.new
		@cipher = OpenSSL::Cipher.new 'AES-128-CBC'
		@iv 
		@salt
		@session_time

      	
		
	end

	def before_show()
		CheckInfo()
		
		nhan = Thread.new { Nhan() }
		
  	end

  	def Destroy(mess)
		alert "#{mess}"
		@client.close
		@builder[:window1].destroy
	end

  	def CheckInfo 
  		receive = @client.gets.chomp
  		if receive.eql? "---FIRST CONNECT---"
  			FirstConnect() 
  		else 
  			Connect()
  		end
  	end

  	def FirstConnect
  		receive = String.new
  		loop do 
            line = @client.gets
            receive = receive + line
            break if line.eql?"-----END CERTIFICATE-----\n"
        end
        certificate_client =OpenSSL::X509::Certificate.new receive
        
        begin 
        	certificate_client.verify @public_key_ca 
    	rescue StandardError => e

    		@client.puts "---ERROR---"
       		Destroy("Certificate Client can not be verified..! Disconnect")
       	else 
       		
       		@client.puts "---OK---"
       		@client.puts @certificate.to_s
       		receive = @client.gets.chomp
       		if receive.eql?"---ERROR---"
				alert "Server - Certificate can not be verified..! Disconnect"
				@builder[:window1].destroy
			else
				serial = File.read('Info/serial').to_i
				info = "#{serial}" + "   " + "#{certificate_client.subject}" + "   " + "CertificateClient/#{serial}_csr_cert.pem"
				open "CertificateClient/#{serial}_csr_cert.pem" , 'w' do |io| io.write certificate_client end
				open 'Info/serial' ,'w' do |io| io.write "#{serial+1}" end
				open 'Info/index.txt' ,'a' do |io| io.puts info end
				@client.puts serial
				receive = @client.gets.chomp
				if receive.eql? "---CONNECT---"
		  			Connect()
		  		end
			end
  		end

  		
  	end

  	def EncryptionWithPublickey(data,public_key)
		wrapped_key = public_key.public_encrypt data
		return wrapped_key
	end

  	def DecryptionWithPrivatekey(data)
  		original_key = @private_key.private_decrypt data
  		return original_key
  	end

  	def CheckSignatures(signature,document)
  		
  		if @public_key_client.verify @digest, signature, document
			  return true
		else
			  return false 
		end
  	end

  	def SignaturesAndPack(document)

		signature = @private_key.sign @digest, document.to_s
		data  = {}
		data[:document] = document
		data[:signature] = signature
		
		return data
	end


	

	def ShowInfo()
		info = String.new
		temp = @Info_client.split("/")
		temp.each do |string|
			info = info + string +"\n"
			
		end
		@builder[:label1].text = info
		@builder[:label3].text = @ID_client

	end

	
  	def Connect
  		begin 
	  		link = String.new
	  		#receive ID from client
	  		receive = @client.gets
	  		
	  		data = eval(receive)
	  		
	  		#find ID in index.txt
	  		File.open('Info/index.txt').each do |line|
	  			array = line.split('   ')
	  			if array[0].eql?"#{data[:document]}"
	  				#get ID
	  				@ID_client = array[0]
	  				@Info_client = array[1]
	  				link = array[2].chomp
	  				

	  				break
	  			end
	  		end

	  		certificate_client = OpenSSL::X509::Certificate.new File.read("#{link}")
	  		@public_key_client = certificate_client.public_key
	  		CheckSignatures(data[:signature],data[:document])? nil : Destroy("Signature of server invalid")
	  		send_client = SignaturesAndPack("---OK---")
	  		
	  		 @client.puts send_client

	  		receive = @client.gets
	  		data = eval(receive)
	  		CheckSignatures(data[:signature],data[:document])? nil : Destroy("Signature of server invalid")
	  		@password_aes = DecryptionWithPrivatekey(data[:document])
	  		
	  		receive = @client.gets
	  		data = eval(receive)
	  		CheckSignatures(data[:signature],data[:document])? nil : Destroy("Signature of server invalid")
	  		@iv = DecryptionWithPrivatekey(data[:document])
	  		
	  		receive = @client.gets
	  		data = eval(receive)
	  		CheckSignatures(data[:signature],data[:document])? nil : Destroy("Signature of server invalid")
	  		@salt = DecryptionWithPrivatekey(data[:document])
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
  		filename = @ID_client + " " + temp1 + " " + temp[1]
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
  		filename = @ID_client + " " + temp1 + " " + temp[1]
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
	  				receive =  @client.gets
					data = eval(receive)
					time = DateTime.now.strftime("%d/%m/%Y %H:%M:%S")
					if CheckSignatures(data[:signature],data[:document])
						print "Receive <="
						p data[:document] 
						puts "\n #{data[:document]}"
						mess = DecryptWithAES(data[:document])
						start = @buffer.get_iter_at(:offset => @buffer.end_iter.offset)
						@buffer.insert(start, "#{time} : ", :tags => ["red"])
						@buffer.apply_tag("red",start, @buffer.end_iter)
						@buffer.insert_at_cursor( mess + "\n")
						#@buffer.set_text(@buffer.text + "\n" + "Nhan <= " +mess)
						@builder[:textview].set_buffer(@buffer)
						SaveMessenger(data,"RECEIVE")
					end
			
			end
  		rescue StandardError => e
  			#temp = @session_time.split(' ')
	  		#temp1 = temp[0].tr("/","-")
	  		#filename = @ID_client + " " + temp1 + " " + temp[1]
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
		
		@client.close
	end

	def button__clicked(*args)
		mess = @builder[:entry].text
		if !mess.empty?
			document = EncryptWithAES(mess)
			print "Send => "
			p document
			puts "\n #{document}"
			document_send = SignaturesAndPack(document)
			@client.puts document_send
			time = DateTime.now.strftime("%d/%m/%Y %H:%M:%S")
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