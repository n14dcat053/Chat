#!/usr/bin/env ruby
require 'openssl'
require 'socket'

class CA

	def initialize 
		#initialize Certificate Authority Server
		$password = '123456789'
		#create necessary directories
		#directory CAKey contain the CA server private key 
		#directory Certificate contain the CA server certificate 
		#directory Certificate contain the client certificate after being signed by the CA server
		Dir.exist?('CAKey') ? nil : Dir.mkdir('CAKey')
		Dir.exist?('Certificate') ? nil : Dir.mkdir('Certificate')
		Dir.exist?('CertificateQuest') ? nil : Dir.mkdir('CertificateQuest')
		Dir.exist?('Info') ? nil : Dir.mkdir('Info')
		@ca_key = OpenSSL::PKey::RSA.new 4096
		options = { 
  
					  :country      => 'VN',
					  :state        => 'HO CHI MINH CITY',
					  :city         => 'HO CHI MINH CITY',
					  :organization => 'PTITHCM',
					  :department   => 'CA', 
					  :common_name  => 'PTITHCM-CA',
					  :email        => 'admin@ptithcm.edu.vn'
					  
					  }

		@ca_name = OpenSSL::X509::Name.new([
			  ['C',             options[:country], OpenSSL::ASN1::PRINTABLESTRING],
			  ['ST',            options[:state],        OpenSSL::ASN1::PRINTABLESTRING],
			  ['L',             options[:city],         OpenSSL::ASN1::PRINTABLESTRING],
			  ['O',             options[:organization], OpenSSL::ASN1::UTF8STRING],
			  ['OU',            options[:department],   OpenSSL::ASN1::UTF8STRING],
			  ['CN',            options[:common_name],  OpenSSL::ASN1::UTF8STRING],
			  ['emailAddress',  options[:email],        OpenSSL::ASN1::UTF8STRING]
			  
			  ])  
		File.exist?('Info/serial') ? nil : (open 'Info/serial', 'w' do |io| io.write "0" end)
		File.exist?('Info/index.txt') ? nil : (open 'Info/index.txt', 'a')
		File.exist?('CAKey/ca_key.pem') ? nil : CreateKey()
		File.exist?('Certificate/ca_cert.pem') ? nil : CreateCertificate()
		
	end

	def CreateKey
		
		cipher = OpenSSL::Cipher.new 'AES-256-CBC'
		open 'CAKey/ca_key.pem' , 'w', 0400 do |io|
			io.write @ca_key.export(cipher,$password)
		end
	end

	def CreateCertificate

		ca_cert = OpenSSL::X509::Certificate.new
		ca_cert.serial = 0
		ca_cert.version = 2
		ca_cert.not_before = Time.now
		ca_cert.not_after = Time.now + 2 * 365 * 24 * 60 * 60

		ca_cert.public_key = @ca_key.public_key
		ca_cert.subject = @ca_name
		ca_cert.issuer = @ca_name

		extension_factory = OpenSSL::X509::ExtensionFactory.new
		extension_factory.subject_certificate = ca_cert
		extension_factory.issuer_certificate = ca_cert

		ca_cert.add_extension    extension_factory.create_extension('subjectKeyIdentifier', 'hash')
		ca_cert.add_extension    extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
		ca_cert.add_extension    extension_factory.create_extension('keyUsage', 'cRLSign,keyCertSign', true)
		ca_cert.sign @ca_key, OpenSSL::Digest::SHA1.new
		open 'Certificate/ca_cert.pem', 'w' do |io|
			  io.write ca_cert.to_pem
		end
		serial = File.read('Info/serial').to_i
		puts serial
		info = "#{serial}" + "   " + "#{ca_cert.subject}" + "   " + "Certificate/ca_cert.pem" 
		open 'Info/serial' ,'w' do |io| io.write "#{serial+1}" end
		open 'Info/index.txt' ,'a' do |io| io.puts info end
	end
end



class Connect

	def initialize
		@port = 5555
		@hostname = 'localhost'
		@server =TCPServer.new  @hostname,@port
		@private_key = OpenSSL::PKey::RSA.new File.read('CAKey/ca_key.pem') , $password
		@public_key =  OpenSSL::PKey::RSA.new @private_key.public_key
		@pass_client = String.new
	
		
	end

	def CertificateFromCSR(csr)
		ca_key = OpenSSL::PKey::RSA.new File.read("CAKey/ca_key.pem"),$password
		ca_cert = OpenSSL::X509::Certificate.new File.read("Certificate/ca_cert.pem")
		csr_cert = OpenSSL::X509::Certificate.new
		csr_cert.serial = 0
		csr_cert.version = 2
		csr_cert.not_before = Time.now
		csr_cert.not_after = Time.now + 1 * 365 * 24 * 60 * 60
		csr_cert.subject = csr.subject
		csr_cert.public_key = csr.public_key
		csr_cert.issuer = ca_cert.subject
		extension_factory = OpenSSL::X509::ExtensionFactory.new
		extension_factory.subject_certificate = csr_cert
		extension_factory.issuer_certificate = ca_cert
		csr_cert.add_extension    extension_factory.create_extension('basicConstraints', 'CA:FALSE')
		csr_cert.add_extension    extension_factory.create_extension(
		    'keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
		csr_cert.add_extension    extension_factory.create_extension('subjectKeyIdentifier', 'hash')
		csr_cert.sign ca_key, OpenSSL::Digest::SHA1.new
		serial = File.read('Info/serial')
		serial = serial.to_i
		open "CertificateQuest/#{serial}_csr_cert", 'w' do |io| io.write csr_cert.to_pem end
		info = "#{serial}" + "   " + "#{csr_cert.subject}" + "   " +"CertificateQuest/"+"#{serial}_csr_cert" 
		open 'Info/serial' ,'w' do |io| io.write serial+1 end
		open 'Info/index.txt' ,'a' do |io| io.puts info end
		return csr_cert
	end

	def connect
			puts "Server is starting ..!"

		while true 
		
				Thread.start( @server.accept()) do  |client|
					begin 
						receive = String.new
						loop do 
							line = client.gets
							receive = receive + line
							break if line.eql?"-----END CERTIFICATE REQUEST-----\n"
						end
						csr = OpenSSL::X509::Request.new receive
						if csr.verify csr.public_key
							csr_cert = CertificateFromCSR(csr) 
							client.puts csr_cert.to_s	
							client.puts @public_key.to_s
						else 
							puts 'CSR can not be verified'
						end
					rescue StandardError => e
						puts "Disconnect..!"
					end 
				end
			
		end

	end
end




ca = CA.new() 
connect = Connect.new()
connect.connect

