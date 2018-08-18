

class MyClass #(change name)
 
  include GladeGUI

 def initialize
      @window1 = "Server"
      @password = String.new
      @hostname = 'localhost'
      @port = 11111
      @server
      @ca
      
      
  end
  def CheckConnect
      Dir.exist?('Info') ? nil : Dir.mkdir('Info')
      Dir.exist?('CertificateClient')? nil : Dir.mkdir('CertificateClient')
      File.exist?('Info/serial')? nil :  (open 'Info/serial', 'w' do |io| io.write "0" end)
      while true
        if !@password.empty?
          client = @server.accept()
            puts "Client Connect...!"
            chat = Chat.new client,@password
            chat.show_glade()
        end
      end
    
  end
  def button_con__clicked(*args)
    if File.exist?('PrivateKey/private_key.pem')  && File.exist?('Certificate/csr_cert.pem')
        if @password.empty?
            password =  Password.new(@password)
        	  password.show_glade()	
        end
        if !@password.empty?
          begin
            @server = TCPServer.new @hostname,@port
          rescue StandardError => e
            alert "Server is running..!"
          else
              check_connect = Thread.new{CheckConnect()}
          end
        end
    else 
        button_reg__clicked()
    end
  end

   def CC()
    begin
      @ca =  TCPSocket.new('localhost', 5555)
    rescue StandardError => e
       alert "Server does not work..!"
    else
      create_certificate = CreateCertificate.new(@ca)
      create_certificate.show_glade()
    end
     
  end

  def button_reg__clicked(*args)
      if File.exist?('PrivateKey/private_key.pem') 
          CC()
      else
          PrivateKey.new.show_glade()
          File.exist?('PrivateKey/private_key.pem') ? CC() : nil 
      end 
  		
  end	
  def button_messenger__clicked(*args)
    if @password.empty?
            password =  Password.new(@password)
            password.show_glade() 
    end
    if !@password.empty?
      file = String.new
      dialog = Gtk::FileChooserDialog.new( :title => "Open File",
                                         :parent => nil,
                                        :action => Gtk::FileChooserAction::OPEN,
                                        :buttons => 
                                       [[Gtk::Stock::CANCEL, Gtk::ResponseType::CANCEL],
                                       [Gtk::Stock::OPEN , Gtk::ResponseType::ACCEPT]])


      if dialog.run == Gtk::ResponseType::ACCEPT
         file = dialog.filename
      end
      dialog.destroy
      if !file.empty?
        mess = Messenger.new(file,@password)
        mess.show_glade()
      end
    end

  end

end

