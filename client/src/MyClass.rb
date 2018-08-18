

class MyClass #(change name)
 
  include GladeGUI

 def initialize
      @window1 = "Client"
      @hostname = String.new
      @port = String.new 
      @password = String.new
      @server
      @ca 
      Thread.abort_on_exception=true
  end
    
  def button_con__clicked(*args)
    if File.exist?('PrivateKey/private_key.pem')  && File.exist?('Certificate/csr_cert.pem')
      @password = ""
  		connect = Connect.new(@hostname,@port,@password)
      connect.show_glade()
      empty = (@hostname.empty? || @port.empty? || @password.empty?)
      if !empty
        begin
          @server = TCPSocket.new @hostname,@port
        rescue StandardError => e
          alert "Server does not work..!"
          @hostname = ""
          @port = ""
          @password = ""
        else
          chat = Chat.new @hostname ,@port,@password,@server
          chat.show_glade()
          @hostname = ""
          @port = ""
          @password = ""
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

