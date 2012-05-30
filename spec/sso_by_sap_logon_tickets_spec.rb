require 'openssl'
require 'timecop'
require 'sso_sap'

FIXTURES_PATH = File.expand_path('../fixtures', __FILE__)

describe "SAP logon ticket functions" do
  it "should parse a sample logon ticket from the web" do
    ticket_path = "#{FIXTURES_PATH}/logon_ticket_from_web.txt"
    ticket_bytes = SsoSap::LogonTicket.decode_ticket(File.read(ticket_path))
    SsoSap::LogonTicket.parse_ticket(ticket_bytes).should == {
      :version        => 2,
      :code_page      => "1100",
      :user           => "DCHQ04",
      :create_client  => "000",
      :create_name    => "EP4",
      :create_time    => "201106011245",
      :valid_time     => "\x00\x00\x00\b",
      :user_utf       => "DCHQ04",
      32              => "portal:DCHQ04",
      :authscheme     => "basicauthentication",
      :signature      => "0\x82\x01\x01\x06\t*\x86H\x86\xF7\r\x01\a\x02\xA0\x81\xF30\x81\xF0\x02\x01\x011\v0\t\x06\x05+\x0E\x03\x02\x1A\x05\x000\v\x06\t*\x86H\x86\xF7\r\x01\a\x011\x81\xD00\x81\xCD\x02\x01\x010\"0\x1D1\f0\n\x06\x03U\x04\x03\x13\x03EP41\r0\v\x06\x03U\x04\v\x13\x04J2EE\x02\x01\x000\t\x06\x05+\x0E\x03\x02\x1A\x05\x00\xA0]0\x18\x06\t*\x86H\x86\xF7\r\x01\t\x031\v\x06\t*\x86H\x86\xF7\r\x01\a\x010\x1C\x06\t*\x86H\x86\xF7\r\x01\t\x051\x0F\x17\r110601124508Z0#\x06\t*\x86H\x86\xF7\r\x01\t\x041\x16\x04\x14:\x8A0a0<W\xD9\xF2\xF3\x05|*\xFA9}_\n*30\t\x06\a*\x86H\xCE8\x04\x03\x04/0-\x02\x15\x00\xE0\x9B\x90\xE0\xC8i,\xBE\x1D\xFBa\x1D\xE4}\x1D'\x17JU\xC0\x02\x14\x17\xBE\b\x8F\xB7@\xA7}\xE6\x99'\xDE\x95\x01\xCAC\xB6\xA6\xFE\x8F",
      :start_time     => Time.gm(2011, 6, 1, 12, 45, 0),
      :end_time       => Time.gm(2011, 6, 1, 20, 45, 0),
    }
  end

  it "should raise an error for a truncated logon ticket" do
    ticket_path = "#{FIXTURES_PATH}/logon_ticket_truncated.txt"
    ticket_bytes = SsoSap::LogonTicket.decode_ticket(File.read(ticket_path))
    lambda {
      SsoSap::LogonTicket.parse_ticket(ticket_bytes)
    }.should raise_error(SsoSap::TicketError, 'Truncated cookie: Expected InfoUnit of length 261 but got 242')
  end

  context 'when using generated tickets' do
    before(:each) do
      # To recreate these fixtures, run:
      #   java/issue_logon_ticket.sh logon_ticket_generated1.txt generated1.verify.der
      #   java/issue_logon_ticket.sh logon_ticket_generated2.txt generated2.verify.der
      # and update the timecop times

      @ticket_path1 = "#{FIXTURES_PATH}/logon_ticket_generated1.txt"
      @cert_path1 = "#{FIXTURES_PATH}/generated1.verify.der"
      @ticket_bytes1 = SsoSap::LogonTicket.decode_ticket(File.read(@ticket_path1))
  
      @ticket_path2 = "#{FIXTURES_PATH}/logon_ticket_generated2.txt"
      @cert_path2 = "#{FIXTURES_PATH}/generated2.verify.der"
      @ticket_bytes2 = SsoSap::LogonTicket.decode_ticket(File.read(@ticket_path2))
    end

    it "should successfully verify logon ticket signatures" do
      Timecop.freeze(Time.gm(2012, 5, 7, 20, 5, 0)) do
        SsoSap::LogonTicket.verify_ticket!(@ticket_bytes1, File.read(@cert_path1))
      end
      Timecop.freeze(Time.gm(2012, 5, 7, 20, 5, 0)) do
        SsoSap::LogonTicket.verify_ticket!(@ticket_bytes2, File.read(@cert_path2))
      end
    end

    it "shouldn't verify tickets signed with a different keypair" do
      lambda {
        SsoSap::LogonTicket.verify_ticket!(@ticket_bytes1, File.read(@cert_path2))
      }.should raise_error(SsoSap::TicketError, 'Certificate verification failed: signer certificate not found')
      lambda {
        SsoSap::LogonTicket.verify_ticket!(@ticket_bytes2, File.read(@cert_path1))
      }.should raise_error(SsoSap::TicketError, 'Certificate verification failed: signer certificate not found')
    end

    it "shouldn't verify tickets signed with a different key pair even with forged serial numbers" do
      parsed1 = SsoSap::LogonTicket.parse_ticket(@ticket_bytes1)
      asn1_1 = OpenSSL::ASN1.decode(parsed1[:signature])
      serial_num1 = asn1_1.value[1].value[0].value[3].value[0].value[1].value[1].value
      packed_serial_num1 = [serial_num1].pack('N')
      @ticket_bytes1.index(packed_serial_num1).should_not be_nil
  
      parsed2 = SsoSap::LogonTicket.parse_ticket(@ticket_bytes2)
      asn1_2 = OpenSSL::ASN1.decode(parsed2[:signature])
      serial_num2 = asn1_2.value[1].value[0].value[3].value[0].value[1].value[1].value
      packed_serial_num2 = [serial_num2].pack('N')
      @ticket_bytes2.index(packed_serial_num2).should_not be_nil
  
      bad_ticket_bytes1 = @ticket_bytes1.gsub(packed_serial_num1, packed_serial_num2)
      bad_ticket_bytes1.size.should == @ticket_bytes1.size
      bad_ticket_bytes1.should_not == @ticket_bytes1
      lambda {
        SsoSap::LogonTicket.verify_ticket!(bad_ticket_bytes1, File.read(@cert_path2))
      }.should raise_error(SsoSap::TicketError, 'Certificate verification failed: BN lib')
    end
  
    it "shouldn't verify tickets that were tampered with" do
      good_bytes = SsoSap::LogonTicket.decode_ticket(File.read(@ticket_path1))
      bad_bytes = good_bytes.gsub('USER', 'USR2')
      bad_bytes.should_not == good_bytes # make sure USER is actually present in the ticket
      Timecop.freeze(Time.gm(2012, 5, 7, 20, 8, 0)) do
        SsoSap::LogonTicket.verify_ticket!(good_bytes, File.read(@cert_path1))
        lambda {
          SsoSap::LogonTicket.verify_ticket!(bad_bytes, File.read(@cert_path1))
        }.should raise_error(SsoSap::TicketError, 'Certificate verification failed: digest failure')
      end
    end
  
    it "shouldn't verify tickets that were tampered with, even if the SHA1 was updated too" do
      good_bytes = SsoSap::LogonTicket.decode_ticket(File.read(@ticket_path1))
      good_data_to_sign = SsoSap::LogonTicket.data_to_sign(good_bytes)
      good_sha1 = OpenSSL::Digest::SHA1.digest(good_data_to_sign)
      good_bytes.index(good_sha1).should_not be_nil # ticket digest embeds the sha1 of other infounits
      bad_data_to_sign = good_data_to_sign.gsub('USER', 'USR2')
      bad_sha1 = OpenSSL::Digest::SHA1.digest(bad_data_to_sign)
      bad_bytes = good_bytes.gsub('USER', 'USR2').gsub(good_sha1, bad_sha1)
      bad_bytes.size.should == good_bytes.size
      bad_bytes.should_not == good_bytes
      Timecop.freeze(Time.gm(2012, 5, 7, 20, 8, 0)) do
        SsoSap::LogonTicket.verify_ticket!(good_bytes, File.read(@cert_path1))
        lambda {
          SsoSap::LogonTicket.verify_ticket!(bad_bytes, File.read(@cert_path1))
        }.should raise_error(SsoSap::TicketError, 'Certificate verification failed: BN lib')
      end
    end
  end

  it "should successfully verify logon ticket signatures" do
    def test_expiration_times(options, &block)
      lambda {
        Timecop.freeze(options[:too_early]) { block.call }
      }.should raise_error SsoSap::TicketError
  
      Timecop.freeze(options[:good_time]) { block.call } # should not error
  
      lambda {
        Timecop.freeze(options[:too_late]) { block.call }
      }.should raise_error SsoSap::TicketError
    end

    ticket_path = "#{FIXTURES_PATH}/logon_ticket_generated1.txt"
    ticket_bytes = SsoSap::LogonTicket.decode_ticket(File.read(ticket_path))
    cert_path = "#{FIXTURES_PATH}/generated1.verify.der"
    test_expiration_times(:too_early => Time.gm(2012, 5, 7, 0, 0, 0),
                          :good_time => Time.gm(2012, 5, 8, 0, 0, 0),
                          :too_late  => Time.gm(2012, 5, 9, 0, 0, 0)) do
      SsoSap::LogonTicket.verify_ticket!(ticket_bytes, File.read(cert_path))
    end
  end

  it "should convert binary strings to ints correctly" do
    SsoSap::LogonTicket.unpack_binary_int("\0\0\0\0").should == 0
    SsoSap::LogonTicket.unpack_binary_int('').should == 0
    SsoSap::LogonTicket.unpack_binary_int('nil').should == 0
    SsoSap::LogonTicket.unpack_binary_int("\0\0\0\x01").should == 1
    SsoSap::LogonTicket.unpack_binary_int("\xff\xff\xff\xff").should == 256 ** 4 - 1
  end

end
