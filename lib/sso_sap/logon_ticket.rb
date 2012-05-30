require 'base64'
require 'open-uri'

module SsoSap
  class LogonTicket
    ID2FIELD_NAME = {
      1   => :user,
      2   => :create_client,
      3   => :create_name,
      4   => :create_time,
      5   => :valid_time,
      6   => :rfc,
      7   => :valid_time_min,
      8   => :flags,
      9   => :language,
      10  => :user_utf,
      11  => :create_client_utf,
      12  => :create_name_utf,
      13  => :create_time_utf,
      14  => :language_utf,
      15  => :auth_type,
      136 => :authscheme,
      255 => :signature,
    }

    # unpack example: "\0\0\x01\x02".unpack('N')[0] = 258
    def self.unpack_binary_int(four_bytes)
      (four_bytes || "\0\0\0\0").unpack('N')[0].to_i
    end

    def self.decode_ticket(ticket)
      Base64.decode64(URI::decode(ticket).gsub(/!/, '+'))
    end

    def self.parse_ticket(bytes)
      input = StringIO.new(bytes)

      version = input.getbyte
      raise TicketError, "Truncated cookie: Expected version" if version.nil?

      code_page = input.read(4)
      raise TicketError, "Truncated cookie: Expected 4-byte code page" if code_page.nil? || code_page.size < 4

      out = { :version => version, :code_page => code_page }
      self.info_units(input).each { |info_unit|
        out[info_unit.name] = info_unit.value
      }

      if (out[:create_time] || '').size >= 12
        out[:start_time] = utc_time_string_to_time(out[:create_time])
        out[:end_time] = out[:start_time] +
          self.unpack_binary_int(out[:valid_time]) * 3600 +
          self.unpack_binary_int(out[:valid_time_min]) * 60
      else
        raise TicketError, "Creation time not set in ticket"
      end

      out
    end

    def self.info_units(input)
      out = []
      while true
        binary = ''

        id = input.getbyte
        break if id.nil?
        binary += id.chr

        length1 = input.getbyte
        raise TicketError, "Truncated cookie: Expected input size byte 1" if length1.nil?
        binary += length1.chr

        length2 = input.getbyte
        raise TicketError, "Truncated cookie: Expected input size byte 2" if length2.nil?
        binary += length2.chr

        length = (length1 * 256) + length2

        content = input.read(length)
        raise TicketError, "Truncated cookie: Expected InfoUnit of length #{length} but got #{content.size}" if content.size < length
        binary += content

        name = ID2FIELD_NAME[id] || id

        out.push(InfoUnit.new(id, name, content, binary))
      end
      out
    end

    def self.data_to_sign(bytes)
      input = StringIO.new(bytes)
      out = ''

      version = input.getbyte
      raise TicketError, "Truncated cookie: Expected version" if version.nil?
      out += version.chr

      code_page = input.read(4)
      raise TicketError, "Truncated cookie: Expected 4-byte code page" if code_page.nil? || code_page.size < 4
      out += code_page

      self.info_units(input).each { |info_unit|
        if info_unit.id != 255
          out += info_unit.binary
        end
      }
      out
    end

    def self.utc_time_string_to_time(string)
      year = (string[0...4]).to_i
      month = (string[4...6]).to_i
      day = (string[6...8]).to_i
      hour = (string[8...10]).to_i
      min = (string[10...12]).to_i
      sec = 0
      Time.gm(year, month, day, hour, min, sec)
    end

    def self.verify_ticket!(ticket_bytes, cert_bytes)
      data_to_sign = LogonTicket.data_to_sign(ticket_bytes)
      ticket = LogonTicket.parse_ticket(ticket_bytes)
      digest = ticket[:signature] \
        or raise TicketError, "Ticket missing InfoUnit for signature (ID=255)"
      cert = OpenSSL::X509::Certificate.new(cert_bytes)
      pkcs7 = OpenSSL::PKCS7.new(digest)
      a1 = OpenSSL::ASN1.decode(pkcs7)
      store = OpenSSL::X509::Store.new
      store.add_cert(cert)
      pkcs7.verify([cert], store, data_to_sign, OpenSSL::PKCS7::DETACHED) \
        or raise TicketError, "Certificate verification failed: #{pkcs7.error_string}"

      if Time.now.utc < ticket[:start_time]
        raise TicketError, "Ticket not valid until #{ticket[:start_time]}"
      elsif Time.now.utc > ticket[:end_time]
        raise TicketError, "Ticket expired #{ticket[:end_time]}"
      end
    end
  end
end
