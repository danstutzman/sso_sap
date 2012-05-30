module SsoSap
  def self.extract_user_from_ticket(request, public_key_verify_der_base64)
    ticket_bytes = request.params['MYSAPSSO2'] || request.cookies['MYSAPSSO2']
    if ticket_bytes.nil?
      raise TicketError,
        'Need MYSAPSSO2 cookie; please login to SAP self-serve portal'
    end
    
    if public_key_verify_der_base64.nil? || public_key_verify_der_base64 == ''
      raise TicketError, 'Need public_key_verify_der_base64 option set; ' +
        'You can generate one by running java/create_keystore.sh in this ' +
        'sso_sap gem.'
    end

    decoded_ticket = LogonTicket.decode_ticket(ticket_bytes)

    LogonTicket.verify_ticket! decoded_ticket,
      Base64.decode64(public_key_verify_der_base64)

    parsed_ticket = LogonTicket.parse_ticket(decoded_ticket)

    user = parsed_ticket[:user]
  end
end
