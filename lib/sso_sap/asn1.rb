# these methods are not for production use; just for debugging

module SsoSap
  def self.asn1_string_to_ruby(asn1_string)
    self.asn1_to_ruby(OpenSSL::ASN1.decode(asn1_string))
  end
  def self.asn1_to_ruby(asn1)
    case asn1
      when OpenSSL::ASN1::Sequence
        asn1.collect { |child| self.asn1_to_ruby(child) }
      when OpenSSL::ASN1::ObjectId
        asn1.long_name
      when OpenSSL::ASN1::ASN1Data
        if asn1.value.respond_to?(:collect)
          asn1.value.collect { |child| self.asn1_to_ruby(child) }
        else
          self.asn1_to_ruby(asn1.value)
        end
      when OpenSSL::BN
        asn1.to_i
      when String
        # to avoid Encoding::UndefinedConversionError when using json
        asn1.force_encoding('iso-8859-1')
      else
        asn1
    end
  end
end
