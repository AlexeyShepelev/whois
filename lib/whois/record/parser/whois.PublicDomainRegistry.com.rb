#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      # Parser for the whois.PublicDomainRegistry.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Simone Carletti
      # @author Alexey Shepelev <al.shepelev@gmail.com>
      class WhoisPublicdomainregistryCom < Base

        property_supported :registrant_contacts do
          build_contact('Registrant:', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact:', Record::Contact::TYPE_TECHNICAL)
        end


      private

        def build_contact(element, type)
          match = content_for_scanner.slice(/#{element}.+\n((.+\n){8})/, 1)
          return unless match

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
              :type         => type,
              :id           => nil,
              :name         => lines[1].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
              :organization => lines[0],
              :address      => lines[2],
              :city         => lines[3],
              :zip          => lines[4].to_s.partition(",")[2].to_s.strip,
              :state        => '',
              :country      => lines[5],
              :phone        => lines[6].empty? ? '' : "+#{lines[6].to_s.scan(/\d+/).join('.')}",
              :fax          => lines[7].empty? ? '' : "+#{lines[7].to_s.scan(/\d+/).join('.')}",
              :email        => lines[1].to_s.scan(/[^(\s]\S+@[^\.].*\.[a-z]{2,}[^\s\)\n]/).first
          )
        end

      end

    end
  end
end
