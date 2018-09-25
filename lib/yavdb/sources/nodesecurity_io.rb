# yavdb - The Free and Open Source vulnerability database
# Copyright (C) 2017-present Rodrigo Fernandes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'oga'
require 'oga/xml/entities'
require 'date'

require_relative '../dtos/advisory'
require_relative '../utils/http'

module YAVDB
  module Sources
    module NodeSecurityIO
      class Client

        API_URL     = 'https://api.nodesecurity.io/advisories'
        WEBSITE_URL = 'https://nodesecurity.io/advisories'

        def self.advisories
          fetch_advisories.map do |advisory_hash|
            create(advisory_hash)
          end
        end

        class << self

          private

          def fetch_advisories
            offset     = 0
            advisories = []

            loop do
              nodesecurity    = YAVDB::Utils::HTTP.get_page_contents("#{API_URL}?offset=#{offset}", false, 'nodesecurity.io/advisories')
              advisories_json = JSON.parse(nodesecurity.join)

              advisories_json['count'].positive? ? advisories = advisories.concat(advisories_json['results']) : break

              offset += advisories_json['count']
            end

            advisories
          end

          def create(advisory_hash)
            publish_date = Date.parse(advisory_hash['publish_date'])
            created_at   = Date.parse(advisory_hash['created_at'])
            updated_at   = Date.parse(advisory_hash['updated_at'])

            vulnerable_versions =
              if advisory_hash['vulnerable_versions'].nil? || advisory_hash['vulnerable_versions'].empty?
                '*'
              else
                advisory_hash['vulnerable_versions']
              end

            YAVDB::Advisory.new(
              "nodesecurity:npm:#{advisory_hash['module_name']}:#{publish_date}",
              advisory_hash['title'],
              advisory_hash['overview'],
              advisory_hash['module_name'],
              [vulnerable_versions],
              nil, #:unaffected_versions
              advisory_hash['patched_versions'],
              severity(advisory_hash['cvss_score']),
              'npm',
              advisory_hash['cves'],
              nil, #:cwe
              nil, #:osvdb
              nil, #:cvss_v2_vector
              nil, #:cvss_v2_score
              advisory_hash['cvss_vector'],
              advisory_hash['cvss_score'],
              publish_date,
              created_at,
              updated_at,
              [advisory_hash['author']],
              clean_references(advisory_hash['references']),
              "#{WEBSITE_URL}/#{advisory_hash['id']}"
            )
          end

          def severity(cvss_score)
            case cvss_score
              when 0.0..3.3 then
                'low'
              when 3.3..6.6 then
                'medium'
              else
                'high'
            end
          end

          def clean_references(references)
            if references
              [references.gsub(%r{.*?(http.+)}, '\1')]
            else
              []
            end
          end

        end

      end
    end
  end
end
