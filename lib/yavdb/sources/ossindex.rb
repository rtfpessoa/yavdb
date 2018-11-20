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

require_relative '../dtos/advisory'
require_relative '../utils/http'

module YAVDB
  module Sources
    module OSSIndex
      class Client

        API_URL               = 'https://ossindex.net'
        PACKAGE_MANAGERS      = ['npm', 'maven', 'composer', 'nuget', 'rubygems', 'pypi']
        PACKAGE_MANAGER_ALIAS = Hash['composer' => 'packagist']

        def self.advisories
          PACKAGE_MANAGERS.map do |package_manager|
            packages = fetch_packages(package_manager)
            parse_vulnerabilities(package_manager, packages)
          end.flatten
        end

        class << self

          private

          def fetch_packages(package_manager)
            next_url = start_url(package_manager)
            packages = []

            while next_url
              ossindex      = YAVDB::Utils::HTTP.get_page_contents(next_url, true, 'ossindex/advisories')
              ossindex_json = JSON.parse(ossindex.join)
              page_packages = ossindex_json['packages']

              packages.concat(page_packages)

              next_url = ossindex_json['next']
            end

            packages
          end

          def parse_vulnerabilities(package_manager, packages)
            packages
              .map do |package|
              package['vulnerabilities'].map do |advisory|
                create(package_manager, package, advisory)
              end
            end.flatten
          end

          def create(package_manager, package, advisory)
            published_date = Date.strptime((advisory['published'] / 1000).to_s, '%s')
            updated_date   = Date.strptime((advisory['updated'] / 1000).to_s, '%s')

            cve = if advisory['cve']
                    [advisory['cve']].map(&:strip).reject(&:empty?)
                  else
                    []
                  end

            package_manager = PACKAGE_MANAGER_ALIAS[package_manager] || package_manager

            package_name =
              if package_manager == 'maven'
                "#{package['group']}:#{package['name']}"
              elsif package_manager == 'packagist'
                "#{package['group']}/#{package['name']}"
              else
                package['name']
              end

            versions = advisory['versions']
                         .map { |v| v.split('||') }
                         .flatten
                         .map(&:strip)
                         .reject(&:empty?)
                         .reject { |v| v == '-' }
                         .map { |version| version.gsub("''", '') }
            versions = ['*'] unless versions.any?

            vuln_id = "ossindex:#{package_manager}:#{package_name}:#{advisory['id']}"

            YAVDB::Advisory.new(
              vuln_id,
              advisory['title'],
              advisory['description'],
              package_name,
              versions,
              nil, #:unaffected_versions
              nil, #:patched_versions
              nil, #:severity
              package_manager,
              cve,
              nil, #:cwe
              nil, #:osvdb
              nil, #:cvss_v2_vector
              nil, #:cvss_v2_score
              nil, #:cvss_v3_vector
              nil, #:cvss_v3_score
              published_date,
              published_date,
              updated_date,
              ['OSSIndex'],
              advisory['references'],
              website_url(package['id'])
            )
          end

          def start_url(package_manager)
            "#{API_URL}/v2.0/vulnerability/pm/#{package_manager}/fromtill/0/-1"
          end

          def website_url(id)
            "#{API_URL}/resource/package/#{id}/vulnerabilities"
          end

        end

      end
    end
  end
end
